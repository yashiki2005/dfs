#!/usr/bin/env python3
"""DNSSEC で公開する dfs5 の root / registry 情報を読む。

レコード形式は ``_dfs5.<domain>`` の TXT に置く JSON:

{
  "schema": "dfs5-discovery-v1",
  "domain": "example.com",
  "root_anchor": "/example.com",
  "root_pubkey": "ssh-ed25519 AAAA...",
  "registries": [
    {"url": "https://l2-a.example.com:9440", "role": "primary"},
    {"url": "https://l2-b.example.com:9440", "role": "secondary"}
  ],
  "epoch": 1,
  "ttl": 300
}

DNSSEC の AD（Authenticated Data）ビットを確認できた場合だけ採用する。
AD を付けられないローカルリゾルバ向けに ``require_ad=False`` も用意するが、
本番では使わない。
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence
from urllib.parse import urlparse

from .crypto import normalize_path

SCHEMA = "dfs5-discovery-v1"
DEFAULT_RECORD_PREFIX = "_dfs5"


class DiscoveryError(ValueError):
    """DNSSEC discovery のレコード不正・検証失敗。"""


@dataclass(frozen=True)
class RegistryEndpoint:
    url: str
    role: str  # "primary" or "secondary"


@dataclass(frozen=True)
class Discovery:
    domain: str
    root_anchor: str
    root_pubkey: str
    registries: Sequence[RegistryEndpoint]
    epoch: int
    ttl: int
    raw: Dict[str, Any]

    @property
    def primary(self) -> RegistryEndpoint:
        return next(r for r in self.registries if r.role == "primary")

    @property
    def alternates(self) -> List[RegistryEndpoint]:
        return [r for r in self.registries if r.role == "secondary"]

    @property
    def primary_url(self) -> str:
        return self.primary.url

    @property
    def alternate_urls(self) -> List[str]:
        return [r.url for r in self.alternates]


def _normalize_domain(value: str) -> str:
    domain = str(value or "").strip().rstrip(".").lower()
    if not domain or any(ch.isspace() for ch in domain):
        raise DiscoveryError(f"Invalid domain: {value!r}")
    if domain.startswith(".") or ".." in domain:
        raise DiscoveryError(f"Invalid domain: {value!r}")
    return domain


def _validate_registry_url(value: str) -> str:
    text = str(value or "").strip().rstrip("/")
    parsed = urlparse(text)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise DiscoveryError(f"Registry URL must be http(s)://host:port: {value!r}")
    return text


def parse_discovery_text(
    text: str,
    *,
    expected_domain: Optional[str] = None,
) -> Discovery:
    """TXT レコードの JSON を検証して ``Discovery`` にする。"""
    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        raise DiscoveryError(f"Invalid discovery JSON: {e}") from e
    if not isinstance(data, dict):
        raise DiscoveryError("Discovery record must be a JSON object")
    if data.get("schema") != SCHEMA:
        raise DiscoveryError(f"Unsupported discovery schema: {data.get('schema')!r}")

    domain = _normalize_domain(str(data.get("domain", "")))
    if expected_domain is not None:
        expected = _normalize_domain(expected_domain)
        if domain != expected:
            raise DiscoveryError(
                f"Discovery domain mismatch: expected {expected!r}, got {domain!r}"
            )

    raw_anchor = str(data.get("root_anchor", "")).strip()
    try:
        root_anchor = normalize_path(raw_anchor)
    except ValueError as e:
        raise DiscoveryError(f"Invalid root_anchor: {e}") from e

    root_pubkey = str(data.get("root_pubkey", "")).strip()
    if not root_pubkey or "\n" in root_pubkey or not root_pubkey.startswith("ssh-"):
        raise DiscoveryError("Discovery record has an invalid root_pubkey")

    raw_registries = data.get("registries")
    if not isinstance(raw_registries, list) or not raw_registries:
        raise DiscoveryError("Discovery record has no registries")
    registries: List[RegistryEndpoint] = []
    seen_urls = set()
    primary_count = 0
    for item in raw_registries:
        if not isinstance(item, dict):
            raise DiscoveryError("Each registry entry must be an object")
        role = str(item.get("role", "")).strip().lower()
        if role not in ("primary", "secondary"):
            raise DiscoveryError(f"Invalid registry role: {role!r}")
        url = _validate_registry_url(str(item.get("url", "")))
        if url in seen_urls:
            raise DiscoveryError(f"Duplicate registry URL: {url!r}")
        seen_urls.add(url)
        if role == "primary":
            primary_count += 1
        registries.append(RegistryEndpoint(url=url, role=role))
    if primary_count != 1:
        raise DiscoveryError(
            f"Discovery record must have exactly one primary registry, got {primary_count}"
        )

    try:
        epoch = int(data.get("epoch", 1))
    except (TypeError, ValueError) as e:
        raise DiscoveryError(f"Invalid discovery epoch: {data.get('epoch')!r}") from e
    if epoch < 1:
        raise DiscoveryError(f"Discovery epoch must be >= 1: {epoch}")
    try:
        ttl = int(data.get("ttl", 300))
    except (TypeError, ValueError) as e:
        raise DiscoveryError(f"Invalid discovery ttl: {data.get('ttl')!r}") from e
    if ttl <= 0:
        raise DiscoveryError(f"Discovery ttl must be > 0: {ttl}")

    return Discovery(
        domain=domain,
        root_anchor=root_anchor,
        root_pubkey=root_pubkey,
        registries=tuple(registries),
        epoch=epoch,
        ttl=ttl,
        raw=data,
    )


def discover_domain(
    domain: str,
    *,
    record_name: Optional[str] = None,
    require_ad: bool = True,
    timeout: float = 5.0,
) -> Discovery:
    """DNSSEC 対応リゾルバで ``_dfs5.<domain>`` TXT を読む。

    ``require_ad=True`` のとき、レスポンスに AD ビットがなければ拒否する。
    これは「検証済みリゾルバを信頼する」方式であり、クライアント自身が
    DNSKEY/DS チェーンを再検証する方式ではない。詳細は specs/dnssec.md を参照。
    """
    try:
        import dns.flags
        import dns.resolver
    except ImportError as e:  # pragma: no cover - 環境依存
        raise DiscoveryError(
            "DNSSEC discovery requires dnspython (pip install dnspython)"
        ) from e

    normalized = _normalize_domain(domain)
    qname = record_name or f"{DEFAULT_RECORD_PREFIX}.{normalized}"
    resolver = dns.resolver.Resolver(configure=True)
    resolver.lifetime = timeout
    # AD ビットは DNSSEC を要求する問い合わせで検証済みリゾルバが返す。
    # EDNS0 の DO ビットを付けないと、署名自体は正しくても AD が付かない。
    if hasattr(resolver, "use_edns"):
        resolver.use_edns(edns=0, ednsflags=dns.flags.DO, payload=1232)
    try:
        answer = resolver.resolve(qname, "TXT")
    except Exception as e:  # noqa: BLE001 - DNS の例外型は環境で揺れる
        raise DiscoveryError(f"Cannot resolve {qname}: {e}") from e

    if require_ad:
        flags = getattr(getattr(answer, "response", None), "flags", None)
        if flags is None or not (flags & dns.flags.AD):
            raise DiscoveryError(
                f"DNS response for {qname} is not DNSSEC-authenticated (AD bit missing)"
            )

    texts: List[str] = []
    for rdata in answer:
        strings = getattr(rdata, "strings", None)
        if strings is None:
            raise DiscoveryError(f"Unexpected TXT rdata for {qname}: {rdata!r}")
        try:
            texts.append(b"".join(strings).decode("utf-8"))
        except UnicodeDecodeError as e:
            raise DiscoveryError(f"TXT record is not UTF-8: {e}") from e
    if len(texts) != 1:
        raise DiscoveryError(
            f"Expected exactly one {qname} TXT record, got {len(texts)}"
        )
    return parse_discovery_text(texts[0], expected_domain=normalized)
