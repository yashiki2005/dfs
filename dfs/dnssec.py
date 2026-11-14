#!/usr/bin/env python3
"""DNSSEC で公開する dfs の root / registry 情報を読む。

レコード形式は ``_dfs.<domain>`` の TXT に置く JSON:

{
  "schema": "dfs-discovery-v1",
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
import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence
from urllib.parse import urlparse

from .crypto import normalize_path

SCHEMA = "dfs-discovery-v1"
DEFAULT_RECORD_PREFIX = "_dfs"

# IANA の root trust anchor（KSK-2017 / KSK-2024）。
# https://data.iana.org/root-anchors/root-anchors.xml
ROOT_TRUST_ANCHOR_DS = (
    "20326 8 2 "
    "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D",
    "38696 8 2 "
    "683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16",
)

_ZONE_KEY_CACHE: Dict[str, Any] = {}
_ZONE_KEY_CACHE_LOCK = threading.RLock()


def clear_zone_cache() -> None:
    """検証済みゾーン鍵のプロセス内キャッシュを消す（試験・鍵ロールオーバー用）。"""
    with _ZONE_KEY_CACHE_LOCK:
        _ZONE_KEY_CACHE.clear()


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


def _query_rrset(resolver: Any, name: Any, rdtype: str):
    """DNS 応答から対象 RRset と RRSIG RRset を取り出す。"""
    import dns.rdatatype
    import dns.resolver

    try:
        answer = resolver.resolve(name, rdtype)
    except Exception as e:  # noqa: BLE001 - dnspython の例外型は環境で揺れる
        raise DiscoveryError(f"Cannot resolve {name} {rdtype}: {e}") from e

    want = dns.rdatatype.from_text(rdtype)
    rrset = None
    sigset = None
    for item in answer.response.answer:
        if item.name != answer.canonical_name:
            continue
        if item.rdtype == want:
            rrset = item
        elif item.rdtype == dns.rdatatype.RRSIG:
            if any(r.type_covered == want for r in item):
                sigset = item
    if rrset is None or sigset is None:
        raise DiscoveryError(
            f"DNSSEC proof missing for {answer.canonical_name} {rdtype}"
        )
    return rrset, sigset


def _matching_dnskeys(zone: Any, keys: Any, ds_rrset: Any):
    """DS に一致する DNSKEY だけを返す。"""
    import dns.dnssec
    import dns.rrset

    matching = []
    for key in keys:
        for ds in ds_rrset:
            if dns.dnssec.key_id(key) != ds.key_tag or key.algorithm != ds.algorithm:
                continue
            try:
                made = dns.dnssec.make_ds(zone, key, ds.digest_type, validating=True)
            except Exception:  # noqa: BLE001 - 未対応アルゴリズム等
                continue
            if made.digest == ds.digest:
                matching.append(key)
                break
    if not matching:
        raise DiscoveryError(f"No DNSKEY matches the DS set for {zone}")
    return dns.rrset.from_rdata(zone, keys.ttl, *matching)


def _validated_zone_keys(
    resolver: Any, zone: Any, cache: Dict[Any, Any]
):
    """root から ``zone`` までの DNSKEY/DS チェーンを検証し、DNSKEY 集合を返す。"""
    import dns.dnssec
    import dns.name
    import dns.rrset

    zone = dns.name.from_text(str(zone))
    if zone in cache:
        return cache[zone]
    zone_key = zone.to_text()
    now = int(time.time())
    with _ZONE_KEY_CACHE_LOCK:
        cached = _ZONE_KEY_CACHE.get(zone_key)
        if cached is not None and cached[0] > now:
            cache[zone] = cached[1]
            return cached[1]
        if cached is not None:
            _ZONE_KEY_CACHE.pop(zone_key, None)

    dnskey_rrset, dnskey_rrsig = _query_rrset(resolver, zone, "DNSKEY")
    if zone == dns.name.root:
        anchor_text = list(ROOT_TRUST_ANCHOR_DS)
        ds_rrset = dns.rrset.from_text(".", 0, "IN", "DS", *anchor_text)
    else:
        ds_rrset, ds_rrsig = _query_rrset(resolver, zone, "DS")
        signers = {sig.signer for sig in ds_rrsig}
        if len(signers) != 1:
            raise DiscoveryError(f"DS for {zone} has ambiguous signers")
        parent = next(iter(signers))
        parent_keys = _validated_zone_keys(resolver, parent, cache)
        try:
            dns.dnssec.validate(ds_rrset, ds_rrsig, {parent: parent_keys})
        except Exception as e:  # noqa: BLE001
            raise DiscoveryError(f"DS validation failed for {zone}: {e}") from e

    trusted_keys = _matching_dnskeys(zone, dnskey_rrset, ds_rrset)
    try:
        dns.dnssec.validate(dnskey_rrset, dnskey_rrsig, {zone: trusted_keys})
    except Exception as e:  # noqa: BLE001
        raise DiscoveryError(f"DNSKEY validation failed for {zone}: {e}") from e

    expires_at = now + int(dnskey_rrset.ttl or 0)
    if ds_rrset is not None:
        expires_at = min(expires_at, now + int(ds_rrset.ttl or 0))
    for sigset in (dnskey_rrsig, ds_rrsig if zone != dns.name.root else None):
        if sigset is None:
            continue
        for sig in sigset:
            expires_at = min(expires_at, int(sig.expiration))
    with _ZONE_KEY_CACHE_LOCK:
        _ZONE_KEY_CACHE[zone_key] = (max(now + 1, expires_at), dnskey_rrset)
    cache[zone] = dnskey_rrset
    return dnskey_rrset


def _validate_answer(resolver: Any, answer: Any, rrset: Any) -> None:
    """TXT 応答の RRSIG を、root から検証したゾーン鍵で確認する。"""
    import dns.dnssec
    import dns.rdatatype

    sigset = None
    for item in answer.response.answer:
        if item.name != answer.canonical_name:
            continue
        if item.rdtype == dns.rdatatype.RRSIG and any(
            r.type_covered == dns.rdatatype.TXT for r in item
        ):
            sigset = item
            break
    if sigset is None:
        raise DiscoveryError(f"DNSSEC proof missing for {answer.canonical_name} TXT")
    signers = {sig.signer for sig in sigset}
    if len(signers) != 1:
        raise DiscoveryError(f"TXT for {answer.canonical_name} has ambiguous signers")
    zone = next(iter(signers))
    keys = _validated_zone_keys(resolver, zone, {})
    try:
        dns.dnssec.validate(rrset, sigset, {zone: keys})
    except Exception as e:  # noqa: BLE001
        raise DiscoveryError(f"TXT DNSSEC validation failed: {e}") from e


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


def has_txt_record(record_name: str, timeout: float = 1.5) -> bool:
    """``record_name`` に TXT レコードが存在するか確認する。"""
    try:
        import dns.resolver
    except ImportError:
        return False
    resolver = dns.resolver.Resolver(configure=True)
    resolver.lifetime = timeout
    try:
        answer = resolver.resolve(record_name, "TXT")
        return len(answer) > 0
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return False
    except Exception:  # noqa: BLE001
        return False


def discover_domain(
    domain: str,
    *,
    record_name: Optional[str] = None,
    require_ad: bool = True,
    validate: bool = True,
    timeout: float = 5.0,
) -> Discovery:
    """DNSSEC 対応リゾルバで ``_dfs.<domain>`` TXT を読む。

    既定ではクライアント自身が root trust anchor から DNSKEY/DS チェーンを
    検証する。``validate=False`` のときだけ、従来どおり ``require_ad=True`` で
    AD ビットを要求する。詳細は specs/dnssec.md を参照。
    """
    try:
        import dns.flags
        import dns.rdatatype
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
        if validate:
            # 完全検証では AD ビットに依存しない。validate=False のときだけ
            # 検証済みリゾルバの AD を信頼するフォールバックを使う。
            pass
        else:
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
    if validate:
        txt_rrset = None
        for item in answer.response.answer:
            if (
                item.name == answer.canonical_name
                and item.rdtype == dns.rdatatype.TXT
            ):
                txt_rrset = item
                break
        if txt_rrset is None:
            raise DiscoveryError(f"DNSSEC proof missing for {qname} TXT")
        _validate_answer(resolver, answer, txt_rrset)
    return parse_discovery_text(texts[0], expected_domain=normalized)
