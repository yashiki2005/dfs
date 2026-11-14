#!/usr/bin/env python3
"""小規模運用向けの署名付き立候補モデル (Signed Candidacy / Roster Discovery)。

未公開・閉域環境では DNSSEC の運用コスト（公開ドメイン管理・ゾーン署名・外部リゾルバ依存）が
重いため、小規模運用では「手元の root 公開鍵 + 立候補ノードが提示する署名付き名簿」で
primary / secondary と role_epoch を発見・切り替える。
中規模を超える公開運用へ移行する場合は DNSSEC (dfs/dnssec.py) へ移行する。
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from .crypto import (
    NS_CANDIDACY,
    SignatureVerificationError,
    canonical_json,
    normalize_path,
    ssh_sign,
    ssh_verify,
)
from .dnssec import Discovery, DiscoveryError, RegistryEndpoint, _validate_registry_url

CANDIDACY_SCHEMA = "dfs-candidacy-v1"


class CandidacyError(DiscoveryError):
    """署名付き立候補エンベロープの作成・検証・取得エラー。"""


def _normalize_registries(raw_registries: Sequence[Dict[str, Any]]) -> List[Dict[str, str]]:
    if not isinstance(raw_registries, (list, tuple)) or not raw_registries:
        raise CandidacyError("Candidacy record must have at least one registry")
    normalized: List[Dict[str, str]] = []
    seen_urls = set()
    primary_count = 0
    for item in raw_registries:
        if not isinstance(item, dict):
            raise CandidacyError("Each registry entry must be an object")
        role = str(item.get("role", "")).strip().lower()
        if role not in ("primary", "secondary"):
            raise CandidacyError(f"Invalid registry role: {role!r}")
        url = _validate_registry_url(str(item.get("url", "")))
        if url in seen_urls:
            raise CandidacyError(f"Duplicate registry URL: {url!r}")
        seen_urls.add(url)
        if role == "primary":
            primary_count += 1
        normalized.append({"role": role, "url": url})
    if primary_count != 1:
        raise CandidacyError(
            f"Candidacy record must have exactly one primary registry, got {primary_count}"
        )
    return normalized


def create_candidacy_envelope(
    root_priv_key: Path | str,
    root_anchor: str,
    root_pubkey: str,
    registries: Sequence[Dict[str, Any]],
    *,
    epoch: int = 1,
    issued_at: Optional[int] = None,
    expires_at: Optional[int] = None,
    ttl_days: int = 30,
) -> Dict[str, Any]:
    """root 秘密鍵で署名した立候補エンベロープ (`dfs-candidacy-v1`) を生成する。"""
    norm_anchor = normalize_path(root_anchor)
    clean_pub = " ".join(str(root_pubkey or "").split())
    if not clean_pub or not clean_pub.startswith("ssh-"):
        raise CandidacyError("Invalid root_pubkey for candidacy")
    if int(epoch) < 1:
        raise CandidacyError(f"Candidacy epoch must be >= 1, got {epoch}")

    now = int(time.time()) if issued_at is None else int(issued_at)
    exp = now + int(ttl_days) * 86400 if expires_at is None else int(expires_at)
    if now >= exp:
        raise CandidacyError(f"Invalid candidacy validity window: issued_at={now} >= expires_at={exp}")

    norm_regs = _normalize_registries(registries)
    payload: Dict[str, Any] = {
        "epoch": int(epoch),
        "expires_at": exp,
        "issued_at": now,
        "registries": norm_regs,
        "root_anchor": norm_anchor,
        "root_pubkey": clean_pub,
        "schema": CANDIDACY_SCHEMA,
    }
    raw_bytes = canonical_json(payload)
    try:
        signature = ssh_sign(root_priv_key, NS_CANDIDACY, raw_bytes)
    except SignatureVerificationError as e:
        raise CandidacyError(str(e)) from e

    return {
        "payload": payload,
        "signature": signature,
    }


def verify_candidacy_envelope(
    envelope: Dict[str, Any],
    expected_root_pubkey: str,
    *,
    expected_root_anchor: Optional[str] = None,
    now: Optional[int] = None,
    min_epoch: Optional[int] = None,
) -> Discovery:
    """立候補エンベロープを検証し、`Discovery` へ変換する。"""
    if not isinstance(envelope, dict):
        raise CandidacyError("Malformed candidacy envelope")
    payload = envelope.get("payload")
    signature = envelope.get("signature")
    if not isinstance(payload, dict) or not isinstance(signature, str):
        raise CandidacyError("Malformed candidacy envelope")
    if payload.get("schema") != CANDIDACY_SCHEMA:
        raise CandidacyError(f"Unsupported candidacy schema: {payload.get('schema')!r}")

    try:
        norm_anchor = normalize_path(str(payload.get("root_anchor", "")))
    except ValueError as e:
        raise CandidacyError(f"Invalid root_anchor in candidacy: {e}") from e
    if norm_anchor != payload.get("root_anchor"):
        raise CandidacyError("Unnormalized root_anchor in candidacy payload")
    if expected_root_anchor is not None:
        want_anchor = normalize_path(expected_root_anchor)
        if norm_anchor != want_anchor:
            raise CandidacyError(
                f"Candidacy root_anchor mismatch: expected {want_anchor!r}, got {norm_anchor!r}"
            )

    expected_pub = " ".join(str(expected_root_pubkey or "").split())
    if not expected_pub:
        raise CandidacyError("expected_root_pubkey is required")
    actual_pub = " ".join(str(payload.get("root_pubkey", "")).split())
    if actual_pub != expected_pub:
        raise CandidacyError("Candidacy root_pubkey does not match trusted root_pubkey")

    try:
        epoch = int(payload["epoch"])
        issued_at = int(payload["issued_at"])
        expires_at = int(payload["expires_at"])
    except (KeyError, TypeError, ValueError) as e:
        raise CandidacyError(f"Invalid numeric fields in candidacy: {e}") from e
    if epoch < 1:
        raise CandidacyError(f"Candidacy epoch must be >= 1: {epoch}")
    if min_epoch is not None and epoch < int(min_epoch):
        raise CandidacyError(
            f"Candidacy epoch rollback: got {epoch}, minimum allowed is {int(min_epoch)}"
        )

    current = int(time.time()) if now is None else int(now)
    if not (issued_at <= current < expires_at):
        raise CandidacyError(
            f"Candidacy expired or not yet valid: now={current}, window=[{issued_at}, {expires_at})"
        )

    norm_regs = _normalize_registries(payload.get("registries") or [])
    raw_bytes = canonical_json(payload)
    if not ssh_verify(expected_pub, norm_anchor, NS_CANDIDACY, raw_bytes, signature):
        raise CandidacyError("Invalid candidacy signature")

    endpoints = tuple(RegistryEndpoint(url=r["url"], role=r["role"]) for r in norm_regs)
    return Discovery(
        domain=norm_anchor.lstrip("/"),
        root_anchor=norm_anchor,
        root_pubkey=expected_pub,
        registries=endpoints,
        epoch=epoch,
        ttl=max(1, expires_at - current),
        raw=payload,
    )


def fetch_candidacy(
    candidate_urls: Sequence[str],
    expected_root_pubkey: str,
    *,
    expected_root_anchor: Optional[str] = None,
    min_epoch: Optional[int] = None,
    now: Optional[int] = None,
    timeout: float = 5.0,
) -> Discovery:
    """立候補しているレジストリ群から `/v1/candidacy` を取得し、検証済みかつ最大 epoch を採用する。"""
    urls: List[str] = []
    seen = set()
    for raw in candidate_urls:
        value = str(raw or "").strip().rstrip("/")
        if value and value not in seen:
            seen.add(value)
            urls.append(value)
    if not urls:
        raise CandidacyError("At least one candidate registry URL is required")

    best: Optional[Discovery] = None
    last_error: Optional[Exception] = None
    for url in urls:
        req = urllib.request.Request(
            f"{url}/v1/candidacy",
            data=b"{}",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, urllib.error.HTTPError, OSError, TimeoutError, ValueError) as e:
            last_error = e
            continue
        envelope = data.get("candidacy") if isinstance(data, dict) else None
        if not envelope:
            continue
        try:
            candidate = verify_candidacy_envelope(
                envelope,
                expected_root_pubkey,
                expected_root_anchor=expected_root_anchor,
                now=now,
                min_epoch=min_epoch,
            )
        except CandidacyError as e:
            last_error = e
            continue
        if best is None or candidate.epoch > best.epoch:
            best = candidate

    if best is None:
        detail = f": {last_error}" if last_error is not None else ""
        raise CandidacyError(f"No valid candidacy found from {urls}{detail}")
    return best
