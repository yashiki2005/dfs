#!/usr/bin/env python3
"""RunPod 等の使い捨て環境向け・読み取り専用招待トークン (`dfs-invite-ro-v1`)。

書き手の秘密鍵を含めず、読み取りに必要な情報（`root_pubkey`・`tree_secret`・
`registries`・`path`）だけをコンパクトな Base64url 文字列にまとめる。
"""

from __future__ import annotations

import base64
import json
from typing import Any, Dict, List, Optional, Sequence

from .crypto import canonical_json, normalize_path
from .dnssec import _validate_registry_url

INVITE_RO_SCHEMA = "dfs-invite-ro-v1"
INVITE_RO_PREFIX = "dfs-ro-v1:"
INVITE_RW_SCHEMA = "dfs-invite-rw-v1"
INVITE_RW_PREFIX = "dfs-rw-v1:"


class InviteError(ValueError):
    """読み取り専用招待トークンの形式・検証エラー。"""


def encode_ro_invite(
    *,
    name: str,
    registries: Sequence[str],
    root_pubkey: str,
    tree_secret: str,
    path: str = "",
    ost: str = "",
    ost_alternates: Sequence[str] = (),
    role_epoch: int = 1,
    poll_seconds: int = 30,
    use_candidacy: bool = False,
) -> str:
    """読み取り専用招待トークン（``dfs-ro-v1:<base64url>``）を生成する。"""
    clean_pub = " ".join(str(root_pubkey or "").split())
    if not clean_pub or not clean_pub.startswith("ssh-"):
        raise InviteError("Read-only invite requires a valid root_pubkey (no TOFU)")
    if not tree_secret:
        raise InviteError("Read-only invite requires tree_secret")

    urls: List[str] = []
    seen = set()
    for raw in registries:
        text = str(raw or "").strip()
        if not text:
            continue
        url = _validate_registry_url(text)
        if url not in seen:
            seen.add(url)
            urls.append(url)
    if not urls:
        raise InviteError("At least one registry URL is required")

    norm_path = normalize_path(path) if path else ""
    payload: Dict[str, Any] = {
        "mode": "read-only",
        "name": str(name or "ro").strip() or "ro",
        "ost": str(ost or "").strip(),
        "ost_alternates": [str(u).strip() for u in ost_alternates if str(u).strip()],
        "path": norm_path,
        "poll_seconds": max(1, int(poll_seconds)),
        "registries": urls,
        "role_epoch": max(1, int(role_epoch)),
        "root_pubkey": clean_pub,
        "schema": INVITE_RO_SCHEMA,
        "tree_secret": str(tree_secret),
        "use_candidacy": bool(use_candidacy),
    }
    raw_bytes = canonical_json(payload)
    b64 = base64.urlsafe_b64encode(raw_bytes).decode("ascii").rstrip("=")
    return f"{INVITE_RO_PREFIX}{b64}"


def decode_ro_invite(token: str) -> Dict[str, Any]:
    """``dfs-ro-v1:<base64url>``（または生 Base64url）をデコードして検証する。"""
    raw = str(token or "").strip()
    if raw.startswith(INVITE_RO_PREFIX):
        raw = raw[len(INVITE_RO_PREFIX):].strip()
    if not raw:
        raise InviteError("Empty invite token")
    padded = raw + "=" * (-len(raw) % 4)
    try:
        decoded = base64.urlsafe_b64decode(padded.encode("ascii"))
        data = json.loads(decoded.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as e:
        raise InviteError(f"Invalid invite token: {e}") from e

    if not isinstance(data, dict):
        raise InviteError("Invite payload must be a JSON object")
    if data.get("schema") != INVITE_RO_SCHEMA:
        raise InviteError(f"Unsupported invite schema: {data.get('schema')!r}")
    if data.get("mode") != "read-only":
        raise InviteError(f"Unsupported invite mode: {data.get('mode')!r}")

    clean_pub = " ".join(str(data.get("root_pubkey", "")).split())
    if not clean_pub or not clean_pub.startswith("ssh-"):
        raise InviteError("Invite token has invalid root_pubkey")
    tree_secret = str(data.get("tree_secret", ""))
    if not tree_secret:
        raise InviteError("Invite token has no tree_secret")

    raw_regs = data.get("registries")
    if not isinstance(raw_regs, list) or not raw_regs:
        raise InviteError("Invite token has no registries")
    urls = [_validate_registry_url(str(u)) for u in raw_regs]

    raw_path = str(data.get("path", "") or "")
    norm_path = normalize_path(raw_path) if raw_path else ""

    return {
        "schema": INVITE_RO_SCHEMA,
        "mode": "read-only",
        "name": str(data.get("name") or "ro").strip() or "ro",
        "path": norm_path,
        "registries": urls,
        "ost": str(data.get("ost", "") or "").strip(),
        "ost_alternates": [
            str(u).strip()
            for u in (data.get("ost_alternates") or [])
            if str(u).strip()
        ],
        "root_pubkey": clean_pub,
        "tree_secret": tree_secret,
        "role_epoch": max(1, int(data.get("role_epoch", 1))),
        "poll_seconds": max(1, int(data.get("poll_seconds", 30))),
        "use_candidacy": bool(data.get("use_candidacy", False)),
    }


def encode_rw_invite(
    *,
    name: str,
    registries: Sequence[str],
    root_pubkey: str,
    tree_secret: str,
    write_name: str,
    write_path: str,
    write_priv_key: str,
    write_pub_key: str,
    write_epoch: int = 1,
    path: str = "",
    ost: str = "",
    ost_alternates: Sequence[str] = (),
    role_epoch: int = 1,
    poll_seconds: int = 30,
    use_candidacy: bool = False,
) -> str:
    """読み取り専用入力 + 出力専用一時書き手鍵を含む招待トークン (``dfs-rw-v1:<base64url>``) を生成する。"""
    ro_token = encode_ro_invite(
        name=name,
        registries=registries,
        root_pubkey=root_pubkey,
        tree_secret=tree_secret,
        path=path,
        ost=ost,
        ost_alternates=ost_alternates,
        role_epoch=role_epoch,
        poll_seconds=poll_seconds,
        use_candidacy=use_candidacy,
    )
    base_payload = decode_ro_invite(ro_token)
    norm_write_path = normalize_path(write_path)
    if not write_priv_key or not write_pub_key:
        raise InviteError("Write invite requires ephemeral write keypair")
    payload: Dict[str, Any] = {
        **base_payload,
        "mode": "read-write-ephemeral",
        "schema": INVITE_RW_SCHEMA,
        "write": {
            "epoch": max(1, int(write_epoch)),
            "name": str(write_name or "out").strip() or "out",
            "path": norm_write_path,
            "priv_key": str(write_priv_key),
            "pub_key": str(write_pub_key).strip(),
        },
    }
    raw_bytes = canonical_json(payload)
    b64 = base64.urlsafe_b64encode(raw_bytes).decode("ascii").rstrip("=")
    return f"{INVITE_RW_PREFIX}{b64}"


def decode_invite(token: str) -> Dict[str, Any]:
    """``dfs-ro-v1:`` または ``dfs-rw-v1:`` の招待トークンをデコード・検証する。"""
    raw = str(token or "").strip()
    if raw.startswith(INVITE_RO_PREFIX):
        return decode_ro_invite(raw)
    if not raw.startswith(INVITE_RW_PREFIX):
        return decode_ro_invite(raw)

    body = raw[len(INVITE_RW_PREFIX):].strip()
    if not body:
        raise InviteError("Empty invite token")
    padded = body + "=" * (-len(body) % 4)
    try:
        decoded = base64.urlsafe_b64decode(padded.encode("ascii"))
        data = json.loads(decoded.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as e:
        raise InviteError(f"Invalid invite token: {e}") from e
    if not isinstance(data, dict) or data.get("schema") != INVITE_RW_SCHEMA:
        raise InviteError("Unsupported rw invite schema")
    if data.get("mode") != "read-write-ephemeral":
        raise InviteError(f"Unsupported rw invite mode: {data.get('mode')!r}")

    # 共通フィールドを ro デコーダと同じ規則で検証する
    ro_check = dict(data)
    ro_check["schema"] = INVITE_RO_SCHEMA
    ro_check["mode"] = "read-only"
    ro_b64 = base64.urlsafe_b64encode(canonical_json(ro_check)).decode("ascii").rstrip("=")
    parsed = decode_ro_invite(f"{INVITE_RO_PREFIX}{ro_b64}")

    write_info = data.get("write")
    if not isinstance(write_info, dict):
        raise InviteError("RW invite is missing 'write' section")
    write_priv = str(write_info.get("priv_key", ""))
    write_pub = str(write_info.get("pub_key", "")).strip()
    if not write_priv or not write_pub.startswith("ssh-"):
        raise InviteError("RW invite has invalid write keypair")
    write_path = normalize_path(str(write_info.get("path", "")))
    parsed["mode"] = "read-write-ephemeral"
    parsed["schema"] = INVITE_RW_SCHEMA
    parsed["write"] = {
        "name": str(write_info.get("name") or "out").strip() or "out",
        "path": write_path,
        "priv_key": write_priv,
        "pub_key": write_pub,
        "epoch": max(1, int(write_info.get("epoch", 1))),
    }
    return parsed
