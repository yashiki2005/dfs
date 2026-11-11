#!/usr/bin/env python3
"""
dfs5/l1_delegation.py
specs/delegation.md の 5 つの不変条件 (Invariants 1〜5) と多段委譲チェーン検証を実装する L1 モジュール。
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

from .crypto import (
    NS_L1_DELEGATION,
    SignatureVerificationError,
    canonical_json,
    normalize_path,
    ssh_sign,
    ssh_verify,
)


class DelegationError(Exception):
    """L1 権威の委譲・検証・失効エラー"""


def create_delegation_envelope(
    parent_priv_key: Path | str,
    parent: str,
    path: str,
    writer_pubkey: str,
    epoch: int,
    base_version: int,
    issued_at: int,
    expires_at: int,
) -> Dict[str, Any]:
    """正規化・検証済みの L1 委譲エンベロープを生成し、親の秘密鍵で署名する。"""
    norm_parent = normalize_path(parent)
    norm_path = normalize_path(path)
    if not norm_path.startswith(norm_parent + "/"):
        raise DelegationError(f"Scope violation: {norm_path!r} is not under {norm_parent!r}")
    if epoch < 1:
        raise DelegationError(f"epoch must be >= 1, got {epoch}")
    if base_version < 0:
        raise DelegationError(f"base_version must be >= 0, got {base_version}")
    if issued_at >= expires_at:
        raise DelegationError(f"Invalid validity window: issued_at={issued_at} >= expires_at={expires_at}")

    payload = {
        "base_version": int(base_version),
        "epoch": int(epoch),
        "expires_at": int(expires_at),
        "issued_at": int(issued_at),
        "parent": norm_parent,
        "path": norm_path,
        "writer": writer_pubkey.strip(),
    }
    raw_bytes = canonical_json(payload)
    try:
        sig = ssh_sign(parent_priv_key, NS_L1_DELEGATION, raw_bytes)
    except SignatureVerificationError as e:
        raise DelegationError(str(e)) from e

    return {
        "payload": payload,
        "signature": sig,
    }


def verify_single_delegation(
    envelope: Dict[str, Any],
    parent_pubkey: str,
    now: int,
    parent_expires_at: Optional[int] = None,
    current_active_epoch: Optional[int] = None,
    current_head_version: Optional[int] = None,
) -> Dict[str, Any]:
    """
    単一の委譲レコードに対して specs/delegation.md の不変条件 1〜4 および §3.2 を検証する。
    検証に成功した場合は payload 辞書を返す。
    """
    if "payload" not in envelope or "signature" not in envelope:
        raise DelegationError("Malformed delegation envelope")

    p = envelope["payload"]
    required_keys = {"base_version", "epoch", "expires_at", "issued_at", "parent", "path", "writer"}
    if set(p.keys()) != required_keys:
        raise DelegationError(f"Invalid delegation payload keys: {set(p.keys())}")

    try:
        norm_parent = normalize_path(p["parent"])
        norm_path = normalize_path(p["path"])
    except ValueError as e:
        raise DelegationError(f"Invalid path in delegation (Invariant 2): {e}") from e

    if norm_parent != p["parent"] or norm_path != p["path"]:
        raise DelegationError("Unnormalized path in delegation payload (Invariant 2)")

    # 不変条件 2: 名前空間の包含（減衰の原則）
    if not norm_path.startswith(norm_parent + "/"):
        raise DelegationError(f"Scope violation (Invariant 2): {norm_path!r} is not under {norm_parent!r}")

    # 不変条件 3: 有効期限の包含と現在時刻の整合性
    if not (p["issued_at"] <= now < p["expires_at"]):
        raise DelegationError(
            f"Delegation expired or not yet valid (Invariant 3): now={now}, window=[{p['issued_at']}, {p['expires_at']})"
        )
    if parent_expires_at is not None and p["expires_at"] > parent_expires_at:
        raise DelegationError(
            f"Child expires_at ({p['expires_at']}) exceeds parent expires_at ({parent_expires_at}) (Invariant 3)"
        )

    # 不変条件 4: エポックの単調増加（即時失効規則）
    if p["epoch"] < 1:
        raise DelegationError("Epoch must be >= 1 (Invariant 4)")
    if current_active_epoch is not None and p["epoch"] <= current_active_epoch:
        raise DelegationError(
            f"Epoch must strictly increase (Invariant 4): got {p['epoch']}, active is {current_active_epoch}"
        )

    # §3.2 引き継ぎ版番号 (base_version) の整合性
    if p["base_version"] < 0:
        raise DelegationError("base_version must be >= 0")
    if current_head_version is not None and p["base_version"] != current_head_version:
        raise DelegationError(
            f"base_version mismatch (§3.2): delegation specifies {p['base_version']}, current head is {current_head_version}"
        )

    # 不変条件 1: 正規化 JSON と親公開鍵による署名検証
    raw_bytes = canonical_json(p)
    if not ssh_verify(parent_pubkey, norm_parent, NS_L1_DELEGATION, raw_bytes, envelope["signature"]):
        raise DelegationError(f"Invalid L1 delegation signature for {norm_path!r} by parent {norm_parent!r} (Invariant 1)")

    return p


def verify_delegation_chain(
    root_anchor_path: str,
    root_anchor_pubkey: str,
    chain: List[Dict[str, Any]],
    now: int,
    requested_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    ルートアンカーから対象パスに至る委譲チェーン [D_1, D_2, ..., D_n] を検証し、
    末端 D_n の検証済み payload を返す（不変条件 1〜5 すべてを検証）。

    ``requested_path`` を渡した場合は、末端の委譲がそのパスに一致することも検証する。
    名簿が別サブツリーのチェーンを返しても、クライアントがそれを要求パスとして
    受け入れないための束縛になる。
    """
    if not chain:
        raise DelegationError("Delegation chain cannot be empty (Invariant 5)")

    norm_root = normalize_path(root_anchor_path)
    first_parent = chain[0].get("payload", {}).get("parent")
    if first_parent != norm_root:
        raise DelegationError(
            f"Chain does not start at root anchor (Invariant 5): expected {norm_root!r}, got {first_parent!r}"
        )

    curr_pubkey = root_anchor_pubkey
    curr_path = norm_root
    curr_expires: Optional[int] = None
    last_payload: Optional[Dict[str, Any]] = None

    for idx, env in enumerate(chain):
        parent_in_env = env.get("payload", {}).get("parent")
        if parent_in_env != curr_path:
            raise DelegationError(
                f"Broken delegation chain at step {idx} (Invariant 5): expected parent {curr_path!r}, got {parent_in_env!r}"
            )
        verified_p = verify_single_delegation(
            envelope=env,
            parent_pubkey=curr_pubkey,
            now=now,
            parent_expires_at=curr_expires,
        )
        curr_pubkey = verified_p["writer"]
        curr_path = verified_p["path"]
        curr_expires = verified_p["expires_at"]
        last_payload = verified_p

    assert last_payload is not None
    if requested_path is not None:
        norm_requested = normalize_path(requested_path)
        if last_payload["path"] != norm_requested:
            raise DelegationError(
                f"Delegation chain leaf path mismatch: expected {norm_requested!r}, "
                f"got {last_payload['path']!r}"
            )
    return last_payload
