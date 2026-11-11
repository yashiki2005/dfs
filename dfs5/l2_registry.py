#!/usr/bin/env python3
"""
dfs5/l2_registry.py
specs/l2_comparison.md に基づく署名付きロケータ (`dfs5-l2-locator-v1`) と
名簿 (Directory) + L4 追記ログ CAS 調停サービス、および 2段キャッシュ対応リゾルバ。
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .crypto import (
    EMPTY_SHA256,
    NS_L2_LOCATOR,
    NS_L4_LOG,
    ChunkIntegrityError,
    SignatureVerificationError,
    canonical_json,
    normalize_path,
    sha256_hex,
    ssh_sign,
    ssh_verify,
)
from .l1_delegation import DelegationError, verify_single_delegation


class RegistryError(Exception):
    """L2 名簿・通信エラー"""


class ServiceUnavailableError(RegistryError):
    """L2 名簿または L3 OST が停止中の場合の明示的拒否例外"""


class ConflictError(RegistryError):
    """単一書き手境界の CAS 競合または A5 リプレイ検出例外"""


def create_locator_envelope(
    writer_priv_key: Path | str,
    path: str,
    delegation_epoch: int,
    head_version: int,
    head_hash: str,
    endpoints: List[str],
    expires_at: int,
    ttl: int = 300,
) -> Dict[str, Any]:
    """署名付きロケータエンベロープ (`dfs5-l2-locator-v1`) を生成する。"""
    norm_path = normalize_path(path)
    payload = {
        "delegation_epoch": int(delegation_epoch),
        "endpoints": list(endpoints),
        "expires_at": int(expires_at),
        "head_hash": head_hash,
        "head_version": int(head_version),
        "path": norm_path,
        "ttl": int(ttl),
    }
    raw_bytes = canonical_json(payload)
    try:
        sig = ssh_sign(writer_priv_key, NS_L2_LOCATOR, raw_bytes)
    except SignatureVerificationError as e:
        raise RegistryError(str(e)) from e

    return {
        "payload": payload,
        "signature": sig,
    }


def verify_locator_envelope(
    envelope: Dict[str, Any],
    expected_path: str,
    writer_pubkey: str,
    now: int,
) -> Dict[str, Any]:
    if "payload" not in envelope or "signature" not in envelope:
        raise RegistryError("Malformed locator envelope")
    p = envelope["payload"]
    if p.get("path") != expected_path:
        raise RegistryError(f"Locator path mismatch: expected {expected_path!r}, got {p.get('path')!r}")
    if now >= p.get("expires_at", 0):
        raise RegistryError("Locator has expired")
    raw_bytes = canonical_json(p)
    if not ssh_verify(writer_pubkey, expected_path, NS_L2_LOCATOR, raw_bytes, envelope["signature"]):
        raise RegistryError("Invalid L2 locator signature")
    return p


class DirectoryRegistryService:
    """
    L2 名簿 (MDSAnnouncer 型) + L1 委譲チェーン保持 + L4 先頭版 CAS 調停を担うサービス。
    evil 試験用のフック (`simulate_silent_drop_b7`, `simulate_rollback_b6_to_index`) も備える。
    """

    def __init__(self, root_anchor_path: str, root_anchor_pubkey: str):
        self.root_anchor_path = normalize_path(root_anchor_path)
        self.root_anchor_pubkey = root_anchor_pubkey.strip()
        self.delegations: Dict[str, Dict[str, Any]] = {}
        self.logs: Dict[str, List[Dict[str, Any]]] = {}
        self.locators: Dict[str, Dict[str, Any]] = {}
        self.online: bool = True

        # evil B6 / B7 試験用シミュレーションフラグ
        self.simulate_silent_drop_b7: bool = False
        self.simulate_rollback_b6_to_index: int = -1

    def _ensure_online(self) -> None:
        if not self.online:
            raise ServiceUnavailableError("L2 DirectoryRegistryService is offline")

    def register_delegation(self, envelope: Dict[str, Any], now: int) -> Dict[str, Any]:
        """L1 委譲レコードを検証・登録する（多段委譲・エポック更新による即時失効に対応）。"""
        self._ensure_online()
        p = envelope.get("payload", {})
        parent = p.get("parent", "")
        path = p.get("path", "")

        if parent == self.root_anchor_path:
            parent_pub = self.root_anchor_pubkey
            parent_exp = None
        elif parent in self.delegations:
            parent_del = self.delegations[parent]["payload"]
            if not (parent_del["issued_at"] <= now < parent_del["expires_at"]):
                raise DelegationError(f"Parent delegation {parent!r} has expired")
            parent_pub = parent_del["writer"]
            parent_exp = parent_del["expires_at"]
        else:
            raise DelegationError(f"Unknown or unverified parent path: {parent!r} (Invariant 5)")

        curr_active = self.delegations.get(path)
        curr_epoch = curr_active["payload"]["epoch"] if curr_active else None

        log_list = self.logs.get(path, [])
        curr_head_ver = log_list[-1]["payload"]["version"] if log_list else 0

        verified = verify_single_delegation(
            envelope=envelope,
            parent_pubkey=parent_pub,
            now=now,
            parent_expires_at=parent_exp,
            current_active_epoch=curr_epoch,
            current_head_version=curr_head_ver,
        )
        self.delegations[path] = envelope
        return verified

    def announce_and_append(
        self,
        path: str,
        log_envelope: Dict[str, Any],
        locator_envelope: Dict[str, Any],
        now: int,
    ) -> None:
        """
        単一書き手の CAS 検証を行った上で L4 ログを追記し、L2 ロケータを更新する。
        """
        self._ensure_online()
        norm_path = normalize_path(path)
        del_env = self.delegations.get(norm_path)
        if not del_env:
            raise DelegationError(f"No active delegation registered for {norm_path!r}")

        del_p = del_env["payload"]
        if not (del_p["issued_at"] <= now < del_p["expires_at"]):
            raise DelegationError(f"Active delegation for {norm_path!r} has expired")

        log_p = log_envelope["payload"]
        raw_log = canonical_json(log_p)
        if sha256_hex(raw_log) != log_envelope.get("entry_hash"):
            raise ChunkIntegrityError("L4 log entry_hash does not match canonical payload")

        # specs/delegation.md §3.1: エポック一致検証（旧鍵の即時失効）
        if log_p["delegation_epoch"] != del_p["epoch"]:
            raise DelegationError(
                f"Stale or mismatched delegation_epoch: got {log_p['delegation_epoch']}, active is {del_p['epoch']}"
            )

        # specs/delegation.md §3.2: base_version 引き継ぎ境界検証
        if log_p["version"] <= del_p["base_version"]:
            raise DelegationError(
                f"Version ({log_p['version']}) must be > base_version ({del_p['base_version']})"
            )

        log_list = self.logs.setdefault(norm_path, [])
        head_ver = log_list[-1]["payload"]["version"] if log_list else 0
        head_hash = log_list[-1]["entry_hash"] if log_list else EMPTY_SHA256

        # 単一書き手境界 (CAS) および evil A5 (リプレイ攻撃防止)
        if (
            log_p["version"] != head_ver + 1
            or log_p["parent_version"] != head_ver
            or log_p["parent_hash"] != head_hash
        ):
            raise ConflictError(
                f"CAS conflict on {norm_path!r}: expected version {head_ver + 1} (parent {head_ver}, {head_hash[:10]}...), "
                f"got version {log_p['version']} (parent {log_p['parent_version']}, {log_p['parent_hash'][:10]}...)"
            )

        # L4 ログ署名検証
        if not ssh_verify(del_p["writer"], norm_path, NS_L4_LOG, raw_log, log_envelope["signature"]):
            raise DelegationError("Invalid L4 log signature by writer")

        # L2 ロケータ署名検証と整合確認
        loc_p = verify_locator_envelope(locator_envelope, norm_path, del_p["writer"], now)
        if loc_p["head_version"] != log_p["version"] or loc_p["head_hash"] != log_envelope["entry_hash"]:
            raise RegistryError("Locator head_version/head_hash does not match L4 log entry")

        # evil B7 シミュレーション（成功したふりをして黙って破棄）
        if self.simulate_silent_drop_b7:
            return

        log_list.append(log_envelope)
        self.locators[norm_path] = locator_envelope

    def delegation_chain(self, path: str) -> List[Dict[str, Any]]:
        """``path`` に至る委譲チェーンを、root 直下から末端まで順に組み立てる。

        名簿は末端の委譲しか索引していないので、``parent`` をたどって並べる。
        クライアントはこれを root アンカー公開鍵から検証する（名簿を信頼しない）。
        """
        norm_path = normalize_path(path)
        chain: List[Dict[str, Any]] = []
        cur = norm_path
        seen = set()
        while cur:
            if cur in seen:
                raise RegistryError(f"Delegation chain for {norm_path!r} has a cycle at {cur!r}")
            seen.add(cur)
            env = self.delegations.get(cur)
            if env is None:
                break
            chain.append(env)
            parent = env.get("payload", {}).get("parent", "")
            if parent == self.root_anchor_path:
                break
            cur = parent
        chain.reverse()
        return chain

    def resolve(
        self, path: str
    ) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
        """
        (delegation_envelope, locator_envelope, head_log_envelope) を 1 RTT で返す。

        ``delegation_envelope`` には、末端の委譲に **チェーンの組** と **root アンカー** を
        足したものを返す。クライアントはこれで root から検証できる（名簿を信頼しない）。
        """
        self._ensure_online()
        norm_path = normalize_path(path)
        del_env = self.delegations.get(norm_path)
        loc_env = self.locators.get(norm_path)
        log_list = self.logs.get(norm_path, [])

        # 末端の委譲に、チェーンと root アンカーの情報を足して返す。
        # クライアントはこの組で root から検証する（名簿を信頼しない）。
        if del_env is not None:
            del_env = dict(del_env)
            del_env["chain"] = self.delegation_chain(norm_path)
            del_env["root_anchor"] = self.root_anchor_path

        if not log_list:
            return del_env, loc_env, None

        # evil B6 シミュレーション（古いログエントリを先頭と見せかける）
        if 0 <= self.simulate_rollback_b6_to_index < len(log_list):
            stale_head = log_list[self.simulate_rollback_b6_to_index]
            return del_env, loc_env, stale_head

        return del_env, loc_env, log_list[-1]
