#!/usr/bin/env python3
"""
dfs/l2_registry.py
specs/l2_comparison.md に基づく署名付きロケータ (`dfs-l2-locator-v1`) と
名簿 (Directory) + L4 追記ログ CAS 調停サービス、および 2段キャッシュ対応リゾルバ。
"""

from __future__ import annotations

import threading
import time
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
from .l1_delegation import (
    DelegationError,
    verify_delegation_chain,
    verify_single_delegation,
)


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
    """署名付きロケータエンベロープ (`dfs-l2-locator-v1`) を生成する。"""
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
    if not isinstance(envelope, dict) or "payload" not in envelope or "signature" not in envelope:
        raise RegistryError("Malformed locator envelope")
    p = envelope["payload"]
    sig = envelope["signature"]
    if not isinstance(p, dict) or not isinstance(sig, str):
        raise RegistryError("Malformed locator envelope")
    if p.get("path") != expected_path:
        raise RegistryError(f"Locator path mismatch: expected {expected_path!r}, got {p.get('path')!r}")
    exp = p.get("expires_at")
    if not isinstance(exp, int) or isinstance(exp, bool) or now >= exp:
        raise RegistryError("Locator has expired")
    raw_bytes = canonical_json(p)
    if not ssh_verify(writer_pubkey, expected_path, NS_L2_LOCATOR, raw_bytes, sig):
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
        self.delegation_history: Dict[str, Dict[int, List[Dict[str, Any]]]] = {}
        self.logs: Dict[str, List[Dict[str, Any]]] = {}
        self.locators: Dict[str, Dict[str, Any]] = {}
        self.archives: Dict[str, Dict[int, Dict[str, Any]]] = {}
        self.candidacy: Optional[Dict[str, Any]] = None
        self.online: bool = True
        # 単一書き手境界の CAS は「head 読み取り -> 検証 -> append」を原子的に行う。
        # HTTP サーバは ThreadingHTTPServer なので、サービス側でも排他する。
        self._lock = threading.RLock()

        # evil B6 / B7 試験用シミュレーションフラグ
        self.simulate_silent_drop_b7: bool = False
        self.simulate_rollback_b6_to_index: int = -1

    def _ensure_online(self) -> None:
        if not self.online:
            raise ServiceUnavailableError("L2 DirectoryRegistryService is offline")

    @property
    def lock(self) -> threading.RLock:
        """HTTP ハンドラが state 保存まで同じ排他区間に入れるためのロック。"""
        return self._lock

    def set_candidacy(self, envelope: Dict[str, Any], now: int) -> Dict[str, Any]:
        """署名付き立候補エンベロープ (dfs-candidacy-v1) を検証して保存する。"""
        from .discovery import verify_candidacy_envelope

        with self._lock:
            self._ensure_online()
            min_epoch: Optional[int] = None
            if self.candidacy is not None:
                try:
                    min_epoch = int(self.candidacy.get("payload", {}).get("epoch", 1))
                except (TypeError, ValueError):
                    min_epoch = None
            verified = verify_candidacy_envelope(
                envelope,
                self.root_anchor_pubkey,
                expected_root_anchor=self.root_anchor_path,
                now=now,
                min_epoch=min_epoch,
            )
            self.candidacy = envelope
            return dict(verified.raw)

    def register_delegation(self, envelope: Dict[str, Any], now: int) -> Dict[str, Any]:
        """L1 委譲レコードを検証・登録する（多段委譲・エポック更新による即時失効に対応）。"""
        with self._lock:
            self._ensure_online()
            p = envelope.get("payload", {})
            parent = p.get("parent", "")
            path = p.get("path", "")

            if parent == self.root_anchor_path:
                parent_pub = self.root_anchor_pubkey
                parent_exp = None
            elif parent in self.delegations:
                parent_del = self._verify_active_chain(parent, now)
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
            self.delegations[verified["path"]] = envelope
            self.delegation_history.setdefault(verified["path"], {})[
                int(verified["epoch"])
            ] = self.delegation_chain(verified["path"])
            return verified

    def announce_and_append(
        self,
        path: str,
        log_envelope: Dict[str, Any],
        locator_envelope: Dict[str, Any],
        now: int,
        role_epoch: int = 1,
    ) -> None:
        """
        単一書き手の CAS 検証を行った上で L4 ログを追記し、L2 ロケータを更新する。
        """
        with self._lock:
            self._ensure_online()
            norm_path = normalize_path(path)
            del_p = self._verify_active_chain(norm_path, now)
            del_env = self.delegations[norm_path]

            log_p = log_envelope["payload"]
            try:
                log_path = normalize_path(log_p["path"])
            except (KeyError, TypeError, ValueError) as e:
                raise DelegationError(f"Invalid path in L4 log payload: {e}") from e
            if log_path != norm_path:
                raise DelegationError(
                    f"L4 log path mismatch: request={norm_path!r}, payload={log_path!r}"
                )

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
            if loc_p.get("delegation_epoch") != del_p["epoch"]:
                raise DelegationError("Locator delegation_epoch does not match active delegation")
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
        with self._lock:
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

    def register_archive(self, envelope: Dict[str, Any], now: int) -> Dict[str, Any]:
        """書き手署名付きarchive descriptorを、対応するL4 headへ束縛して登録する。"""
        from .archive import verify_archive_descriptor

        with self._lock:
            self._ensure_online()
            payload = envelope.get("payload", {})
            try:
                norm_path = normalize_path(payload["path"])
                version = int(payload["version"])
            except (KeyError, TypeError, ValueError) as e:
                raise RegistryError(f"Invalid archive descriptor: {e}") from e

            del_payload = self._verify_active_chain(norm_path, now)

            selected = next(
                (
                    entry
                    for entry in self.logs.get(norm_path, [])
                    if int(entry.get("payload", {}).get("version", -1)) == version
                ),
                None,
            )
            if selected is None:
                raise RegistryError(
                    f"No L4 version {version} for archive path {norm_path!r}"
                )
            verified = verify_archive_descriptor(
                envelope,
                norm_path,
                del_payload["writer"],
                head_log=selected,
            )
            current = self.archives.get(norm_path, {}).get(version)
            if current is not None and canonical_json(current) != canonical_json(envelope):
                raise ConflictError(
                    f"Archive descriptor already exists for {norm_path!r} v{version}"
                )
            self.archives.setdefault(norm_path, {})[version] = envelope
            return verified

    def list_archives(
        self, path: str, version: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """指定パスの署名済みarchive descriptorを版順で返す。"""
        with self._lock:
            self._ensure_online()
            norm_path = normalize_path(path)
            entries = self.archives.get(norm_path, {})
            if version is not None:
                selected = entries.get(int(version))
                return [selected] if selected is not None else []
            return [entries[key] for key in sorted(entries)]

    def replication_bundle(self, path: str) -> Optional[Dict[str, Any]]:
        """複製名簿へ送る、署名済みの委譲チェーン・ログ・ロケータの束。"""
        with self._lock:
            norm_path = normalize_path(path)
            if norm_path not in self.delegations:
                return None
            current_chain = self.delegation_chain(norm_path)
            epoch_chains = {
                str(ep): ch
                for ep, ch in self.delegation_history.get(norm_path, {}).items()
            }
            if current_chain:
                cur_ep = str(current_chain[-1].get("payload", {}).get("epoch", ""))
                if cur_ep:
                    epoch_chains.setdefault(cur_ep, current_chain)
            return {
                "root_anchor": self.root_anchor_path,
                "path": norm_path,
                "chain": current_chain,
                "epoch_chains": epoch_chains,
                "logs": list(self.logs.get(norm_path, [])),
                "locator": self.locators.get(norm_path),
                "archives": self.list_archives(norm_path),
            }

    def ingest_replica(self, bundle: Dict[str, Any], now: int) -> bool:
        """主名簿から受け取ったバンドルを検証して保存する（読み取り専用の複製）。

        署名済みの委譲チェーンと L4 ログを root アンカーから検証する。
        既存のログがバンドルの prefix でない場合は fork として拒否する。
        """
        with self._lock:
            self._ensure_online()
            if not isinstance(bundle, dict):
                raise RegistryError("Malformed replication bundle")
            root_anchor = bundle.get("root_anchor")
            if root_anchor != self.root_anchor_path:
                raise RegistryError(
                    f"Replication root anchor mismatch: expected {self.root_anchor_path!r}, "
                    f"got {root_anchor!r}"
                )
            raw_path = bundle.get("path")
            if not isinstance(raw_path, str):
                raise RegistryError("Replication bundle has no path")
            norm_path = normalize_path(raw_path)

            chain = bundle.get("chain") or []
            if not chain:
                raise DelegationError("Replication bundle has no delegation chain")
            leaf = verify_delegation_chain(
                root_anchor_path=self.root_anchor_path,
                root_anchor_pubkey=self.root_anchor_pubkey,
                chain=chain,
                now=now,
                requested_path=norm_path,
            )

            epoch_chains_raw = bundle.get("epoch_chains") or {}
            verified_epochs: Dict[int, Dict[str, Any]] = {int(leaf["epoch"]): leaf}
            verified_epoch_chains: Dict[int, List[Dict[str, Any]]] = {
                int(leaf["epoch"]): list(chain)
            }

            raw_logs = bundle.get("logs") or []
            if not isinstance(raw_logs, list):
                raise RegistryError("Replication logs must be a list")
            logs: List[Dict[str, Any]] = []
            prev_version = 0
            prev_hash = EMPTY_SHA256
            prev_epoch = 0
            for env in raw_logs:
                if not isinstance(env, dict) or "payload" not in env or "signature" not in env:
                    raise RegistryError("Malformed L4 log in replication bundle")
                p = env["payload"]
                try:
                    log_path = normalize_path(p["path"])
                except (KeyError, TypeError, ValueError) as e:
                    raise DelegationError(f"Invalid L4 log path in replication: {e}") from e
                if log_path != norm_path:
                    raise DelegationError(
                        f"Replication log path mismatch: expected {norm_path!r}, got {log_path!r}"
                    )
                raw = canonical_json(p)
                if sha256_hex(raw) != env.get("entry_hash"):
                    raise ChunkIntegrityError("Replication log entry_hash mismatch")
                log_epoch = p.get("delegation_epoch")
                if not isinstance(log_epoch, int):
                    raise DelegationError("Replication log delegation_epoch mismatch")
                if log_epoch < prev_epoch:
                    raise DelegationError("Replication log delegation_epoch regressed")
                if log_epoch not in verified_epochs:
                    ep_chain = None
                    if isinstance(epoch_chains_raw, dict):
                        ep_chain = epoch_chains_raw.get(str(log_epoch)) or epoch_chains_raw.get(log_epoch)
                    if not ep_chain:
                        raise DelegationError("Replication log delegation_epoch mismatch")
                    log_ts = p.get("timestamp")
                    ep_now = int(log_ts) if isinstance(log_ts, (int, float)) else now
                    ep_leaf = verify_delegation_chain(
                        root_anchor_path=self.root_anchor_path,
                        root_anchor_pubkey=self.root_anchor_pubkey,
                        chain=ep_chain,
                        now=ep_now,
                        requested_path=norm_path,
                    )
                    if int(ep_leaf["epoch"]) != log_epoch:
                        raise DelegationError("Replication epoch_chains epoch mismatch")
                    verified_epochs[log_epoch] = ep_leaf
                    verified_epoch_chains[log_epoch] = list(ep_chain)
                ep_leaf = verified_epochs[log_epoch]
                if p.get("version") != prev_version + 1:
                    raise ConflictError(
                        f"Replication log version gap: expected {prev_version + 1}, "
                        f"got {p.get('version')}"
                    )
                if p.get("version") <= ep_leaf["base_version"]:
                    raise DelegationError("Replication log version is at or below base_version")
                if p.get("parent_version") != prev_version or p.get("parent_hash") != prev_hash:
                    raise ConflictError("Replication log parent mismatch")
                if not ssh_verify(
                    ep_leaf["writer"], norm_path, NS_L4_LOG, raw, env["signature"]
                ):
                    raise DelegationError("Invalid replication log signature")
                logs.append(env)
                prev_version = p["version"]
                prev_hash = env["entry_hash"]
                prev_epoch = log_epoch

            locator = bundle.get("locator")
            if logs:
                if not locator:
                    raise RegistryError("Replication bundle has logs but no locator")
                raw_locator_payload = locator.get("payload")
                if not isinstance(raw_locator_payload, dict):
                    raise RegistryError("Malformed replication locator")
                try:
                    locator_epoch = int(raw_locator_payload["delegation_epoch"])
                except (KeyError, TypeError, ValueError) as e:
                    raise RegistryError("Replication locator has no valid epoch") from e
                if locator_epoch != prev_epoch:
                    raise DelegationError(
                        "Replication locator does not match the log head epoch"
                    )
                locator_leaf = verified_epochs.get(locator_epoch)
                if locator_leaf is None:
                    raise DelegationError(
                        "Replication locator epoch has no verified delegation chain"
                    )
                loc_p = verify_locator_envelope(
                    locator,
                    norm_path,
                    locator_leaf["writer"],
                    now,
                )
                if loc_p["head_version"] != prev_version or loc_p["head_hash"] != prev_hash:
                    raise RegistryError("Replication locator does not match the log head")
            elif locator is not None:
                raise RegistryError("Replication bundle has a locator but no logs")

            raw_archives = bundle.get("archives") or []
            if not isinstance(raw_archives, list):
                raise RegistryError("Replication archives must be a list")
            from .archive import verify_archive_descriptor

            archives: Dict[int, Dict[str, Any]] = {}
            for envelope in raw_archives:
                if not isinstance(envelope, dict):
                    raise RegistryError("Malformed archive descriptor in replication bundle")
                p = envelope.get("payload", {})
                try:
                    version = int(p["version"])
                except (KeyError, TypeError, ValueError) as e:
                    raise RegistryError("Archive descriptor has no valid version") from e
                selected = next(
                    (
                        entry
                        for entry in logs
                        if int(entry.get("payload", {}).get("version", -1)) == version
                    ),
                    None,
                )
                if selected is None:
                    raise RegistryError("Archive descriptor has no matching replicated L4 log")
                archive_epoch = int(selected.get("payload", {}).get("delegation_epoch", leaf["epoch"]))
                archive_leaf = verified_epochs.get(archive_epoch, leaf)
                verify_archive_descriptor(
                    envelope,
                    norm_path,
                    archive_leaf["writer"],
                    head_log=selected,
                )
                archives[version] = envelope

            if prev_epoch > int(leaf["epoch"]):
                raise DelegationError(
                    f"Replication log epoch {prev_epoch} exceeds active chain epoch {leaf['epoch']}"
                )

            existing = self.logs.get(norm_path, [])
            if len(existing) > len(logs):
                # 複製名簿の方が進んでいる。古いバンドルで巻き戻さない。
                return False
            existing_del = self.delegations.get(norm_path)
            if len(existing) == len(logs) and existing_del is not None:
                existing_epoch = int(existing_del.get("payload", {}).get("epoch", 0))
                if int(leaf["epoch"]) < existing_epoch:
                    return False
            for i, old_env in enumerate(existing):
                if old_env.get("entry_hash") != logs[i].get("entry_hash"):
                    raise ConflictError("Replication fork detected")

            if archives:
                current = self.archives.get(norm_path, {})
                for version, envelope in archives.items():
                    existing_envelope = current.get(version)
                    if (
                        existing_envelope is not None
                        and canonical_json(existing_envelope) != canonical_json(envelope)
                    ):
                        raise ConflictError(
                            f"Archive descriptor fork detected for {norm_path!r} v{version}"
                        )

            self._store_replica_chain(chain)
            self.delegation_history.setdefault(norm_path, {}).update(verified_epoch_chains)
            if logs:
                self.logs[norm_path] = logs
                self.locators[norm_path] = locator
            if archives:
                self.archives.setdefault(norm_path, {}).update(archives)
            return True

    def _verify_active_chain(self, path: str, now: int) -> Dict[str, Any]:
        norm_path = normalize_path(path)
        if norm_path not in self.delegations:
            raise DelegationError(f"No active delegation registered for {norm_path!r}")
        chain = self.delegation_chain(norm_path)
        return verify_delegation_chain(
            root_anchor_path=self.root_anchor_path,
            root_anchor_pubkey=self.root_anchor_pubkey,
            chain=chain,
            now=now,
            requested_path=norm_path,
        )

    def _store_replica_chain(self, chain: List[Dict[str, Any]]) -> None:
        for env in chain:
            p = env.get("payload", {})
            anc_path = normalize_path(p["path"])
            existing = self.delegations.get(anc_path)
            if existing is not None:
                existing_epoch = int(existing.get("payload", {}).get("epoch", 0))
                if int(p.get("epoch", 0)) < existing_epoch:
                    continue
            self.delegations[anc_path] = env

    def resolve(
        self,
        path: str,
        version: Optional[int] = None,
        now: Optional[int] = None,
    ) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
        """
        (delegation_envelope, locator_envelope, head_log_envelope) を 1 RTT で返す。

        ``delegation_envelope`` には、末端の委譲に **チェーンの組** と **root アンカー** を
        足したものを返す。クライアントはこれで root から検証できる（名簿を信頼しない）。
        """
        with self._lock:
            self._ensure_online()
            norm_path = normalize_path(path)
            del_env = self.delegations.get(norm_path)
            loc_env = self.locators.get(norm_path)
            log_list = self.logs.get(norm_path, [])

            if not log_list:
                selected = None
            elif version is not None:
                try:
                    wanted = int(version)
                except (TypeError, ValueError) as e:
                    raise RegistryError(f"Invalid version: {version!r}") from e
                selected = next(
                    (entry for entry in log_list
                     if int(entry.get("payload", {}).get("version", -1)) == wanted),
                    None,
                )
                if selected is None:
                    raise RegistryError(
                        f"Version {wanted} not found for {norm_path!r}"
                    )
            elif 0 <= self.simulate_rollback_b6_to_index < len(log_list):
                # evil B6 シミュレーション（古いログエントリを先頭と見せかける）
                selected = log_list[self.simulate_rollback_b6_to_index]
            else:
                selected = log_list[-1]

            # 署名検証には、選択した head を書いた時点の委譲チェーンを返す。
            # エポック切替直後は現在のチェーンと head のエポックが異なるため、
            # 常に現在のチェーンを返すと旧 head の署名検証に失敗する。
            response_chain: List[Dict[str, Any]] = []
            if del_env is not None:
                response_epoch = (
                    int(selected["payload"]["delegation_epoch"])
                    if selected is not None
                    else int(del_env["payload"]["epoch"])
                )
                response_chain = list(
                    self.delegation_history.get(norm_path, {}).get(
                        response_epoch, []
                    )
                )
                if not response_chain:
                    current_chain = self.delegation_chain(norm_path)
                    if (
                        current_chain
                        and int(
                            current_chain[-1].get("payload", {}).get("epoch", -1)
                        )
                        == response_epoch
                    ):
                        response_chain = current_chain

            if response_chain:
                del_env = dict(response_chain[-1])
                del_env["chain"] = response_chain
                del_env["root_anchor"] = self.root_anchor_path
            elif del_env is not None:
                del_env = dict(del_env)

            if selected is None:
                return del_env, loc_env, None
            # ロケータは現在の先頭版にしか対応しない。過去版では返さない。
            selected_locator = loc_env if selected is log_list[-1] else None
            if selected_locator is not None:
                try:
                    expires_at = int(
                        selected_locator.get("payload", {}).get("expires_at", 0)
                    )
                except (TypeError, ValueError):
                    expires_at = 0
                check_now = int(time.time()) if now is None else int(now)
                if check_now >= expires_at:
                    # endpointはL2の/v1/ostから再解決できる。期限切れの署名済み
                    # locatorをクライアントへ返して読み取り全体を止めない。
                    selected_locator = None
            return del_env, selected_locator, selected

    def history(self, path: str, limit: int = 50) -> List[Dict[str, Any]]:
        """指定パスの L4 ログ履歴を新しい順に返す（署名済みエンベロープの要約）。"""
        with self._lock:
            self._ensure_online()
            norm_path = normalize_path(path)
            if limit < 1 or limit > 1000:
                raise RegistryError(f"history limit must be between 1 and 1000: {limit}")
            entries = list(self.logs.get(norm_path, []))
            rows = []
            for entry in reversed(entries[-limit:]):
                p = entry.get("payload", {})
                rows.append({
                    "entry_hash": entry.get("entry_hash", ""),
                    "path": p.get("path", norm_path),
                    "timestamp": p.get("timestamp"),
                    "version": p.get("version"),
                })
            return rows
