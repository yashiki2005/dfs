#!/usr/bin/env python3
"""
dfs5/l4_log.py
L4 (一貫性・単一書き手追記ログ・Merkle ディレクトリ塊・evil B6/B7 防御) モジュール。
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from .crypto import (
    EMPTY_SHA256,
    NS_L4_LOG,
    ChunkIntegrityError,
    ContentAddressedCrypto,
    SignatureVerificationError,
    canonical_json,
    normalize_name,
    normalize_path,
    sha256_hex,
    ssh_sign,
    ssh_verify,
)
from .l1_delegation import DelegationError
from .l2_registry import DirectoryRegistryService, create_locator_envelope
from .l3_ost_adapter import OSTClient


class RollbackDetectedError(Exception):
    """evil B6: リモートの先頭版またはハッシュがローカルピンより古い・不一致"""


class SilentDropDetectedError(Exception):
    """evil B7: 書き込み成功応答直後の Read-after-Write 照合で不一致を検出"""


@dataclass
class HeadPin:
    """B6 / B7 を防ぐためクライアントが手元に保持する 1 行の状態 (local_head.json)"""

    version: int = 0
    entry_hash: str = EMPTY_SHA256
    delegation_epoch: int = 0

    def save(self, path: Path) -> None:
        path.write_bytes(canonical_json(asdict(self)))

    @classmethod
    def load(cls, path: Path) -> "HeadPin":
        if not path.exists():
            return cls()
        data = json.loads(path.read_text(encoding="utf-8"))
        return cls(
            version=int(data["version"]),
            entry_hash=str(data["entry_hash"]),
            delegation_epoch=int(data["delegation_epoch"]),
        )


class MerkleTreeBuilder:
    """
    ローカルディレクトリ（またはメモリ辞書）と L3 OST の間で Merkle ディレクトリ塊 (`dfs5-dir-v1`) を読み書きする。
    再委譲された境界 (`delegated_mounts`) はシンボリック参照として記録し、親のハッシュ計算から切り離す。

    ストライピング:
      複数の OST を `stores` に渡すと、塊を round-robin で分散させる。
      現在の既定は 1 OST（`stores={"ost0": client}`）であり、2 個以上渡せば分散する。
      各エントリには配置先の `store` を持たせる（既定の OST のときは省略する）。
    """

    IGNORED_NAMES = {".clayfs", ".DS_Store"}

    def __init__(
        self,
        crypto: ContentAddressedCrypto,
        ost: OSTClient,
        stores: Optional[Dict[str, OSTClient]] = None,
        default_store: str = "ost0",
        index: Optional[Dict[str, Any]] = None,
    ):
        self.crypto = crypto
        # 後方互換: ost は既定の OST を指す
        self.ost = ost
        self.stores: Dict[str, OSTClient] = dict(stores) if stores else {default_store: ost}
        self.default_store = default_store if default_store in self.stores else next(iter(self.stores))
        self.stripe_order: list[str] = list(self.stores.keys())
        self._next_stripe = 0
        # (plain_id -> (wire_id, store_id)) の書き手側索引。古い形式（str）も読める。
        self.index: Dict[str, Any] = dict(index or {})

    # ---- ストア選択 -------------------------------------------------------
    def _store_for_new_chunk(self) -> str:
        """新しい塊の配置先を round-robin で決める。現在 1 OST なら常に既定。"""
        if len(self.stripe_order) == 1:
            return self.stripe_order[0]
        sid = self.stripe_order[self._next_stripe % len(self.stripe_order)]
        self._next_stripe += 1
        return sid

    def _client(self, store_id: str) -> OSTClient:
        return self.stores.get(store_id, self.ost)

    @staticmethod
    def _index_get(entry: Any) -> Optional[Tuple[str, str]]:
        """索引の値を (wire_id, store_id) に正規化する。旧形式の str も受ける。"""
        if entry is None:
            return None
        if isinstance(entry, str):
            return entry, ""
        if isinstance(entry, (tuple, list)) and len(entry) == 2:
            return str(entry[0]), str(entry[1])
        return None

    # ---- 書き込み ---------------------------------------------------------
    def upload_directory(
        self,
        source_dir: Path,
        delegated_mounts: Optional[Dict[str, str]] = None,
    ) -> Tuple[str, str]:
        """ディレクトリを再帰的に塊化して OST に PUT し、(root_plain_id, root_wire_id) を返す。

        重複排除は暗号化の前に plain_id で判定する。索引にあり OST にも現存する塊は
        再暗号化も再送もしない（Nonce がランダムでも重複排除率は落ちない）。
        """
        delegated_mounts = delegated_mounts or {}
        pending: Dict[str, Dict[str, bytes]] = {sid: {} for sid in self.stores}

        def _stage(plaintext: bytes) -> Tuple[str, str, str]:
            plain_id = self.crypto.compute_plain_id(plaintext).hex()
            known = self._index_get(self.index.get(plain_id))
            if known is not None:
                known_wire, known_store = known
                store_id = known_store or self.default_store
                if known_wire in pending.get(store_id, {}):
                    return plain_id, known_wire, store_id
                try:
                    if self._client(store_id).batch_has([known_wire]).get(known_wire, False):
                        return plain_id, known_wire, store_id
                except Exception:
                    pass
            store_id = self._store_for_new_chunk()
            pack_pid, wire_id, blob = self.crypto.pack_chunk(plaintext)
            assert pack_pid == plain_id
            self.index[plain_id] = (wire_id, store_id)
            pending.setdefault(store_id, {})[wire_id] = blob
            return plain_id, wire_id, store_id

        def _entry(store_id: str) -> Dict[str, Any]:
            # 既定の OST のときは store を書かない（旧リーダーとの互換）
            return {} if store_id == self.default_store else {"store": store_id}

        def _walk(directory: Path, mounts: Dict[str, str]) -> Tuple[str, str, str]:
            items: list = []
            for item in sorted(directory.iterdir(), key=lambda q: q.name):
                if item.name in self.IGNORED_NAMES or item.name.startswith("._"):
                    continue
                norm_name = normalize_name(item.name)
                if norm_name in mounts:
                    items.append(
                        {
                            "mount_path": normalize_path(mounts[norm_name]),
                            "name": norm_name,
                            "type": "delegated_mount",
                        }
                    )
                elif item.is_file():
                    raw_data = item.read_bytes()
                    pid, wid, sid = _stage(raw_data)
                    item_entry = {
                        "name": norm_name,
                        "plain_id": pid,
                        "size": len(raw_data),
                        "type": "file",
                        "wire_id": wid,
                    }
                    item_entry.update(_entry(sid))
                    items.append(item_entry)
                elif item.is_dir():
                    sub_pid, sub_wid, sub_sid = _walk(item, {})
                    item_entry = {
                        "name": norm_name,
                        "plain_id": sub_pid,
                        "type": "dir",
                        "wire_id": sub_wid,
                    }
                    item_entry.update(_entry(sub_sid))
                    items.append(item_entry)
            items.sort(key=lambda e: e["name"])
            dir_bytes = canonical_json({"entries": items, "format": "dfs5-dir-v1"})
            return _stage(dir_bytes)

        root_pid, root_wid, root_sid = _walk(source_dir, delegated_mounts)
        for sid, chunks in pending.items():
            if chunks:
                self._client(sid).batch_put_if_absent(chunks)
        # 根の配置先を呼び出し側が知れるよう、既定と異なるときは属性に残す
        self.root_store = root_sid
        return root_pid, root_wid

    # ---- 読み込み ---------------------------------------------------------
    def download_directory(
        self,
        root_plain_id: str,
        root_wire_id: str,
        dest_dir: Path,
        root_store: Optional[str] = None,
    ) -> None:
        """(root_plain_id, root_wire_id) から再帰的に塊を取得・検証・復号して dest_dir に展開する。"""
        dest_dir.mkdir(parents=True, exist_ok=True)
        store_id = root_store or self.default_store
        blob = self._client(store_id).get(root_wire_id)
        dir_bytes = self.crypto.unpack_chunk(root_plain_id, root_wire_id, blob)
        dir_obj = json.loads(dir_bytes.decode("utf-8"))

        if dir_obj.get("format") != "dfs5-dir-v1":
            raise ChunkIntegrityError("Invalid directory chunk format")

        for entry in dir_obj["entries"]:
            name = normalize_name(entry["name"])
            target = dest_dir / name
            etype = entry["type"]
            entry_store = entry.get("store") or self.default_store

            if etype == "file":
                f_blob = self._client(entry_store).get(entry["wire_id"])
                f_data = self.crypto.unpack_chunk(entry["plain_id"], entry["wire_id"], f_blob)
                if len(f_data) != entry.get("size", len(f_data)):
                    raise ChunkIntegrityError(f"File size mismatch for {name}")
                target.write_bytes(f_data)
            elif etype == "dir":
                self.download_directory(entry["plain_id"], entry["wire_id"], target, root_store=entry_store)
            elif etype == "delegated_mount":
                target.mkdir(parents=True, exist_ok=True)
            else:
                raise ChunkIntegrityError(f"Unknown directory entry type: {etype!r}")


class L4LogClient:
    """
    単一書き手追記ログの生成・署名・Read-after-Write (B7 防御)・巻き戻し検知 (B6 防御) を担う L4 クライアント。
    """

    def __init__(
        self,
        sub_path: str,
        priv_key_path: Path | str,
        pub_key_str: str,
        pin_file: Optional[Path] = None,
    ):
        self.sub_path = normalize_path(sub_path)
        self.priv_key_path = Path(priv_key_path)
        self.pub_key_str = pub_key_str.strip()
        self.pin_file = pin_file
        self.pin = HeadPin.load(pin_file) if pin_file else HeadPin()

    def _save_pin(self) -> None:
        if self.pin_file:
            self.pin.save(self.pin_file)

    def sync_head(
        self,
        registry: DirectoryRegistryService,
        expected_writer_pubkey: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        L2/L4 から先頭版を取得し、署名検証および B6（巻き戻し・フォーク）チェックを行ってローカルピンを更新する。
        """
        del_env, _, head_env = registry.resolve(self.sub_path)
        if head_env is None:
            if self.pin.version > 0:
                raise RollbackDetectedError(
                    f"B6 Rollback detected: remote log is empty, but local pin is at v{self.pin.version}"
                )
            return None

        p = head_env["payload"]
        raw_p = canonical_json(p)
        if sha256_hex(raw_p) != head_env.get("entry_hash"):
            raise ChunkIntegrityError("Remote head entry_hash corrupted")

        writer_pub = expected_writer_pubkey or (del_env["payload"]["writer"] if del_env else self.pub_key_str)
        if not ssh_verify(writer_pub, self.sub_path, NS_L4_LOG, raw_p, head_env["signature"]):
            raise ChunkIntegrityError("Remote head signature verification failed")

        # B6: 版番号の巻き戻し検出
        if p["version"] < self.pin.version:
            raise RollbackDetectedError(
                f"B6 Rollback detected: remote version {p['version']} < local pinned version {self.pin.version}"
            )
        # B6: 同一版番号での別ハッシュへのすり替え検出
        if p["version"] == self.pin.version and head_env["entry_hash"] != self.pin.entry_hash:
            raise RollbackDetectedError("B6 Fork/Tamper detected at same version")
        # B6: エポックの逆行検出
        if p["delegation_epoch"] < self.pin.delegation_epoch:
            raise RollbackDetectedError("B6 Delegation epoch rollback detected")

        self.pin = HeadPin(
            version=p["version"],
            entry_hash=head_env["entry_hash"],
            delegation_epoch=p["delegation_epoch"],
        )
        self._save_pin()
        return head_env

    def commit(
        self,
        registry: DirectoryRegistryService,
        root_plain_id: str,
        root_wire_id: str,
        delegation_epoch: int,
        ost_endpoint: str,
        now: int,
    ) -> Dict[str, Any]:
        """
        新しい版を署名して L2/L4 に CAS 追記し、直後に Read-after-Write 照合 (B7 防御) を行う。
        """
        next_ver = self.pin.version + 1
        log_payload = {
            "delegation_epoch": int(delegation_epoch),
            "parent_hash": self.pin.entry_hash,
            "parent_version": self.pin.version,
            "path": self.sub_path,
            "root_plain_id": root_plain_id,
            "root_wire_id": root_wire_id,
            "timestamp": int(now),
            "version": next_ver,
        }
        raw_log = canonical_json(log_payload)
        entry_hash = sha256_hex(raw_log)
        try:
            log_sig = ssh_sign(self.priv_key_path, NS_L4_LOG, raw_log)
        except SignatureVerificationError as e:
            raise DelegationError(str(e)) from e

        log_env = {
            "entry_hash": entry_hash,
            "payload": log_payload,
            "signature": log_sig,
        }

        loc_env = create_locator_envelope(
            writer_priv_key=self.priv_key_path,
            path=self.sub_path,
            delegation_epoch=delegation_epoch,
            head_version=next_ver,
            head_hash=entry_hash,
            endpoints=[ost_endpoint],
            expires_at=now + 86400,
        )

        # 1. CAS 追記要求
        registry.announce_and_append(self.sub_path, log_env, loc_env, now=now)

        # 2. B7 防御: Read-after-Write 照合（一致が確認できるまでローカルピンは進めない）
        _, _, readback = registry.resolve(self.sub_path)
        if (
            readback is None
            or readback["payload"]["version"] != next_ver
            or readback["entry_hash"] != entry_hash
        ):
            raise SilentDropDetectedError(
                f"B7 Silent drop detected: wrote v{next_ver} ({entry_hash[:10]}...), "
                f"but readback returned {readback['payload']['version'] if readback else None}"
            )

        # 3. 照合成功後にピンを更新
        self.pin = HeadPin(
            version=next_ver,
            entry_hash=entry_hash,
            delegation_epoch=delegation_epoch,
        )
        self._save_pin()
        return log_env