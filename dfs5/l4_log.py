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

        WAN 向けの往復回数: 索引ヒットの存在確認は全チャンクまとめて 1 往復の
        ``batch_has`` に集約し、送信も 1 往復の ``batch_put_if_absent`` で行う。
        したがって 1 回の push は「HAS 1 往復 + PUT 1 往復」に固定される
        （サーバ側から塊が消えていた場合のみ 2 回目の走査が入る）。
        """
        delegated_mounts = delegated_mounts or {}

        def _entry(store_id: str) -> Dict[str, Any]:
            # 既定の OST のときは store を書かない（旧リーダーとの互換）
            return {} if store_id == self.default_store else {"store": store_id}

        def _one_pass(
            force_new: set,
        ) -> Tuple[Dict[str, Dict[str, bytes]], Dict[str, Tuple[str, str]], Dict[str, Tuple[str, str]], Tuple[str, str, str]]:
            """ツリーを 1 回走査し結果を返す（``self.index`` は書き換えない）。

            戻り値: (送るべき塊, 索引ヒットした塊, 今回暗号化した塊, 根の 3 つ組)

            ``force_new`` の plain_id は索引を信用せず必ず再暗号化する
            （サーバ側から塊が消えていた場合の再構築に使う）。索引を書き換えないのは、
            2 回目の走査で 1 回目の結果と混ざらないようにするため。索引の更新は
            走査がすべて終わってからまとめて行う。
            """
            pending: Dict[str, Dict[str, bytes]] = {sid: {} for sid in self.stores}
            reused: Dict[str, Tuple[str, str]] = {}
            packed: Dict[str, Tuple[str, str]] = {}
            # 同じ走査中の重複排除。同一内容の 2 ファイル目以降は再暗号化しない。
            staged: Dict[str, Tuple[str, str]] = {}

            def _stage(plaintext: bytes) -> Tuple[str, str, str]:
                plain_id = self.crypto.compute_plain_id(plaintext).hex()
                if plain_id in staged:
                    wire_id, store_id = staged[plain_id]
                    return plain_id, wire_id, store_id
                known = None if plain_id in force_new else self._index_get(self.index.get(plain_id))
                if known is not None:
                    known_wire, known_store = known
                    store_id = known_store or self.default_store
                    reused[plain_id] = (known_wire, store_id)
                    staged[plain_id] = (known_wire, store_id)
                    return plain_id, known_wire, store_id
                store_id = self._store_for_new_chunk()
                pack_pid, wire_id, blob = self.crypto.pack_chunk(plaintext)
                assert pack_pid == plain_id
                packed[plain_id] = (wire_id, store_id)
                staged[plain_id] = (wire_id, store_id)
                pending.setdefault(store_id, {})[wire_id] = blob
                return plain_id, wire_id, store_id

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

            root = _walk(source_dir, delegated_mounts)
            return pending, reused, packed, root

        # ---- 1 回目の走査: 索引ヒットは「サーバに在る」と仮定して記録だけする ----
        pending, reused, packed, (root_pid, root_wid, root_sid) = _one_pass(force_new=set())

        # ---- 索引ヒットした塊の存在確認を 1 往復の一括 HAS にまとめる ----
        # ここが WAN 対応の要。チャンクごとに HAS を撃つ実装では往復がチャンク数に比例する。
        missing_plain: set = set()
        if reused:
            by_store: Dict[str, list] = {}
            for plain_id, (wire, store_id) in reused.items():
                by_store.setdefault(store_id, []).append((plain_id, wire))
            for store_id, pairs in by_store.items():
                try:
                    presence = self._client(store_id).batch_has([w for _pid, w in pairs])
                except Exception:
                    # HAS 自体が失敗したら安全側に倒し、その分は全再送する
                    missing_plain.update(pid for pid, _w in pairs)
                    continue
                for plain_id, wire in pairs:
                    if not presence.get(wire, False):
                        missing_plain.add(plain_id)

        # ---- 消えていた塊があれば、それを強制再生成してツリー全体を組み直す ----
        # ディレクトリ塊は子の wire_id を含むので、部分差し替えでは整合しない。
        if missing_plain:
            pending, reused, packed, (root_pid, root_wid, root_sid) = _one_pass(force_new=missing_plain)

        # ---- 索引を確定してから送る ----
        # 索引ヒットした塊は既存の索引をそのまま維持し、今回暗号化した塊だけ貼り替える。
        for plain_id, (wire_id, store_id) in packed.items():
            self.index[plain_id] = (wire_id, store_id)

        # ---- 送信: すべて「未確認（今回暗号化したか、無いと分かっている）」塊なので HAS を省く ----
        for sid, chunks in pending.items():
            if chunks:
                self._client(sid).batch_put_if_absent(chunks, assume_absent=True)

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