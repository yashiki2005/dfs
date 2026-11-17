#!/usr/bin/env python3
"""
dfs/l4_log.py
L4 (一貫性・単一書き手追記ログ・Merkle ディレクトリ塊・evil B6/B7 防御) モジュール。
"""

from __future__ import annotations

import base64
import json
import os
import sqlite3
import stat
import sys
import tempfile
import threading
import time
from collections.abc import MutableMapping
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Sequence, Tuple, Protocol
from contextlib import contextmanager

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
from .compression import (
    effective_policy,
    list_raw_xattrs,
    normalize_policy,
    set_raw_xattr,
    set_xattr,
)
from .l1_delegation import DelegationError, verify_delegation_chain
from .l2_registry import (
    DirectoryRegistryService,
    create_locator_envelope,
    verify_locator_envelope,
)
from .l3_ost_adapter import OSTClientProtocol, _get_available_memory_bytes
from .path_safety import UnsafePathError, _open_no_follow
from .private_io import write_private_json


_ACTIVE_BUILDERS: "set[MerkleTreeBuilder]" = set()
_ACTIVE_BUILDERS_LOCK = threading.Lock()


class RollbackDetectedError(Exception):
    """evil B6: リモートの先頭版またはハッシュがローカルピンより古い・不一致"""


def _env_positive_int(name: str, default: int) -> int:
    """環境変数から正の整数を読む。未設定・不正値・0 以下は既定に戻す。"""
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value > 0 else default


MIN_DYNAMIC_BATCH_BYTES = 8 * 1024 * 1024
MAX_DYNAMIC_BATCH_BYTES = 256 * 1024 * 1024


def _dynamic_batch_bytes(default: int = 16 * 1024 * 1024) -> int:
    """DFS_BATCH_BYTES 未指定時、空きメモリの 1/8 を上限（8MiB〜256MiB）として返す。"""
    raw = os.environ.get("DFS_BATCH_BYTES")
    if raw is not None and raw.strip() != "":
        return _env_positive_int("DFS_BATCH_BYTES", default)
    avail = _get_available_memory_bytes()
    if avail is None or avail <= 0:
        return default
    budget = avail // 8
    return max(MIN_DYNAMIC_BATCH_BYTES, min(MAX_DYNAMIC_BATCH_BYTES, budget))


def _normalize_index_entry(entry: Any) -> Optional[Tuple[str, str, str]]:
    """索引エントリを ``(wire_id, store_id, codec)`` へ正規化する。"""
    if isinstance(entry, str) and entry:
        return entry, "", "none"
    if isinstance(entry, (tuple, list)):
        if len(entry) == 2:
            wire_id, store_id = entry
            if isinstance(wire_id, str) and wire_id:
                return wire_id, str(store_id or ""), "none"
        elif len(entry) >= 3:
            wire_id, store_id, codec = entry[0], entry[1], entry[2]
            if isinstance(wire_id, str) and wire_id:
                return wire_id, str(store_id or ""), str(codec or "none")
    return None


class SQLiteChunkIndex(MutableMapping[str, Tuple[str, str, str]]):
    """全件をメモリに載せず SQLite 上で重複排除索引を保持する辞書互換ストア。"""

    def __init__(self, db_path: Path, address_key: str) -> None:
        self.db_path = Path(db_path).expanduser()
        self.address_key = str(address_key)
        self._lock = threading.RLock()
        self._closed = False
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        legacy_entries = self._extract_legacy_json_if_needed()
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
        )
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS ost_index ("
            "plain_id TEXT PRIMARY KEY, "
            "wire_id TEXT NOT NULL, "
            "store_id TEXT NOT NULL, "
            "codec TEXT NOT NULL"
            ") WITHOUT ROWID"
        )
        row = self._conn.execute(
            "SELECT value FROM meta WHERE key = 'address_key'"
        ).fetchone()
        if row is not None and row[0] != self.address_key:
            self._conn.execute("DELETE FROM ost_index")
        self._conn.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES ('address_key', ?)",
            (self.address_key,),
        )
        if legacy_entries:
            self._conn.executemany(
                "INSERT OR REPLACE INTO ost_index (plain_id, wire_id, store_id, codec) "
                "VALUES (?, ?, ?, ?)",
                legacy_entries,
            )
        self._conn.commit()
        if os.name != "nt":
            try:
                os.chmod(self.db_path, 0o600)
            except OSError:
                pass

    def _extract_legacy_json_if_needed(self) -> List[Tuple[str, str, str, str]]:
        if not self.db_path.is_file() or self.db_path.stat().st_size == 0:
            return []
        try:
            with open(self.db_path, "rb") as fh:
                magic = fh.read(16)
        except OSError:
            return []
        if magic.startswith(b"SQLite format 3\x00"):
            return []
        migrated: List[Tuple[str, str, str, str]] = []
        try:
            data = json.loads(self.db_path.read_text(encoding="utf-8"))
            if (
                isinstance(data, dict)
                and data.get("schema") == "dfs-ost-index-v1"
                and data.get("address_key") == self.address_key
                and isinstance(data.get("entries"), dict)
            ):
                for plain_id, entry in data["entries"].items():
                    parsed = _normalize_index_entry(entry)
                    if parsed is not None:
                        migrated.append((str(plain_id), parsed[0], parsed[1], parsed[2]))
        except (OSError, ValueError, TypeError):
            migrated = []
        try:
            self.db_path.unlink()
        except OSError:
            pass
        return migrated

    def __getitem__(self, key: str) -> Tuple[str, str, str]:
        with self._lock:
            row = self._conn.execute(
                "SELECT wire_id, store_id, codec FROM ost_index WHERE plain_id = ?",
                (str(key),),
            ).fetchone()
        if row is None:
            raise KeyError(key)
        return (str(row[0]), str(row[1]), str(row[2]))

    def __setitem__(self, key: str, value: Any) -> None:
        parsed = _normalize_index_entry(value)
        if parsed is None:
            raise ValueError(f"Invalid index entry: {value!r}")
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO ost_index (plain_id, wire_id, store_id, codec) "
                "VALUES (?, ?, ?, ?)",
                (str(key), parsed[0], parsed[1], parsed[2]),
            )

    def __delitem__(self, key: str) -> None:
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM ost_index WHERE plain_id = ?", (str(key),)
            )
            if cur.rowcount == 0:
                raise KeyError(key)

    def __iter__(self) -> Iterator[str]:
        with self._lock:
            rows = self._conn.execute("SELECT plain_id FROM ost_index").fetchall()
        for row in rows:
            yield str(row[0])

    def __len__(self) -> int:
        with self._lock:
            row = self._conn.execute("SELECT COUNT(*) FROM ost_index").fetchone()
        return int(row[0]) if row else 0

    def commit(self) -> None:
        with self._lock:
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            self._conn.close()


class SilentDropDetectedError(Exception):
    """evil B7: 書き込み成功応答直後の Read-after-Write 照合で不一致を検出"""


FILE_CHUNK_BYTES = 8 * 1024 * 1024
UPLOAD_BATCH_BYTES = 64 * 1024 * 1024


@dataclass
class HeadPin:
    """B6 / B7 を防ぐためクライアントが手元に保持する 1 行の状態 (local_head.json)"""

    version: int = 0
    entry_hash: str = EMPTY_SHA256
    delegation_epoch: int = 0

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = canonical_json(asdict(self))
        fd, tmp_name = tempfile.mkstemp(
            prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent)
        )
        tmp = Path(tmp_name)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(payload)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, path)
            try:
                dir_fd = os.open(path.parent, os.O_RDONLY)
                try:
                    os.fsync(dir_fd)
                finally:
                    os.close(dir_fd)
            except OSError:
                pass
        finally:
            try:
                tmp.unlink()
            except FileNotFoundError:
                pass

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
    ローカルディレクトリ（またはメモリ辞書）と L3 OST の間で Merkle ディレクトリ塊 (`dfs-dir-v1`) を読み書きする。
    再委譲された境界 (`delegated_mounts`) はシンボリック参照として記録し、親のハッシュ計算から切り離す。

    ストライピング:
      複数の OST を `stores` に渡すと、塊を round-robin で分散させる。
      現在の既定は 1 OST（`stores={"ost0": client}`）であり、2 個以上渡せば分散する。
      各エントリには配置先の `store` を持たせる（既定の OST のときは省略する）。
    """

    IGNORED_NAMES = {".clayfs", ".DS_Store"}

    @staticmethod
    def _metadata(path: Path) -> Dict[str, Any]:
        """版に保存する POSIX メタデータ。所有者・特権 xattr は含めない。"""
        info = path.stat(follow_symlinks=False)
        result: Dict[str, Any] = {
            "mode": stat.S_IMODE(info.st_mode),
            "mtime_ns": int(info.st_mtime_ns),
        }
        xattrs = {
            name: base64.b64encode(value).decode("ascii")
            for name, value in list_raw_xattrs(path).items()
        }
        if xattrs:
            result["xattrs"] = xattrs
        return result

    def __init__(
        self,
        crypto: ContentAddressedCrypto,
        ost: OSTClientProtocol,
        stores: Optional[Dict[str, OSTClientProtocol]] = None,
        default_store: str = "ost0",
        index: Optional[Dict[str, Any]] = None,
        replicas: Optional[List[OSTClientProtocol]] = None,
        index_file: Optional[Path] = None,
        compression: str = "auto",
    ):
        self.crypto = crypto
        # 後方互換: ost は既定の OST を指す
        self.ost = ost
        self.stores: Dict[str, OSTClientProtocol] = dict(stores) if stores else {default_store: ost}
        self.default_store = default_store if default_store in self.stores else next(iter(self.stores))
        self.stripe_order: list[str] = list(self.stores.keys())
        self._next_stripe = 0
        # アップロード時に読み飛ばした項目（symlink など）を呼び出し側へ知らせる。
        self.warnings: List[str] = []
        # 書き込み後にチャンクを複製する読み取り専用 OST。
        self.replicas: List[OSTClientProtocol] = list(replicas or [])
        self._last_wire_ids: set[str] = set()
        # (plain_id -> (wire_id, store_id, codec)) の書き手側索引。
        self.index: MutableMapping[str, Any] = dict(index or {})
        self.index_file = Path(index_file).expanduser() if index_file else None
        self.index_key = sha256_hex(self.crypto.address_secret)
        self.compression = normalize_policy(compression)
        if self.index_file is not None and index is None:
            self.index = SQLiteChunkIndex(self.index_file, self.index_key)
        self._closed = False
        with _ACTIVE_BUILDERS_LOCK:
            _ACTIVE_BUILDERS.add(self)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            if isinstance(self.index, SQLiteChunkIndex):
                self.index.close()
        finally:
            with _ACTIVE_BUILDERS_LOCK:
                _ACTIVE_BUILDERS.discard(self)

    @classmethod
    def close_all(cls) -> None:
        with _ACTIVE_BUILDERS_LOCK:
            builders = list(_ACTIVE_BUILDERS)
        for builder in builders:
            try:
                builder.close()
            except Exception:
                pass

    def _save_index_file(self) -> None:
        if isinstance(self.index, SQLiteChunkIndex):
            self.index.commit()
            return
        if self.index_file is None:
            return
        entries: Dict[str, Any] = {}
        for plain_id, entry in self.index.items():
            parsed = _normalize_index_entry(entry)
            if parsed is not None:
                entries[str(plain_id)] = [parsed[0], parsed[1], parsed[2]]
        write_private_json(
            self.index_file,
            {
                "address_key": self.index_key,
                "entries": entries,
                "schema": "dfs-ost-index-v1",
            },
        )

    # ---- ストア選択 -------------------------------------------------------
    def _store_for_new_chunk(self) -> str:
        """新しい塊の配置先を round-robin で決める。現在 1 OST なら常に既定。"""
        if len(self.stripe_order) == 1:
            return self.stripe_order[0]
        sid = self.stripe_order[self._next_stripe % len(self.stripe_order)]
        self._next_stripe += 1
        return sid

    def _client(self, store_id: str) -> OSTClientProtocol:
        return self.stores.get(store_id, self.ost)

    @staticmethod
    def _index_get(entry: Any) -> Optional[Tuple[str, str, str]]:
        """索引の値を (wire_id, store_id, codec) に正規化する。旧形式も受ける。"""
        if entry is None:
            return None
        if isinstance(entry, str):
            return entry, "", "none"
        if isinstance(entry, (tuple, list)) and len(entry) == 2:
            return str(entry[0]), str(entry[1]), "none"
        if isinstance(entry, (tuple, list)) and len(entry) >= 3:
            return str(entry[0]), str(entry[1]), str(entry[2] or "none")
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
        self.warnings = []

        def _entry(store_id: str) -> Dict[str, Any]:
            # 既定の OST のときは store を書かない（旧リーダーとの互換）
            return {} if store_id == self.default_store else {"store": store_id}

        def _one_pass(
            force_new: set,
        ) -> Tuple[
            Dict[str, Dict[str, bytes]],
            Dict[str, Tuple[str, str, str]],
            Dict[str, Tuple[str, str, str]],
            Tuple[str, str, str, str],
        ]:
            """ツリーを 1 回走査し結果を返す（``self.index`` は書き換えない）。

            戻り値: (送るべき塊, 索引ヒットした塊, 今回暗号化した塊, 根の 3 つ組)

            ``force_new`` の plain_id は索引を信用せず必ず再暗号化する
            （サーバ側から塊が消えていた場合の再構築に使う）。索引を書き換えないのは、
            2 回目の走査で 1 回目の結果と混ざらないようにするため。索引の更新は
            走査がすべて終わってからまとめて行う。
            """
            pending: Dict[str, Dict[str, bytes]] = {sid: {} for sid in self.stores}
            pending_bytes: Dict[str, int] = {sid: 0 for sid in self.stores}
            reused: Dict[str, Tuple[str, str, str]] = {}
            packed: Dict[str, Tuple[str, str, str]] = {}
            # 同じ走査中の重複排除。同一内容の 2 ファイル目以降は再暗号化しない。
            staged: Dict[str, Tuple[str, str, str]] = {}
            all_wire_ids: set[str] = set()

            def _flush(store_id: str) -> None:
                chunks = pending.get(store_id) or {}
                if chunks:
                    self._client(store_id).batch_put_if_absent(
                        chunks, assume_absent=True
                    )
                pending[store_id] = {}
                pending_bytes[store_id] = 0

            def _stage(plaintext: bytes, policy: str) -> Tuple[str, str, str, str]:
                plain_id = self.crypto.compute_plain_id(plaintext).hex()
                if plain_id in staged:
                    wire_id, store_id, codec = staged[plain_id]
                    return plain_id, wire_id, store_id, codec
                known = None if plain_id in force_new else self._index_get(self.index.get(plain_id))
                if known is not None:
                    known_wire, known_store, known_codec = known
                    store_id = known_store or self.default_store
                    reused[plain_id] = (known_wire, store_id, known_codec)
                    staged[plain_id] = (known_wire, store_id, known_codec)
                    all_wire_ids.add(known_wire)
                    return plain_id, known_wire, store_id, known_codec
                store_id = self._store_for_new_chunk()
                pack_pid, wire_id, blob = self.crypto.pack_chunk(
                    plaintext, compression=policy
                )
                assert pack_pid == plain_id
                codec = self.crypto.chunk_codec(blob)
                packed[plain_id] = (wire_id, store_id, codec)
                staged[plain_id] = (wire_id, store_id, codec)
                all_wire_ids.add(wire_id)
                pending.setdefault(store_id, {})[wire_id] = blob
                pending_bytes[store_id] = (
                    pending_bytes.get(store_id, 0) + len(blob)
                )
                if pending_bytes[store_id] >= UPLOAD_BATCH_BYTES:
                    _flush(store_id)
                return plain_id, wire_id, store_id, codec

            def _walk(directory: Path, mounts: Dict[str, str]) -> Tuple[str, str, str, str]:
                dir_policy = effective_policy(directory, source_dir, self.compression)
                items: list = []
                for item in sorted(directory.iterdir(), key=lambda q: q.name):
                    if item.name in self.IGNORED_NAMES or item.name.startswith("._"):
                        continue
                    if item.is_symlink():
                        # dfs-dir-v1 に symlink 型はない。リンク先を読むとツリー外の
                        # ファイルをアップロードしてしまうため、明示的に飛ばす。
                        self.warnings.append(f"skipping symlink: {item}")
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
                        item_policy = effective_policy(item, source_dir, self.compression)
                        chunks: List[Dict[str, Any]] = []
                        offset = 0
                        with item.open("rb") as source:
                            while True:
                                raw_chunk = source.read(FILE_CHUNK_BYTES)
                                if not raw_chunk and chunks:
                                    break
                                pid, wid, sid, codec = _stage(raw_chunk, item_policy)
                                chunk_entry = {
                                    "codec": codec,
                                    "offset": offset,
                                    "plain_id": pid,
                                    "size": len(raw_chunk),
                                    "wire_id": wid,
                                }
                                chunk_entry.update(_entry(sid))
                                chunks.append(chunk_entry)
                                offset += len(raw_chunk)
                                if len(raw_chunk) < FILE_CHUNK_BYTES:
                                    break
                        codecs = {chunk["codec"] for chunk in chunks}
                        codec = next(iter(codecs)) if len(codecs) == 1 else "mixed"
                        item_entry = {
                            "codec": codec,
                            "compression": item_policy,
                            "metadata": self._metadata(item),
                            "name": norm_name,
                            "size": offset,
                            "type": "file",
                            "chunks": chunks,
                        }
                        if len(chunks) == 1:
                            item_entry.update({
                                "plain_id": chunks[0]["plain_id"],
                                "wire_id": chunks[0]["wire_id"],
                                **(
                                    {}
                                    if "store" not in chunks[0]
                                    else {"store": chunks[0]["store"]}
                                ),
                            })
                        items.append(item_entry)
                    elif item.is_dir():
                        item_policy = effective_policy(item, source_dir, self.compression)
                        sub_pid, sub_wid, sub_sid, sub_codec = _walk(item, {})
                        item_entry = {
                            "codec": sub_codec,
                            "compression": item_policy,
                            "metadata": self._metadata(item),
                            "name": norm_name,
                            "plain_id": sub_pid,
                            "type": "dir",
                            "wire_id": sub_wid,
                        }
                        item_entry.update(_entry(sub_sid))
                        items.append(item_entry)
                items.sort(key=lambda e: e["name"])
                has_multichunk = any(
                    e.get("type") == "file" and len(e.get("chunks", [])) > 1
                    for e in items
                )
                dir_bytes = canonical_json(
                    {
                        "compression": dir_policy,
                        "entries": items,
                        "format": "dfs-dir-v2" if has_multichunk else "dfs-dir-v1",
                        "metadata": self._metadata(directory),
                    }
                )
                return _stage(dir_bytes, dir_policy)

            root = _walk(source_dir, delegated_mounts)
            self._last_wire_ids = set(all_wire_ids)
            for store_id in list(pending):
                _flush(store_id)
            return pending, reused, packed, root

        # ---- 1 回目の走査: 索引ヒットは「サーバに在る」と仮定して記録だけする ----
        pending, reused, packed, (root_pid, root_wid, root_sid, _root_codec) = _one_pass(force_new=set())

        # 第一走査で暗号化・送信した塊を索引へ仮登録する。後段で欠損が分かって
        # 再走査する場合も、同じ内容をランダム nonce で再暗号化せず再利用できる。
        for plain_id, (wire_id, store_id, codec) in packed.items():
            self.index[plain_id] = (wire_id, store_id, codec)

        # ---- 索引ヒットした塊の存在確認を 1 往復の一括 HAS にまとめる ----
        # ここが WAN 対応の要。チャンクごとに HAS を撃つ実装では往復がチャンク数に比例する。
        missing_plain: set = set()
        if reused:
            by_store: Dict[str, list] = {}
            for plain_id, (wire, store_id, _codec) in reused.items():
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
            pending, reused, packed, (root_pid, root_wid, root_sid, _root_codec) = _one_pass(force_new=missing_plain)

        # ---- 索引を確定してから送る ----
        # 索引ヒットした塊は既存の索引をそのまま維持し、今回暗号化した塊だけ貼り替える。
        for plain_id, (wire_id, store_id, codec) in packed.items():
            self.index[plain_id] = (wire_id, store_id, codec)

        # 根の配置先を呼び出し側が知れるよう、既定と異なるときは属性に残す
        self.root_store = root_sid
        self._replicate_chunks()
        try:
            self._save_index_file()
        except OSError as e:
            self.warnings.append(f"cannot persist OST index: {e}")
        return root_pid, root_wid

    def _replicate_chunks(self) -> None:
        """今回の版に含まれる塊を、読み取り用の複製 OST へコピーする。"""
        if not self.replicas or not self._last_wire_ids:
            return
        wire_ids = sorted(self._last_wire_ids)
        for replica in self.replicas:
            try:
                presence = replica.batch_has(wire_ids)
                missing = [wid for wid in wire_ids if not presence.get(wid, False)]
                for start in range(0, len(missing), 256):
                    group = missing[start : start + 256]
                    blobs = self.ost.batch_get(group)
                    replica.batch_put_if_absent(blobs, assume_absent=True)
            except Exception as e:  # noqa: BLE001 - 複製失敗で主の push を落とさない
                self.warnings.append(
                    f"replica {replica.host}:{replica.port} failed: {type(e).__name__}: {e}"
                )

    # ---- 読み込み ---------------------------------------------------------
    # 一括取得の分割。往復を減らすため件数の上限は大きめに取り、1 回の応答サイズは
    # バイト数の上限で抑える。ファイル塊の大きさはマニフェストの size から分かるので、
    # 先頭の組から正確に見積もれる（測ってから合わせる必要がない）。
    DEFAULT_BATCH_CHUNKS = 1024
    DEFAULT_BATCH_BYTES = 16 * 1024 * 1024
    # 大きさの分からない塊（ディレクトリ塊など）の見積り。小さめに倒して安全側に置く。
    UNKNOWN_CHUNK_ESTIMATE = 4096

    def _iter_fetch_groups(
        self, wanted: Sequence[Tuple[str, str, Optional[int]]]
    ):
        """取得対象を上限ごとに区切り、1 組ずつ結果を返す。

        呼び出し側が全結果を保持せず、ファイルへ順次書き出せるようにする。
        """
        by_store: Dict[str, Dict[str, Optional[int]]] = {}
        for store_id, wire_id, hint in wanted:
            prev = by_store.setdefault(store_id, {})
            # 同じ塊が複数回出たら、大きい方の見積りを採る（安全側）
            if wire_id not in prev or (hint or 0) > (prev[wire_id] or 0):
                prev[wire_id] = hint

        chunk_cap = _env_positive_int("DFS_BATCH_CHUNKS", self.DEFAULT_BATCH_CHUNKS)
        byte_cap = _dynamic_batch_bytes(self.DEFAULT_BATCH_BYTES)

        for store_id, id_to_hint in by_store.items():
            client = self._client(store_id)
            items = list(id_to_hint.items())
            i = 0
            while i < len(items):
                group: List[str] = []
                est = 0
                # 件数と見積りバイト数の両方の上限まで詰める。1 件だけの組は必ず許す。
                while i < len(items) and len(group) < chunk_cap:
                    wid, hint = items[i]
                    size = hint if hint is not None else self.UNKNOWN_CHUNK_ESTIMATE
                    if group and est + size > byte_cap:
                        break
                    group.append(wid)
                    est += size
                    i += 1
                yield client.batch_get(group)

    def _fetch_grouped(self, wanted: Sequence[Tuple[str, str, Optional[int]]]) -> Dict[str, bytes]:
        result: Dict[str, bytes] = {}
        for got in self._iter_fetch_groups(wanted):
            result.update(got)
        return result

    @staticmethod
    def _entry_chunks(entry: Dict[str, Any]) -> List[Dict[str, Any]]:
        """新旧マニフェストから、正規化した塊一覧を取り出す。"""
        raw = entry.get("chunks")
        if raw is None:
            return [
                {
                    "codec": entry.get("codec", "none"),
                    "offset": 0,
                    "plain_id": entry.get("plain_id", ""),
                    "size": entry.get("size"),
                    "store": entry.get("store", ""),
                    "wire_id": entry.get("wire_id", ""),
                }
            ]
        if not isinstance(raw, list) or not raw:
            raise ChunkIntegrityError("File entry has no chunks")
        result: List[Dict[str, Any]] = []
        cursor = 0
        for item in raw:
            if not isinstance(item, dict):
                raise ChunkIntegrityError("Invalid file chunk entry")
            try:
                offset = int(item.get("offset", 0))
                size = int(item["size"])
            except (KeyError, TypeError, ValueError) as exc:
                raise ChunkIntegrityError("Invalid file chunk size or offset") from exc
            if offset != cursor or size < 0:
                raise ChunkIntegrityError("File chunks must be contiguous")
            result.append(
                {
                    "codec": item.get("codec", "none"),
                    "offset": offset,
                    "plain_id": str(item.get("plain_id", "")),
                    "size": size,
                    "store": str(item.get("store", "")),
                    "wire_id": str(item.get("wire_id", "")),
                }
            )
            cursor += size
        if entry.get("size") is not None and int(entry["size"]) != cursor:
            raise ChunkIntegrityError("File chunk sizes do not match file size")
        return result

    @staticmethod
    def _apply_metadata(target: Path, metadata: Any) -> None:
        """版に記録された mode / 時刻 / 安全な xattr を best-effort で戻す。"""
        if not isinstance(metadata, dict):
            return
        mode = metadata.get("mode")
        if isinstance(mode, int) and 0 <= mode <= 0o7777:
            try:
                # リモート由来の setuid/setgid/sticky ビットは復元しない。
                os.chmod(target, mode & 0o777)
            except OSError:
                pass

        xattrs = metadata.get("xattrs")
        if isinstance(xattrs, dict):
            for name, encoded in list(xattrs.items())[:64]:
                if not isinstance(name, str) or not (
                    name.startswith("user.") or name.startswith("com.apple.")
                ):
                    continue
                if not isinstance(encoded, str):
                    continue
                try:
                    value = base64.b64decode(encoded, validate=True)
                except (ValueError, TypeError):
                    continue
                if len(value) <= 64 * 1024:
                    set_raw_xattr(target, name, value)

        mtime_ns = metadata.get("mtime_ns")
        if isinstance(mtime_ns, int) and mtime_ns >= 0:
            try:
                os.utime(target, ns=(target.stat().st_atime_ns, mtime_ns))
            except OSError:
                pass

    def download_directory(
        self,
        root_plain_id: str,
        root_wire_id: str,
        dest_dir: Path,
        root_store: Optional[str] = None,
    ) -> None:
        """(root_plain_id, root_wire_id) から再帰的に塊を取得・検証・復号して dest_dir に展開する。

        WAN 向けの往復回数:
          - ディレクトリ塊は幅優先で回り、**1 階層ぶんを 1 回の ``batch_get``** にまとめる。
          - ファイル塊は最後に store ごと・上限ごとに ``batch_get`` でまとめて取得する。
        したがって平らなディレクトリ（N ファイル）は 2 往復（根 1 + ファイル 1）で済む。
        塊ごとに ``get`` を撃つ実装では往復がファイル数に比例していた。
        """
        dest_dir.mkdir(parents=True, exist_ok=True)
        root_store_id = root_store or self.default_store

        # 1) ディレクトリ塊を幅優先で辿り、溜まったファイルが閾値に達するたびに順次取得・解放する。
        level: List[Tuple[str, str, str, Path]] = [
            (root_plain_id, root_wire_id, root_store_id, dest_dir)
        ]
        files: List[Dict[str, Any]] = []
        queued_chunks = 0
        queued_bytes = 0
        flush_chunk_cap = _env_positive_int("DFS_BATCH_CHUNKS", self.DEFAULT_BATCH_CHUNKS)
        flush_byte_cap = _dynamic_batch_bytes(self.DEFAULT_BATCH_BYTES)
        directory_metadata: List[Tuple[Path, Any]] = []

        def _flush_files() -> None:
            nonlocal queued_chunks, queued_bytes
            if not files:
                return
            wanted: List[Tuple[str, str, Optional[int]]] = []
            refs_by_wire: Dict[str, List[Tuple[Dict[str, Any], Dict[str, Any]]]] = {}
            written: Dict[Path, int] = {file_entry["target"]: 0 for file_entry in files}
            received_refs: set[Tuple[Path, int]] = set()
            for file_entry in files:
                target = file_entry["target"]
                target.parent.mkdir(parents=True, exist_ok=True)
                fd = _open_no_follow(target, os.O_RDWR | os.O_CREAT)
                with os.fdopen(fd, "r+b") as existing_fh:
                    existing_fh.seek(0, os.SEEK_END)
                    existing_len = existing_fh.tell()
                    if file_entry["size"] is not None and existing_len > int(file_entry["size"]):
                        existing_fh.truncate(int(file_entry["size"]))
                        existing_len = int(file_entry["size"])
                    for chunk in file_entry["chunks"]:
                        wire_id = chunk["wire_id"]
                        if not wire_id or not chunk["plain_id"]:
                            raise ChunkIntegrityError(f"Invalid chunk reference for {target.name}")
                        offset = int(chunk.get("offset", 0))
                        csize = chunk.get("size")
                        resumed = False
                        if csize is not None and offset + int(csize) <= existing_len:
                            existing_fh.seek(offset)
                            local_slice = existing_fh.read(int(csize))
                            if (
                                len(local_slice) == int(csize)
                                and self.crypto.compute_plain_id(local_slice).hex() == chunk["plain_id"]
                            ):
                                written[target] += len(local_slice)
                                received_refs.add((target, offset))
                                resumed = True
                        if not resumed:
                            wanted.append((chunk["store"] or self.default_store, wire_id, csize))
                            refs_by_wire.setdefault(wire_id, []).append((file_entry, chunk))
                    if file_entry["size"] is not None and existing_len < int(file_entry["size"]):
                        existing_fh.truncate(int(file_entry["size"]))

            for got in self._iter_fetch_groups(wanted):
                for wire_id, blob in got.items():
                    for file_entry, chunk in refs_by_wire.get(wire_id, []):
                        target = file_entry["target"]
                        data = self.crypto.unpack_chunk(
                            chunk["plain_id"], wire_id, blob
                        )
                        if chunk.get("size") is not None and len(data) != int(chunk["size"]):
                            raise ChunkIntegrityError(
                                f"File chunk size mismatch for {target.name}"
                            )
                        offset = int(chunk.get("offset", 0))
                        fd = _open_no_follow(target, os.O_RDWR)
                        with os.fdopen(fd, "r+b") as output:
                            output.seek(offset)
                            output.write(data)
                        written[target] += len(data)
                        received_refs.add((target, offset))

            for file_entry in files:
                target = file_entry["target"]
                missing = [
                    chunk for chunk in file_entry["chunks"]
                    if (target, int(chunk.get("offset", 0))) not in received_refs
                ]
                if missing:
                    raise ChunkIntegrityError(
                        f"Missing file chunk during download: {target.name}"
                    )
                expected_size = file_entry["size"]
                if expected_size is not None and written[target] != int(expected_size):
                    raise ChunkIntegrityError(f"File size mismatch for {target.name}")
                set_xattr(target, file_entry["compression"])
                self._apply_metadata(target, file_entry["metadata"])
            files.clear()
            queued_chunks = 0
            queued_bytes = 0

        depth = 0
        while level:
            depth += 1
            if depth > 10000:
                raise ChunkIntegrityError("Directory tree is too deep (possible cycle)")
            blobs = self._fetch_grouped([(sid, wid, None) for _pid, wid, sid, _ in level])
            next_level: List[Tuple[str, str, str, Path]] = []
            for plain_id, wire_id, _store_id, target in level:
                blob = blobs.get(wire_id)
                if blob is None:
                    raise ChunkIntegrityError(f"Missing directory chunk during download: {wire_id}")
                dir_bytes = self.crypto.unpack_chunk(plain_id, wire_id, blob)
                dir_obj = json.loads(dir_bytes.decode("utf-8"))
                if dir_obj.get("format") not in ("dfs-dir-v1", "dfs-dir-v2"):
                    raise ChunkIntegrityError("Invalid directory chunk format")

                # 各階層の対象ディレクトリは、塊を取る前に必ず用意する
                target.mkdir(parents=True, exist_ok=True)
                directory_metadata.append((target, dir_obj.get("metadata")))
                parent_policy = dir_obj.get("compression")
                if parent_policy:
                    set_xattr(target, parent_policy)
                seen_names: set[str] = set()
                seen_casefold: set[str] = set()
                for entry in dir_obj["entries"]:
                    if not isinstance(entry, dict):
                        raise ChunkIntegrityError("Invalid directory entry")
                    name = normalize_name(entry["name"])
                    if name in seen_names:
                        raise ChunkIntegrityError(f"Duplicate directory entry: {name!r}")
                    cf = name.casefold()
                    if cf in seen_casefold:
                        raise ChunkIntegrityError(
                            f"Case-colliding directory entry: {name!r}"
                        )
                    seen_names.add(name)
                    seen_casefold.add(cf)
                    child = target / name
                    if child.is_symlink():
                        raise UnsafePathError(f"Refusing to follow symlink: {child}")
                    etype = entry["type"]
                    entry_store = entry.get("store") or self.default_store

                    if etype == "file":
                        f_chunks = self._entry_chunks(entry)
                        files.append({
                            "chunks": f_chunks,
                            "compression": entry.get("compression", "none"),
                            "metadata": entry.get("metadata"),
                            "size": entry.get("size"),
                            "target": child,
                        })
                        queued_chunks += len(f_chunks)
                        queued_bytes += sum(
                            int(c.get("size") or self.UNKNOWN_CHUNK_ESTIMATE)
                            for c in f_chunks
                        )
                        if (
                            len(files) >= 512
                            or queued_chunks >= flush_chunk_cap
                            or queued_bytes >= flush_byte_cap
                        ):
                            _flush_files()
                    elif etype == "dir":
                        # 空のディレクトリも含めて、ここで実体を作る
                        child.mkdir(parents=True, exist_ok=True)
                        set_xattr(child, entry.get("compression", "none"))
                        directory_metadata.append((child, entry.get("metadata")))
                        next_level.append((entry["plain_id"], entry["wire_id"], entry_store, child))
                    elif etype == "delegated_mount":
                        child.mkdir(parents=True, exist_ok=True)
                        directory_metadata.append((child, entry.get("metadata")))
                    else:
                        raise ChunkIntegrityError(f"Unknown directory entry type: {etype!r}")
            level = next_level

        _flush_files()

        # 子の作成で親の時刻が変わるため、ディレクトリのメタデータは最後に戻す。
        for target, metadata in sorted(
            directory_metadata, key=lambda item: len(item[0].parts), reverse=True
        ):
            self._apply_metadata(target, metadata)


    # ---- 参照のみ（rclone ライク CLI 用） ---------------------------------
    def _dir_entries(self, plain_id: str, wire_id: str, store_id: str) -> list:
        """ディレクトリ塊を 1 つ取得して entries を返す（1 往復）。"""
        blob = self._client(store_id).get(wire_id)
        dir_bytes = self.crypto.unpack_chunk(plain_id, wire_id, blob)
        dir_obj = json.loads(dir_bytes.decode("utf-8"))
        if dir_obj.get("format") not in ("dfs-dir-v1", "dfs-dir-v2"):
            raise ChunkIntegrityError("Invalid directory chunk format")
        return dir_obj["entries"]

    def list_tree(
        self,
        root_plain_id: str,
        root_wire_id: str,
        root_store: Optional[str] = None,
        prefix: str = "",
    ) -> List[Dict[str, Any]]:
        """ツリーを走査して ``path`` 付きのエントリ一覧を返す（内容は取得しない）。

        取得は「1 階層 = 1 往復」。ファイルの中身は取らないので、``ls`` や ``find`` の
        ような一覧表示は構造の階層数だけで決まる。返り値の各要素は
        ``{"path", "type", "wire_id", "plain_id", "store", "size"?}``。
        """
        results: List[Dict[str, Any]] = []
        # (plain_id, wire_id, store_id, そのディレクトリのパス)
        queue: List[Tuple[str, str, str, str]] = [
            (root_plain_id, root_wire_id, root_store or self.default_store, prefix)
        ]
        seen: set = set()
        visited = 0
        while queue:
            plain_id, wire_id, store_id, base = queue.pop(0)
            key = (wire_id, base)
            if key in seen:
                continue
            seen.add(key)
            visited += 1
            if visited > 100000:
                raise ChunkIntegrityError("Directory tree is too large or cyclic")

            for entry in self._dir_entries(plain_id, wire_id, store_id):
                name = normalize_name(entry["name"])
                child = f"{base}/{name}" if base else name
                etype = entry["type"]
                child_store = entry.get("store") or self.default_store
                row = {
                    "path": child,
                    "type": etype,
                    "wire_id": entry.get("wire_id", ""),
                    "plain_id": entry.get("plain_id", ""),
                    "codec": entry.get("codec", "none"),
                    "compression": entry.get("compression", "none"),
                    "store": child_store,
                }
                if etype == "file":
                    chunks = self._entry_chunks(entry)
                    row["chunks"] = chunks
                    if len(chunks) == 1:
                        row["wire_id"] = chunks[0]["wire_id"]
                        row["plain_id"] = chunks[0]["plain_id"]
                    else:
                        row["wire_id"] = ""
                        row["plain_id"] = ""
                    row["store"] = chunks[0]["store"] or child_store
                    row["size"] = int(entry.get("size", 0))
                results.append(row)
                if etype == "dir":
                    queue.append((entry["plain_id"], entry["wire_id"], child_store, child))
        results.sort(key=lambda r: r["path"])
        return results

    def iter_remote_file(
        self,
        root_plain_id: str,
        root_wire_id: str,
        rel_path: str,
        root_store: Optional[str] = None,
        batch_chunks: Optional[int] = None,
    ) -> Iterator[bytes]:
        """``rel_path`` のファイルをチャンク単位で取得・検証して順次 yield する。"""
        parts = [p for p in rel_path.replace("\\", "/").split("/") if p not in ("", ".")]
        if not parts:
            raise IsADirectoryError(f"{rel_path!r} is a directory, not a file")
        plain_id, wire_id, store_id = root_plain_id, root_wire_id, root_store or self.default_store
        for i, part in enumerate(parts):
            want = normalize_name(part)
            entries = self._dir_entries(plain_id, wire_id, store_id)
            entry = None
            for e in entries:
                if normalize_name(e["name"]) == want:
                    entry = e
                    break
            if entry is None:
                raise FileNotFoundError(f"No such entry in the tree: {'/'.join(parts[: i + 1])}")
            last = i == len(parts) - 1
            if last:
                if entry["type"] != "file":
                    raise IsADirectoryError(f"{rel_path!r} is a directory, not a file")
                chunks = self._entry_chunks(entry)
                received = 0
                if batch_chunks is not None:
                    step = max(1, int(batch_chunks))
                    groups = [chunks[s : s + step] for s in range(0, len(chunks), step)]
                else:
                    chunk_cap = _env_positive_int("DFS_BATCH_CHUNKS", self.DEFAULT_BATCH_CHUNKS)
                    byte_cap = _dynamic_batch_bytes(self.DEFAULT_BATCH_BYTES)
                    groups = []
                    idx = 0
                    while idx < len(chunks):
                        group: List[Dict[str, Any]] = []
                        est = 0
                        while idx < len(chunks) and len(group) < chunk_cap:
                            c = chunks[idx]
                            csize = c.get("size")
                            size = int(csize) if csize is not None else self.UNKNOWN_CHUNK_ESTIMATE
                            if group and est + size > byte_cap:
                                break
                            group.append(c)
                            est += size
                            idx += 1
                        groups.append(group)
                for group in groups:
                    blobs = self._fetch_grouped(
                        [
                            (
                                chunk["store"] or self.default_store,
                                chunk["wire_id"],
                                chunk.get("size"),
                            )
                            for chunk in group
                        ]
                    )
                    for chunk in group:
                        blob = blobs.get(chunk["wire_id"])
                        if blob is None:
                            raise ChunkIntegrityError(
                                f"Missing file chunk: {chunk['wire_id']}"
                            )
                        part_bytes = self.crypto.unpack_chunk(
                            chunk["plain_id"], chunk["wire_id"], blob
                        )
                        if int(chunk.get("offset", 0)) != received:
                            raise ChunkIntegrityError("File chunks are not contiguous")
                        received += len(part_bytes)
                        yield part_bytes
                if received != int(entry.get("size", received)):
                    raise ChunkIntegrityError(f"File size mismatch for {rel_path}")
                return
            if entry["type"] != "dir":
                raise NotADirectoryError(f"{'/'.join(parts[: i + 1])!r} is not a directory")
            plain_id = entry["plain_id"]
            wire_id = entry["wire_id"]
            store_id = entry.get("store") or self.default_store
        raise FileNotFoundError(rel_path)

    def read_remote_file(
        self,
        root_plain_id: str,
        root_wire_id: str,
        rel_path: str,
        root_store: Optional[str] = None,
    ) -> bytes:
        """``rel_path`` のファイル 1 つだけを取得・検証して返す。

        空きメモリを超える巨大ファイルで OOM Kill されるのを防ぐため、
        空きメモリの 75% を超える場合は ``MemoryError`` を送出する
        （ストリーム読み込みには ``iter_remote_file`` を使用）。
        """
        avail = _get_available_memory_bytes()
        max_bytes = int(avail * 0.75) if (avail is not None and avail > 0) else None
        buf = bytearray()
        for chunk in self.iter_remote_file(
            root_plain_id, root_wire_id, rel_path, root_store=root_store
        ):
            if max_bytes is not None and len(buf) + len(chunk) > max_bytes:
                raise MemoryError(
                    f"read_remote_file: {rel_path!r} exceeds safe memory budget "
                    f"({max_bytes} bytes); use iter_remote_file() for streaming"
                )
            buf.extend(chunk)
        return bytes(buf)


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
        root_pubkey: Optional[str] = None,
        allow_tofu: bool = False,
    ):
        self.sub_path = normalize_path(sub_path)
        self.priv_key_path = Path(priv_key_path)
        self.pub_key_str = pub_key_str.strip()
        self.pin_file = pin_file
        self.pin = HeadPin.load(pin_file) if pin_file else HeadPin()
        # 直近に検証したロケータ。読み取り時の OST endpoint フォールバックに使う。
        self.last_locator: Optional[Dict[str, Any]] = None
        self.last_delegation: Optional[Dict[str, Any]] = None
        # root アンカーの公開鍵。ここが信頼の根（名簿からは取らない）。
        self.root_pubkey: Optional[str] = (root_pubkey or "").strip() or None
        self.allow_tofu: bool = bool(allow_tofu)

    def _save_pin(self) -> None:
        if self.pin_file:
            self.pin.save(self.pin_file)

    def _verified_writer(self, del_env: Optional[Dict[str, Any]]) -> str:
        """末端の委譲が root まで連鎖することを検証し、確定した writer を返す。

        ``del_env`` には名簿が ``chain``（root 直下から末端まで）と ``root_anchor`` を
        足して返す。root アンカー公開鍵は**手元の記録**（リモート定義）を使う。名簿が
        返した値は使わない（相手から信頼の根を取ると、偽の root を作られて通る）。

        root 公開鍵が未設定（TOFU 前）のときは、chain が 1 段でも root を名乗る場合は
        検証できないため、名簿の主張をそのまま使う（互換のため）。設定済みなら必ず検証する。
        """
        if del_env is None:
            if self.root_pubkey:
                raise DelegationError(f"Missing delegation for {self.sub_path!r}")
            if not self.allow_tofu:
                raise DelegationError(
                    f"root_pubkey is not configured for {self.sub_path!r} (allow_tofu=False)"
                )
            # TOFU 明示時のみ、未登録の間は自分の鍵で検証する。
            return self.pub_key_str

        chain = del_env.get("chain") or []
        if not chain:
            # 名簿がチェーンを返さない（古い名簿）ときは、末端 1 つで検証を試みる。
            chain = [del_env]
        root_anchor = del_env.get("root_anchor") or "/"

        if self.root_pubkey:
            leaf = verify_delegation_chain(
                root_anchor_path=root_anchor,
                root_anchor_pubkey=self.root_pubkey,
                chain=chain,
                now=int(time.time()),
                requested_path=self.sub_path,
            )
            return str(leaf["writer"])

        if not self.allow_tofu:
            raise DelegationError(
                f"root_pubkey is not configured for {self.sub_path!r}; refusing unverified registry writer"
            )
        # TOFU 明示時のみ: 検証できないので名簿の主張を使う（初回のみ通る経路）。
        return str(del_env.get("payload", {}).get("writer") or self.pub_key_str)

    def sync_head(
        self,
        registry: DirectoryRegistryService,
        expected_writer_pubkey: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        L2/L4 から先頭版を取得し、署名検証および B6（巻き戻し・フォーク）チェックを行ってローカルピンを更新する。
        """
        del_env, loc_env, head_env = registry.resolve(self.sub_path)
        self.last_delegation = del_env
        self.last_locator = loc_env
        if head_env is None:
            if self.pin.version > 0:
                raise RollbackDetectedError(
                    f"B6 Rollback detected: remote log is empty, but local pin is at v{self.pin.version}"
                )
            return None

        p = head_env["payload"]
        try:
            head_path = normalize_path(p["path"])
        except (KeyError, TypeError, ValueError) as e:
            raise ChunkIntegrityError(f"Remote head has invalid path: {e}") from e
        if head_path != self.sub_path:
            raise ChunkIntegrityError(
                f"Remote head path mismatch: expected {self.sub_path!r}, got {head_path!r}"
            )
        raw_p = canonical_json(p)
        if sha256_hex(raw_p) != head_env.get("entry_hash"):
            raise ChunkIntegrityError("Remote head entry_hash corrupted")

        # 名簿を信頼しない: 末端の委譲が root まで連鎖することを、手元の root 公開鍵で
        # 検証する。署名を検証する鍵は「名簿が名乗った writer」ではなく、この検証で
        # 確定した writer でなければならない（さもないと偽の委譲が通る）。
        writer_pub = expected_writer_pubkey
        if writer_pub is None:
            writer_pub = self._verified_writer(del_env)

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

        # L2 ロケータは読み取り先 OST の一覧を運ぶ。署名・期限・head との一致を
        # ここで確認しないと、期限切れの endpoint を使い続けてしまう。
        if loc_env is not None:
            loc_p = verify_locator_envelope(
                loc_env, self.sub_path, writer_pub, int(time.time())
            )
            if (
                int(loc_p.get("head_version", -1)) != int(p["version"])
                or loc_p.get("head_hash") != head_env["entry_hash"]
            ):
                raise ChunkIntegrityError("Locator does not match the current head")
            if int(loc_p.get("delegation_epoch", -1)) != int(p["delegation_epoch"]):
                raise ChunkIntegrityError("Locator delegation_epoch does not match the head")

        self.pin = HeadPin(
            version=p["version"],
            entry_hash=head_env["entry_hash"],
            delegation_epoch=p["delegation_epoch"],
        )
        self._save_pin()
        cache_verified = getattr(registry, "cache_verified", None)
        if callable(cache_verified):
            cache_verified(
                self.sub_path,
                del_env,
                loc_env,
                head_env,
                now=int(time.time()),
            )
        return head_env

    def resolve_verified(
        self,
        registry: DirectoryRegistryService,
        version: Optional[int] = None,
    ) -> Tuple[Dict[str, Any], Dict[str, Any], Optional[Dict[str, Any]]]:
        """版を指定して、root アンカーから検証済みの head を返す。

        通常の ``sync_head`` と違い、B6 のローカルピンは更新しない。過去版の
        archive 作成や履歴参照で使う。
        """
        del_env, loc_env, head_env = registry.resolve(self.sub_path, version=version)
        if head_env is None:
            raise DelegationError(f"No version available for {self.sub_path!r}")
        p = head_env.get("payload", {})
        try:
            head_path = normalize_path(p["path"])
        except (KeyError, TypeError, ValueError) as e:
            raise ChunkIntegrityError(f"Head has invalid path: {e}") from e
        if head_path != self.sub_path:
            raise ChunkIntegrityError(
                f"Head path mismatch: expected {self.sub_path!r}, got {head_path!r}"
            )
        if not self.root_pubkey:
            raise DelegationError("root_pubkey is required to verify a historical head")
        chain = (del_env or {}).get("chain") or []
        if not chain:
            raise DelegationError("Delegation chain is missing")
        try:
            verified_at = int(p["timestamp"])
        except (KeyError, TypeError, ValueError) as e:
            raise ChunkIntegrityError(f"Head has invalid timestamp: {e}") from e
        leaf = verify_delegation_chain(
            root_anchor_path=(del_env or {}).get("root_anchor") or "/",
            root_anchor_pubkey=self.root_pubkey,
            chain=chain,
            now=verified_at,
            requested_path=self.sub_path,
        )
        raw = canonical_json(p)
        if sha256_hex(raw) != head_env.get("entry_hash"):
            raise ChunkIntegrityError("Head entry_hash mismatch")
        if not ssh_verify(
            leaf["writer"], self.sub_path, NS_L4_LOG, raw, head_env.get("signature", "")
        ):
            raise ChunkIntegrityError("Head signature verification failed")
        if loc_env is not None:
            loc_p = verify_locator_envelope(
                loc_env, self.sub_path, leaf["writer"], verified_at
            )
            if (
                int(loc_p["head_version"]) != int(p["version"])
                or loc_p["head_hash"] != head_env["entry_hash"]
            ):
                raise ChunkIntegrityError("Locator does not match historical head")
        self.last_delegation = del_env
        self.last_locator = loc_env
        return head_env, del_env, loc_env

    def history(self, registry: DirectoryRegistryService, limit: int = 50) -> List[Dict[str, Any]]:
        return registry.history(self.sub_path, limit=limit)

    def commit(
        self,
        registry: DirectoryRegistryService,
        root_plain_id: str,
        root_wire_id: str,
        delegation_epoch: int,
        ost_endpoint: str | Sequence[str],
        now: int,
        role_epoch: int = 1,
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
            endpoints=[ost_endpoint] if isinstance(ost_endpoint, str) else list(ost_endpoint),
            expires_at=now + 86400,
        )

        # 1. CAS 追記要求
        registry.announce_and_append(
            self.sub_path, log_env, loc_env, now=now, role_epoch=role_epoch
        )

        # 2. B7 防御: Read-after-Write 照合（一致が確認できるまでローカルピンは進めない）
        readback_del, _readback_loc, readback = registry.resolve(self.sub_path)
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
        cache_verified = getattr(registry, "cache_verified", None)
        if callable(cache_verified):
            cache_verified(
                self.sub_path,
                readback_del or self.last_delegation,
                loc_env,
                log_env,
                now=now,
            )
        return log_env
