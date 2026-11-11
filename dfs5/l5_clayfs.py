#!/usr/bin/env python3
"""
dfs5/l5_clayfs.py
L5 (clayfs ローカル実体化 & スナップショット連携) アダプタ。
"""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .crypto import ContentAddressedCrypto
from .l2_registry import DirectoryRegistryService
from .l3_ost_adapter import OSTClient
from .fs import FileSystem
from .l4_log import L4LogClient, MerkleTreeBuilder


class ClayFSAdapter:
    """作業ツリーのスナップショット入出力。

    実体のコピーは ``dfs5.fs.FileSystem`` に委譲する。CoW (clonefile / FICLONE /
    block clone) が使える環境ではそれを自動で使い、無い環境では実コピーに落ちる。
    どちらでもスナップショットは作業ツリーから独立した inode になる。
    """

    def __init__(self, mount_root: Path | str, backend: str = "auto"):
        self.mount_root = Path(mount_root).resolve()
        self.work_tree = self.mount_root / "tree"
        self.clayfs_meta = self.mount_root / ".clayfs"
        self.snap_root = self.clayfs_meta / "snapshots"
        self.work_tree.mkdir(parents=True, exist_ok=True)
        self.snap_root.mkdir(parents=True, exist_ok=True)
        self.fs = FileSystem(
            self.mount_root,
            backend=backend,
            work_tree=self.work_tree,
            snap_root=self.snap_root,
        )

    @property
    def backend(self):
        return self.fs.backend.name

    @property
    def is_cow(self) -> bool:
        return self.fs.is_cow

    def take_snapshot(self, snap_id: str) -> Path:
        return self.fs.take_snapshot(snap_id).path

    def replace_work_tree(self, source_dir: Path) -> None:
        source_dir = Path(source_dir)
        if self.work_tree.exists() or self.work_tree.is_symlink():
            if self.work_tree.is_symlink() or self.work_tree.is_file():
                self.work_tree.unlink()
            else:
                shutil.rmtree(self.work_tree)
        shutil.copytree(
            source_dir,
            self.work_tree,
            ignore=shutil.ignore_patterns(".clayfs", ".DS_Store", "._*"),
            symlinks=True,
        )


class DFS5Node:
    def __init__(
        self,
        name: str,
        sub_path: str,
        mount_root: Path | str,
        priv_key_path: Path | str,
        pub_key_str: str,
        tree_secret: bytes | str,
        registry: DirectoryRegistryService,
        ost_host: str,
        ost_port: int,
        root_pubkey: Optional[str] = None,
    ):
        self.name = name
        self.sub_path = sub_path
        self.clayfs = ClayFSAdapter(mount_root)
        self.crypto = ContentAddressedCrypto(tree_secret)
        self.ost = OSTClient(host=ost_host, port=ost_port)
        self.builder = MerkleTreeBuilder(self.crypto, self.ost)
        self.registry = registry
        pin_file = self.clayfs.clayfs_meta / "local_head.json"
        self.l4 = L4LogClient(
            sub_path, priv_key_path, pub_key_str,
            pin_file=pin_file, root_pubkey=root_pubkey,
        )

    def switch_credentials(self, new_priv_key: Path | str, new_pub_key_str: str) -> None:
        self.l4.priv_key_path = Path(new_priv_key)
        self.l4.pub_key_str = new_pub_key_str.strip()

    def push(
        self,
        delegation_epoch: int,
        now: int,
        delegated_mounts: Optional[Dict[str, str]] = None,
    ) -> Tuple[dict, Path, int]:
        self.ost.reset_metrics()
        next_ver = self.l4.pin.version + 1
        snap_dir = self.clayfs.take_snapshot(f"v{next_ver}")

        with self.ost.session():
            root_pid, root_wid = self.builder.upload_directory(snap_dir, delegated_mounts=delegated_mounts)

        log_env = self.l4.commit(
            registry=self.registry,
            root_plain_id=root_pid,
            root_wire_id=root_wid,
            delegation_epoch=delegation_epoch,
            ost_endpoint=f"tls://{self.ost.host}:{self.ost.port}",
            now=now,
        )
        wire_bytes = self.ost.bytes_sent
        return log_env, snap_dir, wire_bytes

    def pull(self, expected_writer_pubkey: Optional[str] = None) -> Path:
        self.ost.reset_metrics()
        head_env = self.l4.sync_head(self.registry, expected_writer_pubkey=expected_writer_pubkey)
        if head_env is None:
            raise RuntimeError(f"No versions available on registry for {self.sub_path}")

        p = head_env["payload"]
        with tempfile.TemporaryDirectory(prefix="dfs5_stage_") as staging:
            staging_dir = Path(staging)
            with self.ost.session():
                self.builder.download_directory(p["root_plain_id"], p["root_wire_id"], staging_dir)
            self.clayfs.replace_work_tree(staging_dir)

        return self.clayfs.take_snapshot(f"v{p['version']}")

    # ---- 参照のみ（rclone ライク CLI 用） ---------------------------------
    def _head_root(self, expected_writer_pubkey: Optional[str] = None) -> Tuple[str, str, Optional[str], int]:
        """先頭版の root 3 つ組と版番号を返す。ピン（local_head.json）も更新する。

        リモートにまだ版が無ければ root を空文字で返す（呼び出し側が「空」を判断する）。
        """
        head_env = self.l4.sync_head(self.registry, expected_writer_pubkey=expected_writer_pubkey)
        if head_env is None:
            return "", "", getattr(self, "root_store", None), 0
        p = head_env["payload"]
        return p["root_plain_id"], p["root_wire_id"], getattr(self, "root_store", None), int(p["version"])

    def list_remote(self, prefix: str = "") -> List[Dict[str, Any]]:
        """リモートのツリーを一覧する（内容は取らない）。1 階層 = 1 往復。

        リモートにまだ版が無ければ空の一覧を返す（最初の push の前でも一覧できる）。
        """
        self.ost.reset_metrics()
        head = self.l4.sync_head(self.registry)
        if head is None:
            return []
        p = head["payload"]
        root_store = getattr(self, "root_store", None)
        with self.ost.session():
            return self.builder.list_tree(
                p["root_plain_id"], p["root_wire_id"], root_store=root_store, prefix=prefix
            )

    def read_remote(self, rel_path: str) -> bytes:
        """リモートの 1 ファイルだけを取得する（ツリー全体は落とさない）。"""
        self.ost.reset_metrics()
        root_pid, root_wid, root_store, ver = self._head_root()
        if ver == 0 or not root_wid:
            raise FileNotFoundError(f"Remote has no versions yet: {rel_path}")
        with self.ost.session():
            return self.builder.read_remote_file(root_pid, root_wid, rel_path, root_store=root_store)

    def remote_version(self) -> int:
        """リモート先頭版の版番号（取得は 1 往復、内容は取らない）。"""
        return self._head_root()[3]

    def local_files(self, root: Optional[Path] = None) -> Dict[str, dict]:
        """作業ツリー配下のファイルとディレクトリを、相対パス -> 情報の辞書で返す。"""
        base = Path(root) if root is not None else self.clayfs.work_tree
        out: Dict[str, dict] = {}
        if not base.exists():
            return out
        base = base.resolve()
        for item in sorted(base.rglob("*")):
            rel = item.relative_to(base).as_posix()
            if any(part == ".clayfs" for part in Path(rel).parts):
                continue
            if item.name in (".DS_Store",) or item.name.startswith("._"):
                continue
            if item.is_dir():
                out[rel] = {"type": "dir", "size": 0}
            elif item.is_file():
                st = item.stat()
                out[rel] = {
                    "type": "file",
                    "size": st.st_size,
                    "mtime": st.st_mtime,
                }
        return out

    def write_files(self, items: Dict[str, bytes], now: int, epoch: Optional[int] = None) -> Tuple[dict, Path, int]:
        """作業ツリーにファイルを書いて push する（親ディレクトリは自動作成）。

        ``items`` は作業ツリーからの相対パス -> 中身。``remote copyto`` / ``sync`` の
        取り込み側で使う。push の前後で内容アドレス索引が効くため、変更のない塊は送らない。
        """
        work_tree = self.clayfs.work_tree
        for rel, data in items.items():
            rel = str(rel).replace("\\", "/").lstrip("/")
            if any(part in ("", ".", "..") for part in rel.split("/")):
                raise ValueError(f"Invalid relative path for write: {rel!r}")
            target = work_tree / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        delegation_epoch = int(epoch) if epoch is not None else int(self.l4.pin.delegation_epoch or 1)
        return self.push(delegation_epoch=delegation_epoch, now=now)