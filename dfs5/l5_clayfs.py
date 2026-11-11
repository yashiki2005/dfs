#!/usr/bin/env python3
"""
dfs5/l5_clayfs.py
L5 (clayfs ローカル実体化 & スナップショット連携) アダプタ。
"""

from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path
from typing import Dict, Optional, Tuple

from .crypto import ContentAddressedCrypto
from .l2_registry import DirectoryRegistryService
from .l3_ost_adapter import OSTClient
from .l4_log import L4LogClient, MerkleTreeBuilder


class ClayFSAdapter:
    def __init__(self, mount_root: Path | str):
        self.mount_root = Path(mount_root).resolve()
        self.work_tree = self.mount_root / "tree"
        self.clayfs_meta = self.mount_root / ".clayfs"
        self.snap_root = self.clayfs_meta / "snapshots"
        self.work_tree.mkdir(parents=True, exist_ok=True)
        self.snap_root.mkdir(parents=True, exist_ok=True)

    def take_snapshot(self, snap_id: str) -> Path:
        dest = self.snap_root / snap_id
        if dest.exists():
            shutil.rmtree(dest)
        shutil.copytree(
            self.work_tree,
            dest,
            ignore=shutil.ignore_patterns(".clayfs", ".DS_Store", "._*"),
            copy_function=os.link,
        )
        if (dest / ".clayfs").exists():
            raise RuntimeError("Invariant violation: .clayfs directory leaked into snapshot")
        return dest

    def replace_work_tree(self, source_dir: Path) -> None:
        if self.work_tree.exists():
            shutil.rmtree(self.work_tree)
        shutil.copytree(
            source_dir,
            self.work_tree,
            ignore=shutil.ignore_patterns(".clayfs", ".DS_Store", "._*"),
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
    ):
        self.name = name
        self.sub_path = sub_path
        self.clayfs = ClayFSAdapter(mount_root)
        self.crypto = ContentAddressedCrypto(tree_secret)
        self.ost = OSTClient(host=ost_host, port=ost_port)
        self.builder = MerkleTreeBuilder(self.crypto, self.ost)
        self.registry = registry
        pin_file = self.clayfs.clayfs_meta / "local_head.json"
        self.l4 = L4LogClient(sub_path, priv_key_path, pub_key_str, pin_file=pin_file)

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