#!/usr/bin/env python3
"""
dfs/l5_fs.py
L5 (ローカル実体化 & スナップショット連携) アダプタ。
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import threading
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

from .crypto import KDF_DEFAULT, ContentAddressedCrypto
from .l2_registry import DirectoryRegistryService, ServiceUnavailableError
from .l3_ost_adapter import (
    FailoverOSTClient,
    OSTClientProtocol,
    SwarmOSTClient,
    make_ost_client,
    parse_ost_endpoint,
)
from .fs import FileSystem
from .fs.core import remove_tree
from .l4_log import L4LogClient, MerkleTreeBuilder
from .path_safety import safe_target, write_bytes_no_follow


_ACTIVE_NODES: "set[DFSNode]" = set()
_ACTIVE_NODES_LOCK = threading.Lock()


class _LocalChunkCache:
    """pull 時に取得したチャンクをローカルディレクトリへ保存し、P2P シードとして配信する。"""

    def __init__(self, root: Path) -> None:
        self.root = Path(root)

    def _path_for(self, wire_id: str) -> Optional[Path]:
        if len(wire_id) != 64 or any(c not in "0123456789abcdefABCDEF" for c in wire_id):
            return None
        return self.root / f"{wire_id.lower()}.blk"

    def has_chunk(self, wire_id: str) -> bool:
        p = self._path_for(wire_id)
        return p is not None and p.is_file()

    def get_chunk(self, wire_id: str) -> bytes:
        p = self._path_for(wire_id)
        if p is None or not p.is_file():
            return b""
        return p.read_bytes()

    def put_chunk(self, wire_id: str, data: bytes) -> None:
        p = self._path_for(wire_id)
        if p is None or not data:
            return
        self.root.mkdir(parents=True, exist_ok=True)
        if not p.exists():
            fd, tmp_name = tempfile.mkstemp(prefix=".blk_", suffix=".tmp", dir=str(self.root))
            tmp = Path(tmp_name)
            try:
                try:
                    f = os.fdopen(fd, "wb")
                except Exception:
                    os.close(fd)
                    raise
                with f:
                    f.write(data)
                os.replace(tmp, p)
            finally:
                try:
                    tmp.unlink()
                except FileNotFoundError:
                    pass


class _CachingOSTProxy:
    """pull 時に取得したチャンクをローカルの P2P シード用キャッシュへ記録する薄いプロキシ。"""

    def __init__(self, inner: Any, cache_store: _LocalChunkCache) -> None:
        self._inner = inner
        self._cache = cache_store

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)

    def get_chunk(self, wire_id: str) -> bytes:
        data = self._inner.get_chunk(wire_id)
        if data:
            self._cache.put_chunk(wire_id, data)
        return data

    def batch_get(self, wire_ids: List[str]) -> Dict[str, bytes]:
        res = self._inner.batch_get(wire_ids)
        for wid, data in res.items():
            if data:
                self._cache.put_chunk(wid, data)
        return res


class ClayFSAdapter:
    """作業ツリーのスナップショット入出力。

    実体のコピーは ``dfs.fs.FileSystem`` に委譲する。CoW (clonefile / FICLONE /
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

    def snapshot_result(self, snap_id: str):
        """``SnapshotResult`` ごと返す（skipped / warnings を呼び出し側で見るため）。"""
        return self.fs.take_snapshot(snap_id)

    def prune_snapshots(self, keep: int = 3) -> int:
        """古いスナップショットを削除し、新しい方から ``keep`` 件だけ残す。"""
        if keep <= 0 or not self.snap_root.is_dir():
            return 0
        snaps = [p for p in self.snap_root.iterdir() if p.is_dir()]
        if len(snaps) <= keep:
            return 0
        def _sort_key(p: Path) -> Tuple[int, float, str]:
            name = p.name
            ver = int(name[1:]) if name.startswith("v") and name[1:].isdigit() else -1
            try:
                mtime = p.stat().st_mtime
            except OSError:
                mtime = 0.0
            return (ver, mtime, name)

        snaps.sort(key=_sort_key, reverse=True)
        removed = 0
        for old in snaps[keep:]:
            try:
                remove_tree(old)
                removed += 1
            except OSError:
                pass
        return removed

    def _auto_prune_snapshots(self) -> None:
        env_keep = os.environ.get("DFS_MAX_SNAPSHOTS", "").strip()
        if env_keep:
            keep = int(env_keep)
        elif not self.is_cow:
            keep = int(os.environ.get("DFS_MAX_SNAPSHOTS_NON_COW", "3") or "3")
        else:
            return
        if keep > 0:
            self.prune_snapshots(keep=keep)

    def replace_work_tree(self, source_dir: Path) -> None:
        source_dir = Path(source_dir)
        if self.work_tree.exists() or self.work_tree.is_symlink():
            if self.work_tree.is_symlink() or self.work_tree.is_file():
                self.work_tree.unlink()
            else:
                remove_tree(self.work_tree)
        shutil.copytree(
            source_dir,
            self.work_tree,
            ignore=shutil.ignore_patterns(".clayfs", ".DS_Store", "._*"),
            symlinks=True,
        )


class DFSNode:
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
        ost_alternates: Optional[List[str]] = None,
        libp2p_peers: Optional[List[str]] = None,
        libp2p_psk: Optional[str] = None,
        role_epoch: int = 1,
        compression: str = "auto",
        ost_endpoint: Optional[str] = None,
        ost_cert_sha256: Optional[str] = None,
        allow_tofu: bool = False,
        kdf_version: str = KDF_DEFAULT,
    ):
        self.name = name
        self.sub_path = sub_path
        self.clayfs = ClayFSAdapter(mount_root)
        self.crypto = ContentAddressedCrypto(
            tree_secret,
            kdf_version=kdf_version,
        )
        self.ost_cert_sha256: Optional[str] = (ost_cert_sha256 or "").strip().lower() or None
        if ost_endpoint:
            primary_canonical = self._normalize_ost_endpoint(ost_endpoint)
        else:
            primary_canonical = self._format_ost_endpoint(str(ost_host), int(ost_port))
        raw_endpoints = [primary_canonical] + [
            self._normalize_ost_endpoint(value) for value in (ost_alternates or [])
        ]
        for reg_u in (getattr(registry, "registry_urls", None) or ()):
            if "/relay/" in str(reg_u):
                raw_endpoints.append(self._normalize_ost_endpoint(str(reg_u)))
        seen = set()
        self.ost_endpoints: List[str] = []
        ost_clients: List[OSTClientProtocol] = []
        for idx, canonical in enumerate(raw_endpoints):
            if canonical in seen:
                continue
            seen.add(canonical)
            pin = self.ost_cert_sha256 if (idx == 0 and not canonical.startswith("http://")) else None
            ost_clients.append(
                make_ost_client(
                    canonical,
                    expected_cert_sha256=pin,
                    writer_priv_key=priv_key_path,
                    writer_pubkey=pub_key_str,
                    writer_path=sub_path,
                )
            )  # type: OSTClientProtocol
            self.ost_endpoints.append(canonical)
        relay_write_fallbacks: List[OSTClientProtocol] = [
            c
            for c, ep in zip(ost_clients[1:], self.ost_endpoints[1:])
            if "/relay/" in ep
        ]
        self.replica_osts: List[OSTClientProtocol] = [
            c
            for c, ep in zip(ost_clients[1:], self.ost_endpoints[1:])
            if "/relay/" not in ep
        ]
        transport_cache = self.clayfs.clayfs_meta / "transport_cache.json"
        self.ost = (
            FailoverOSTClient(
                [ost_clients[0], *relay_write_fallbacks],
                allow_write_failover=True,
                cache_file=transport_cache,
            )
            if relay_write_fallbacks
            else ost_clients[0]
        )
        self.builder = MerkleTreeBuilder(
            self.crypto,
            self.ost,
            replicas=self.replica_osts,
            index_file=self.clayfs.clayfs_meta / "ost_index.json",
            compression=compression,
        )
        self.libp2p_manager = None
        self.libp2p_client = None
        self.p2p_chunk_store: Optional[_LocalChunkCache] = None
        self.libp2p_psk = libp2p_psk or None
        registry_urls = getattr(registry, "registry_urls", None)
        want_p2p = bool(libp2p_peers) or (
            bool(registry_urls) and os.environ.get("DFS_LIBP2P", "1").strip() != "0"
        )
        if want_p2p:
            try:
                from .libp2p_chunk import (
                    Libp2pChunkClient,
                    Libp2pHostManager,
                    is_libp2p_available,
                )

                if is_libp2p_available():
                    self.p2p_chunk_store = _LocalChunkCache(self.clayfs.clayfs_meta / "p2p_chunks")
                    self.libp2p_manager = Libp2pHostManager(
                        store=self.p2p_chunk_store,
                        psk=self.libp2p_psk,
                        enable_dht=True,
                        dht_mode="client",
                        enable_relay=True,
                        relay_hop=False,
                        enable_dcutr=True,
                    )
                    if libp2p_peers:
                        self.libp2p_client = Libp2pChunkClient(
                            libp2p_peers,
                            psk=self.libp2p_psk,
                            manager=self.libp2p_manager,
                        )
                elif libp2p_peers:
                    self.libp2p_client = Libp2pChunkClient(libp2p_peers, psk=self.libp2p_psk)
            except (ImportError, ServiceUnavailableError) as e:  # pragma: no cover - 依存環境
                import warnings

                warnings.warn(
                    f"libp2p unavailable ({e}); continuing over TLS/HTTP/Relay",
                    RuntimeWarning,
                    stacklevel=2,
                )
                self.libp2p_manager = None
                self.libp2p_client = None
        read_clients: List[OSTClientProtocol] = list(ost_clients)
        if self.libp2p_client is not None:
            read_clients.append(self.libp2p_client)
        self.read_ost = SwarmOSTClient(read_clients, cache_file=transport_cache)  # type: ignore
        self.read_builder = MerkleTreeBuilder(self.crypto, self.read_ost)
        self.registry = registry
        self.role_epoch = int(role_epoch)
        self.compression = str(compression or "auto")
        pin_file = self.clayfs.clayfs_meta / "local_head.json"
        self.l4 = L4LogClient(
            sub_path, priv_key_path, pub_key_str,
            pin_file=pin_file, root_pubkey=root_pubkey,
            allow_tofu=bool(allow_tofu),
        )
        self._closed = False
        with _ACTIVE_NODES_LOCK:
            _ACTIVE_NODES.add(self)

    def switch_credentials(self, new_priv_key: Path | str, new_pub_key_str: str) -> None:
        self.l4.priv_key_path = Path(new_priv_key)
        self.l4.pub_key_str = new_pub_key_str.strip()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            try:
                try:
                    if self.libp2p_client is not None:
                        self.libp2p_client.close()
                finally:
                    if self.libp2p_manager is not None:
                        self.libp2p_manager.close()
            finally:
                # SQLite索引はlibp2p側のclose失敗に巻き込まれず必ず閉じる。
                self.builder.close()
                self.read_builder.close()
        finally:
            with _ACTIVE_NODES_LOCK:
                _ACTIVE_NODES.discard(self)

    @classmethod
    def close_all(cls) -> None:
        """プロセス内で開いた全ノードを、CLI終了時などに確実に閉じる。"""
        with _ACTIVE_NODES_LOCK:
            nodes = list(_ACTIVE_NODES)
        for node in nodes:
            try:
                node.close()
            except Exception:
                pass

    @staticmethod
    def _parse_ost_endpoint(value: str) -> Tuple[str, int]:
        host, port, _canonical = parse_ost_endpoint(value)
        return host, port

    @staticmethod
    def _normalize_ost_endpoint(value: str) -> str:
        _host, _port, canonical = parse_ost_endpoint(value)
        return canonical

    @staticmethod
    def _format_ost_endpoint(host: str, port: int) -> str:
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        return f"tls://{host}:{int(port)}"

    def refresh_read_ost(self) -> None:
        """検証済みロケータの endpoints を優先して、読み取り用 OST を組み直す。"""
        endpoints = list(self.ost_endpoints)
        locator = self.l4.last_locator
        if locator:
            for value in (locator.get("payload", {}).get("endpoints") or []):
                try:
                    endpoint = self._normalize_ost_endpoint(value)
                except ValueError:
                    continue
                if endpoint not in endpoints:
                    endpoints.append(endpoint)
        clients: List[Any] = []
        seen = set()
        for endpoint in endpoints:
            try:
                canonical = self._normalize_ost_endpoint(endpoint)
            except ValueError:
                continue
            if canonical in seen:
                continue
            seen.add(canonical)
            pin = (
                self.ost_cert_sha256
                if (
                    self.ost_cert_sha256
                    and self.ost_endpoints
                    and canonical == self.ost_endpoints[0]
                    and not canonical.startswith("http://")
                )
                else None
            )
            clients.append(make_ost_client(canonical, expected_cert_sha256=pin))
        if self.libp2p_client is not None:
            clients.append(self.libp2p_client)
        self.read_ost = SwarmOSTClient(
            clients,
            cache_file=self.clayfs.clayfs_meta / "transport_cache.json",
        )
        registry_urls = getattr(self.registry, "registry_urls", None)
        if registry_urls and os.environ.get("DFS_ICE_DISCOVER", "1").strip() != "0":
            self.read_ost.discover_from_ice(registry_urls, timeout=0.5)
        if (
            self.libp2p_manager is not None
            and registry_urls
            and os.environ.get("DFS_LIBP2P", "1").strip() != "0"
        ):
            try:
                self.libp2p_manager.start(timeout=5.0)
                from .relay import fetch_p2p_peers, register_p2p_peer

                domain_key = getattr(self.l4, "root_pubkey", None) or self.sub_path or "default"
                pre_info = fetch_p2p_peers(registry_urls[0], timeout=1.0)
                pre_peers = pre_info.get("peers") or []
                if pre_peers and hasattr(self.libp2p_manager, "bootstrap_from_peers"):
                    self.libp2p_manager.bootstrap_from_peers(pre_peers, timeout=1.5)
                advertised_addrs = (
                    self.libp2p_manager.effective_addrs()
                    if hasattr(self.libp2p_manager, "effective_addrs")
                    else list(self.libp2p_manager.addrs)
                )
                p2p_info = register_p2p_peer(
                    registry_urls[0],
                    self.libp2p_manager.peer_id,
                    node_id=self.name,
                    p2p_addrs=advertised_addrs,
                    role="seeder",
                    timeout=1.0,
                )
                peers_list = p2p_info.get("peers") or pre_peers
                if peers_list and hasattr(self.libp2p_manager, "bootstrap_from_peers"):
                    self.libp2p_manager.bootstrap_from_peers(peers_list, timeout=1.5)
                if domain_key:
                    self.libp2p_manager.provide_domain(domain_key, timeout=5.0, background=True)
                relay_addrs = [
                    str(a)
                    for entry in peers_list
                    if isinstance(entry, dict) and entry.get("role") in ("hub", "root", "writer")
                    for a in (entry.get("addrs") or [])
                ]
                self.read_ost.discover_from_p2p(
                    self.libp2p_manager,
                    domain_key=domain_key,
                    registry_urls=registry_urls,
                    relay_addrs=relay_addrs,
                    timeout=1.5,
                )
            except Exception:
                pass
        self.read_builder.close()
        self.read_builder = MerkleTreeBuilder(self.crypto, self.read_ost)

    def push(
        self,
        delegation_epoch: int,
        now: int,
        delegated_mounts: Optional[Dict[str, str]] = None,
    ) -> Tuple[dict, Path, int]:
        self.ost.reset_metrics()
        next_ver = self.l4.pin.version + 1
        snapshot = self.clayfs.snapshot_result(f"v{next_ver}")
        snap_dir = snapshot.path
        if snapshot.skipped:
            # ジャンクション等はツリー外を指し得るので入れない。黙って欠けさせない。
            preview = ", ".join(snapshot.skipped[:3])
            more = "" if len(snapshot.skipped) <= 3 else f" 他 {len(snapshot.skipped) - 3} 件"
            print(
                f"[dfs] スナップショットから {len(snapshot.skipped)} 件を除外しました"
                f"（ジャンクション / 特殊ファイル）: {preview}{more}",
                file=sys.stderr,
            )

        with self.ost.session():
            root_pid, root_wid = self.builder.upload_directory(snap_dir, delegated_mounts=delegated_mounts)
        for warning in self.builder.warnings:
            print(f"[dfs] warning: {warning}", file=sys.stderr)

        log_env = self.l4.commit(
            registry=self.registry,
            root_plain_id=root_pid,
            root_wire_id=root_wid,
            delegation_epoch=delegation_epoch,
            ost_endpoint=list(self.ost_endpoints),
            now=now,
            role_epoch=self.role_epoch,
        )
        wire_bytes = self.ost.bytes_sent
        self.clayfs._auto_prune_snapshots()
        return log_env, snap_dir, wire_bytes

    def pull(self, expected_writer_pubkey: Optional[str] = None) -> Path:
        head_env = self.l4.sync_head(self.registry, expected_writer_pubkey=expected_writer_pubkey)
        if head_env is None:
            raise RuntimeError(f"No versions available on registry for {self.sub_path}")
        self.refresh_read_ost()
        self.read_ost.reset_metrics()

        p = head_env["payload"]
        dl_builder = (
            MerkleTreeBuilder(self.crypto, _CachingOSTProxy(self.read_ost, self.p2p_chunk_store))
            if self.p2p_chunk_store is not None
            else self.read_builder
        )
        with tempfile.TemporaryDirectory(prefix="dfs_stage_") as staging:
            staging_dir = Path(staging)
            try:
                with self.read_ost.session():
                    dl_builder.download_directory(
                        p["root_plain_id"], p["root_wire_id"], staging_dir
                    )
            finally:
                if dl_builder is not self.read_builder:
                    dl_builder.close()
            self.clayfs.replace_work_tree(staging_dir)

        snap = self.clayfs.take_snapshot(f"v{p['version']}")
        self.clayfs._auto_prune_snapshots()
        seed_ep = os.environ.get("DFS_SEED_ENDPOINT", "").strip()
        registry_urls = getattr(self.registry, "registry_urls", None)
        if (seed_ep or self.libp2p_manager is not None) and registry_urls:
            from .relay import announce_ice_peer, register_p2p_peer

            peer_id = ""
            p2p_addrs: List[str] = []
            if self.libp2p_manager is not None:
                try:
                    self.libp2p_manager.start(timeout=5.0)
                    peer_id = self.libp2p_manager.peer_id
                    p2p_addrs = (
                        self.libp2p_manager.effective_addrs()
                        if hasattr(self.libp2p_manager, "effective_addrs")
                        else list(self.libp2p_manager.addrs)
                    )
                    domain_key = getattr(self.l4, "root_pubkey", None) or self.sub_path or "default"
                    self.libp2p_manager.provide_domain(domain_key, timeout=5.0, background=True)
                    register_p2p_peer(
                        registry_urls[0],
                        peer_id,
                        node_id=self.name,
                        p2p_addrs=p2p_addrs,
                        role="seeder",
                        timeout=1.0,
                    )
                except Exception:
                    pass
            announce_ice_peer(
                registry_urls[0],
                node_id=self.name,
                direct_endpoints=[seed_ep] if seed_ep else [],
                role="seeder",
                timeout=0.5,
                peer_id=peer_id,
                p2p_addrs=p2p_addrs,
            )
        return snap

    # ---- 参照のみ（rclone ライク CLI 用） ---------------------------------
    def _head_root(self, expected_writer_pubkey: Optional[str] = None) -> Tuple[str, str, Optional[str], int]:
        """先頭版の root 3 つ組と版番号を返す。ピン（local_head.json）も更新する。

        リモートにまだ版が無ければ root を空文字で返す（呼び出し側が「空」を判断する）。
        """
        head_env = self.l4.sync_head(self.registry, expected_writer_pubkey=expected_writer_pubkey)
        root_store = getattr(self, "root_store", None) or getattr(self.builder, "root_store", None) or getattr(self.builder, "root_store", None)
        if head_env is None:
            return "", "", root_store, 0
        self.refresh_read_ost()
        p = head_env["payload"]
        return p["root_plain_id"], p["root_wire_id"], root_store, int(p["version"])

    def list_remote(self, prefix: str = "") -> List[Dict[str, Any]]:
        """リモートのツリーを一覧する（内容は取らない）。1 階層 = 1 往復。

        リモートにまだ版が無ければ空の一覧を返す（最初の push の前でも一覧できる）。
        """
        head = self.l4.sync_head(self.registry)
        if head is None:
            return []
        self.refresh_read_ost()
        self.read_ost.reset_metrics()
        p = head["payload"]
        root_store = getattr(self, "root_store", None) or getattr(self.builder, "root_store", None)
        with self.read_ost.session():
            return self.read_builder.list_tree(
                p["root_plain_id"], p["root_wire_id"], root_store=root_store, prefix=prefix
            )

    def iter_remote(self, rel_path: str) -> Iterator[bytes]:
        """リモートの 1 ファイルをチャンク単位でストリーミング取得する。"""
        root_pid, root_wid, root_store, ver = self._head_root()
        if ver == 0 or not root_wid:
            raise FileNotFoundError(f"Remote has no versions yet: {rel_path}")
        self.read_ost.reset_metrics()
        with self.read_ost.session():
            yield from self.read_builder.iter_remote_file(
                root_pid, root_wid, rel_path, root_store=root_store
            )

    def read_remote(self, rel_path: str) -> bytes:
        """リモートの 1 ファイルだけを取得する（ツリー全体は落とさない）。"""
        root_pid, root_wid, root_store, ver = self._head_root()
        if ver == 0 or not root_wid:
            raise FileNotFoundError(f"Remote has no versions yet: {rel_path}")
        self.read_ost.reset_metrics()
        with self.read_ost.session():
            return self.read_builder.read_remote_file(
                root_pid, root_wid, rel_path, root_store=root_store
            )

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
            if item.is_symlink():
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
            target = safe_target(work_tree, rel, create_parents=True)
            write_bytes_no_follow(target, data)
        delegation_epoch = int(epoch) if epoch is not None else int(self.l4.pin.delegation_epoch or 1)
        return self.push(delegation_epoch=delegation_epoch, now=now)
