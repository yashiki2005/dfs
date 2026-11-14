#!/usr/bin/env python3
"""
dfs/cli_main.py
rclone ライクな dfs の CLI。

`cli.py` の部品（L2 名簿クライアント、`serve`、`delegate`、ノード構築）をそのまま使い、
「リモート名で場所を指す」操作体系を被せる。

    dfscli listremotes
    dfscli config create scaleway --registry http://172.16.1.60:19440 \\
        --ost 172.16.1.60:19443 --path /example.com/alice/notes \\
        --key ~/.ssh/alice --secret <共有秘密>
    dfscli ls    scaleway:
    dfscli ls    scaleway:docs
    dfscli cat   scaleway:docs/readme.md
    dfscli copy  ./local scaleway:docs
    dfscli import_tar release.tar.gz scaleway:docs
    dfscli mv    scaleway:docs/old.md scaleway:docs/new.md
    dfscli sync  ./local scaleway:docs      # リモートをローカルに合わせる
    dfscli pull  scaleway:docs ./local      # リモートをローカルへ取り出す
    dfscli lsd   scaleway:docs
    dfscli mount scaleway:docs /mnt/docs
    dfscli check scaleway:docs ./local
    dfscli about scaleway:

設計上の注意（dfs の単一書き手）:
  - リモートは「1 つの書き込み境界（サブツリー）」に対応する。
  - 書き込み系（copy / sync / copyto）は、まず作業ディレクトリの写しを先頭版に
    合わせてから、変更を載せて 1 版としてまとめて push する。
  - 読み出し系（ls / cat / size / check）は版を進めない。

環境変数:
  DFS_CONFIG    リモート定義ファイル（既定 ~/.config/dfs/remotes.json）

配布:
  `pyproject.toml` の console_scripts で `dfscli` / `dfssvc` をインストールできる。
  リポジトリ直下のシェルラッパーは開発用の互換入口として残している。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import secrets
import tarfile
import tempfile
import zlib
import time
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from . import cli as cli_mod
from .archive import (
    ArchiveError,
    catalog,
    create_archive,
    download_torrent,
    extract_bundle,
    locate_downloaded_bundle,
    magnet_for_descriptor,
    verify_archive_descriptor,
    verify_bundle,
)
from .discovery import (
    CandidacyError,
    create_candidacy_envelope,
    fetch_candidacy,
    verify_candidacy_envelope,
)
from .dnssec import Discovery, DiscoveryError, discover_domain
from .invite import InviteError, decode_invite, encode_ro_invite, encode_rw_invite

# L2 名簿の既定ポート。ホスト名だけで済むようにする（例: --registry 172.16.1.60）。
DEFAULT_REGISTRY_PORT = 9440
# dfssvc が立てるサーバの既定。こちらは連続した空きを選ぶので 19440 から。
DEFAULT_LOCAL_REGISTRY_PORT = 19440
from .l2_registry import ConflictError, ServiceUnavailableError
from .l1_delegation import DelegationError, create_delegation_envelope, verify_delegation_chain
from .l4_log import (
    FILE_CHUNK_BYTES,
    L4LogClient,
    RollbackDetectedError,
    SilentDropDetectedError,
)
from .l5_fs import DFSNode
from .crypto import ssh_key_fingerprint
from .fs.core import remove_tree
from .path_safety import UnsafePathError, copyfile_no_follow, safe_target
from .paths import config_dir, restrict_to_owner
from .private_io import ensure_private_dir, write_private_json
from .remotes import NAME_RE, Remote, RemoteError, RemoteStore, split_remote_spec

CACHE_VERSION_FILENAME = "cache_version"
CHECKSUM_MODES = ("size", "crc32", "sha1", "plain_id")


class UsageError(Exception):
    """コマンドの使い方の誤り（終了コード 2）"""


# ==========================================
# リモートの準備
# ==========================================
def _ensure_keypair(priv_key: Path) -> None:
    """秘密鍵に対する .pub が無ければ作る（L4 の署名検証に要る）。"""
    pub = Path(f"{priv_key}.pub")
    if pub.exists():
        return
    if not priv_key.exists():
        raise UsageError(f"Writer key does not exist: {priv_key}")
    import subprocess

    res = subprocess.run(
        ["ssh-keygen", "-y", "-f", str(priv_key)],
        capture_output=True, text=True,
    )
    if res.returncode != 0:
        raise UsageError(f"Cannot read public key from {priv_key}: {res.stderr.strip()}")
    pub.write_text(res.stdout.strip() + "\n", encoding="utf-8")
    print(f"[dfscli] 公開鍵を作成しました: {pub}", file=sys.stderr)


def resolve_ost(remote: Remote, registry: Optional[cli_mod.RemoteRegistryClient] = None) -> str:
    """L3 OST の ``host:port`` を決める。

    優先順: リモート定義の ``ost`` → ロケータの ``endpoints`` → サーバの広告（``/v1/ost``）。
    L2 は OST の場所を知っているので、``config create`` で ``--ost`` を省ける。
    """
    if remote.ost:
        return remote.ost
    client = registry or cli_mod.RemoteRegistryClient(remote.registry_urls())
    # 1) 先頭版があれば、そのロケータに endpoints が入っている
    if remote.path:
        try:
            _del, loc_env, _head = client.resolve(remote.path)
        except Exception:  # noqa: BLE001 - 解決できなければ次の手に落ちる
            loc_env = None
        if loc_env:
            endpoints = loc_env.get("payload", {}).get("endpoints") or []
            if endpoints:
                return Remote.normalize_ost(endpoints[0])
    # 2) 先頭版がまだ無い（初回）なら、サーバの広告を使う
    info = client.ost_info()
    endpoint = info.get("endpoint") or ""
    if endpoint:
        return Remote.normalize_ost(endpoint)
    raise UsageError(
        f"Cannot determine the L3 OST for remote {remote.name!r}.\n"
        f"L2 ({remote.registry}) did not advertise one; pass --ost explicitly."
    )


def resolve_path(remote: Remote, registry: Optional[cli_mod.RemoteRegistryClient] = None) -> str:
    """サブツリーのパスを決める。

    優先順: リモート定義の ``path`` → 書き手公開鍵に一致する登録済みパス。
    1 つの鍵で 1 つの境界を書く運用なら、``--path`` を省ける。
    """
    if remote.path:
        return remote.path
    client = registry or cli_mod.RemoteRegistryClient(remote.registry_urls())
    priv_key = Path(remote.key).expanduser()
    if not priv_key.is_file():
        raise UsageError(f"Writer key does not exist: {priv_key}")
    pub = public_key_of(priv_key)
    found = client.find_path_for_writer(pub)
    if not found:
        raise UsageError(
            f"Cannot determine the subtree path for remote {remote.name!r}.\n"
            f"No delegation on {remote.registry} lists this key as its writer; "
            f"pass --path explicitly."
        )
    return found


def public_key_of(priv_key: Path) -> str:
    """秘密鍵から公開鍵の 1 行を出す（``.pub`` があればそれを使う）。"""
    pub = Path(f"{priv_key}.pub")
    if pub.is_file():
        return pub.read_text(encoding="utf-8").strip()
    import subprocess

    res = subprocess.run(["ssh-keygen", "-y", "-f", str(priv_key)], capture_output=True, text=True)
    if res.returncode != 0:
        raise UsageError(f"Cannot read public key from {priv_key}: {res.stderr.strip()}")
    return res.stdout.strip()


def _ensure_remote_secret(remote: Remote) -> Remote:
    """``remote.secret`` が空なら端末から 2 度入力して ``RemoteStore`` に保存する。"""
    if remote.secret:
        return remote
    # tree_secret はサーバに置かない共有秘密なので、L2 からは引けない。
    # 対話端末ならその場で 2 度入力して remotes.json に保存する。
    secret = prompt_secret(
        f"tree_secret ({remote.name}): ",
        f"tree_secret ({remote.name}, 確認): ",
    )
    if secret:
        remote.secret = secret
        store = RemoteStore()
        if store.get(remote.name) is not None:
            store.set(remote)
            print(f"[dfscli] 共有秘密鍵 (tree_secret) を保存しました: {store.path}", file=sys.stderr)
    if not remote.secret:
        raise UsageError(
            f"Remote {remote.name!r} has no tree_secret.\n"
            f"Set it with 'dfscli config create {remote.name} ... --secret <共有秘密>' "
            f"(or edit {RemoteStore().path})."
        )
    return remote


def open_remote(remote: Remote, create: bool = False) -> DFSNode:
    """リモートの作業ディレクトリを用意し、ノードを組み立てる。

    ``create=True`` のときは未初期化なら初期化する（書き込み系で使う）。
    ``ost`` と ``path`` は、指定が無ければ L2 から解決する。
    """
    mount_root = remote.resolved_workdir().expanduser()
    cfg_path = mount_root / ".clayfs" / cli_mod.CONFIG_FILENAME
    if cfg_path.parent.exists():
        ensure_private_dir(cfg_path.parent)
    if cfg_path.is_file():
        restrict_to_owner(cfg_path)

    if not cfg_path.is_file():
        if not create:
            raise UsageError(
                f"Remote {remote.name!r} is not initialized at {mount_root}.\n"
                f"Run 'dfscli touch {remote.name}:' or a write command first."
            )
        if remote.read_only:
            priv_key_value = ""
        else:
            priv_key = Path(remote.key).expanduser()
            _ensure_keypair(priv_key)
            priv_key_value = str(priv_key)
        remote = _ensure_remote_secret(remote)
        registry = cli_mod.RemoteRegistryClient(remote.registry_urls())
        ost_value = resolve_ost(remote, registry)
        ost_alternates = list(remote.ost_alternates)
        if not remote.ost:
            try:
                info = registry.ost_info()
                for alt in info.get("alternates") or []:
                    norm_alt = Remote.normalize_ost(str(alt))
                    if norm_alt and norm_alt != ost_value and norm_alt not in ost_alternates:
                        ost_alternates.append(norm_alt)
            except Exception:
                pass
        sub_path = resolve_path(remote, registry)
        try:
            host, port, canonical_ost = (
                DFSNode._parse_ost_endpoint(ost_value)[0],
                DFSNode._parse_ost_endpoint(ost_value)[1],
                DFSNode._normalize_ost_endpoint(ost_value),
            )
        except ValueError as e:
            raise UsageError(
                f"Cannot parse L3 OST endpoint {ost_value!r} for remote {remote.name!r}: {e}"
            ) from e
        mount_root.mkdir(parents=True, exist_ok=True)
        (mount_root / "tree").mkdir(exist_ok=True)
        ensure_private_dir(mount_root / ".clayfs")
        cfg = {
            "delegation_epoch": int(remote.epoch),
            "role_epoch": int(remote.role_epoch),
            "compression": remote.compression,
            "node_name": remote.node_name or remote.name,
            "ost_alternates": ost_alternates,
            "libp2p_peers": list(remote.libp2p_peers),
            "libp2p_psk": remote.libp2p_psk,
            "ost_endpoint": canonical_ost,
            "ost_host": host,
            "ost_port": int(port),
            "priv_key": priv_key_value,
            "read_only": bool(remote.read_only),
            "registry_url": remote.registry,
            "registry_alternates": list(remote.registry_alternates),
            "root_pubkey": remote.root_pubkey,
            "sub_path": sub_path,
            "tree_secret": remote.secret,
        }
        write_private_json(cfg_path, cfg)

    node, cfg, _reg = cli_mod.load_node_from_mount(mount_root)
    # リモート定義は接続先の正本。既存の作業 config が古い場合も、
    # 主名簿・代替名簿・複製 OST をリモート定義に合わせる。
    changed = False
    tree_identity_changed = False
    desired_ost = remote.ost
    if desired_ost:
        desired_host, desired_port = DFSNode._parse_ost_endpoint(desired_ost)
        desired_canonical = DFSNode._normalize_ost_endpoint(desired_ost)
        if (
            str(cfg.get("ost_endpoint", "")) != desired_canonical
            or str(cfg.get("ost_host", "")) != desired_host
            or int(cfg.get("ost_port", 0)) != int(desired_port)
        ):
            cfg["ost_endpoint"] = desired_canonical
            cfg["ost_host"] = desired_host
            cfg["ost_port"] = int(desired_port)
            changed = True
    if (
        cfg.get("registry_url") != remote.registry
        or list(cfg.get("registry_alternates") or []) != list(remote.registry_alternates)
    ):
        cfg["registry_url"] = remote.registry
        cfg["registry_alternates"] = list(remote.registry_alternates)
        changed = True
    if list(cfg.get("ost_alternates") or []) != list(remote.ost_alternates):
        cfg["ost_alternates"] = list(remote.ost_alternates)
        changed = True
    if (
        list(cfg.get("libp2p_peers") or []) != list(remote.libp2p_peers)
        or str(cfg.get("libp2p_psk", "") or "") != remote.libp2p_psk
    ):
        cfg["libp2p_peers"] = list(remote.libp2p_peers)
        cfg["libp2p_psk"] = remote.libp2p_psk
        changed = True
    if int(cfg.get("role_epoch", 1)) != int(remote.role_epoch):
        cfg["role_epoch"] = int(remote.role_epoch)
        changed = True
    if str(cfg.get("compression", "auto") or "auto") != remote.compression:
        cfg["compression"] = remote.compression
        changed = True
    if remote.path and cfg.get("sub_path") != remote.path:
        cfg["sub_path"] = remote.path
        changed = True
        tree_identity_changed = True
    if not remote.secret and not str(cfg.get("tree_secret", "") or ""):
        remote = _ensure_remote_secret(remote)
    if remote.secret and cfg.get("tree_secret") != remote.secret:
        cfg["tree_secret"] = remote.secret
        changed = True
    desired_priv_key = "" if remote.read_only else str(Path(remote.key).expanduser())
    if cfg.get("priv_key") != desired_priv_key:
        cfg["priv_key"] = desired_priv_key
        changed = True
    if bool(cfg.get("read_only", False)) != bool(remote.read_only):
        cfg["read_only"] = bool(remote.read_only)
        changed = True
    if cfg.get("node_name") != (remote.node_name or remote.name):
        cfg["node_name"] = remote.node_name or remote.name
        changed = True
    if int(cfg.get("delegation_epoch", 1)) != int(remote.epoch):
        cfg["delegation_epoch"] = int(remote.epoch)
        changed = True
    if remote.root_pubkey and cfg.get("root_pubkey") != remote.root_pubkey:
        cfg["root_pubkey"] = remote.root_pubkey
        changed = True
        tree_identity_changed = True
    if changed:
        if tree_identity_changed:
            _reset_workdir_pin(mount_root)
        write_private_json(cfg_path, cfg)
        node, cfg, _reg = cli_mod.load_node_from_mount(mount_root)
    return node


def _reset_workdir_pin(mount_root: Path) -> None:
    """接続先ツリーや root 鍵が切り替わったときに古い L4 ピンとキャッシュ版数を消す。"""
    meta = mount_root / ".clayfs"
    for fname in ("local_head.json", CACHE_VERSION_FILENAME):
        try:
            (meta / fname).unlink(missing_ok=True)
        except OSError:
            pass


def _cache_marker(node: DFSNode) -> Path:
    return node.clayfs.clayfs_meta / CACHE_VERSION_FILENAME


def _load_cached_version(node: DFSNode) -> int:
    marker = _cache_marker(node)
    if not marker.is_file():
        return -1
    try:
        return int(marker.read_text(encoding="utf-8").strip())
    except (ValueError, OSError):
        return -1


def _save_cached_version(node: DFSNode, version: int) -> None:
    marker = _cache_marker(node)
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text(str(int(version)) + "\n", encoding="utf-8")


def refresh_cache(node: DFSNode, force: bool = False) -> int:
    """作業ディレクトリの写しをリモートの先頭版に合わせ、その版番号を返す。

    すでに同じ版を持っていれば何もしない（L2 の 1 往復だけ）。
    リモートが空なら、作業ツリーを空にして 0 を返す（これから最初の版を作る）。
    """
    head = node.l4.sync_head(node.registry)
    if head is None:
        # リモートは空。作業ツリーを空にして、最初の push に備える。
        work_tree = node.clayfs.work_tree
        if work_tree.exists():
            remove_tree(work_tree)
        work_tree.mkdir(parents=True, exist_ok=True)
        _save_cached_version(node, 0)
        return 0

    version = int(head["payload"]["version"])
    if not force and _load_cached_version(node) == version:
        return version

    p = head["payload"]
    node.refresh_read_ost()
    node.read_ost.reset_metrics()
    with tempfile.TemporaryDirectory(prefix="dfs_stage_") as staging:
        staging_dir = Path(staging)
        with node.read_ost.session():
            node.read_builder.download_directory(
                p["root_plain_id"], p["root_wire_id"], staging_dir
            )
        node.clayfs.replace_work_tree(staging_dir)
    node.clayfs.take_snapshot(f"v{version}")
    _save_cached_version(node, version)
    return version


def _require_writable(remote: Remote) -> None:
    if remote.read_only:
        raise UsageError(f"Remote {remote.name!r} is read-only; writes are not allowed")


def _push(node: DFSNode, remote: Remote, delegated_mounts: Optional[Dict[str, str]] = None) -> Tuple[dict, int]:
    _require_writable(remote)
    log_env, _snap, wire_bytes = node.push(
        delegation_epoch=int(remote.epoch),
        now=int(time.time()),
        delegated_mounts=delegated_mounts or {},
    )
    version = int(log_env["payload"]["version"])
    _save_cached_version(node, version)
    return log_env, wire_bytes


# ==========================================
# パスの扱い
# ==========================================
def _norm_prefix(prefix: str) -> str:
    prefix = (prefix or "").strip().strip("/")
    if not prefix:
        return ""
    parts = [part for part in prefix.replace("\\", "/").split("/") if part not in ("", ".")]
    if any(part == ".." for part in parts):
        raise UsageError(f"Invalid remote path (contains '..'): {prefix!r}")
    return "/".join(parts)


def _join_prefix(prefix: str, rel: str) -> str:
    rel = rel.replace("\\", "/").lstrip("/")
    return f"{prefix}/{rel}" if prefix else rel


class PathFilter:
    """``--include`` / ``--exclude`` の相対パスフィルタ。

    パターンは操作の基準ディレクトリからの相対パスに適用する。``include`` が
    指定された場合は、まずそれに一致するものだけを対象にし、その後に
    ``exclude`` を適用する（除外が常に優先）。
    """

    def __init__(
        self,
        includes: Optional[List[str]] = None,
        excludes: Optional[List[str]] = None,
    ):
        self.includes = tuple(
            p.replace("\\", "/").lstrip("/")
            for p in (includes or [])
            if p.strip()
        )
        self.excludes = tuple(
            p.replace("\\", "/").lstrip("/")
            for p in (excludes or [])
            if p.strip()
        )

    @staticmethod
    def _match(path: str, pattern: str) -> bool:
        path = path.replace("\\", "/").lstrip("/")
        pattern = pattern.replace("\\", "/").lstrip("/")
        if not pattern:
            return False
        if pattern.endswith("/"):
            prefix = pattern.rstrip("/")
            return path == prefix or path.startswith(prefix + "/")
        if fnmatchcase(path, pattern):
            return True
        # ワイルドカード無しの ``docs`` は、そのディレクトリ配下も対象にする。
        if not any(ch in pattern for ch in "*?["):
            return path.startswith(pattern + "/")
        return False

    def allows(self, path: str) -> bool:
        path = path.replace("\\", "/").lstrip("/")
        if self.includes and not any(self._match(path, p) for p in self.includes):
            return False
        if any(self._match(path, p) for p in self.excludes):
            return False
        return True


def _path_filter(args: argparse.Namespace) -> PathFilter:
    return PathFilter(
        includes=getattr(args, "include", None),
        excludes=getattr(args, "exclude", None),
    )


def _filter_local(local: Dict[str, Path], path_filter: PathFilter) -> Dict[str, Path]:
    return {rel: src for rel, src in local.items() if path_filter.allows(rel)}


def _collect_local(src: Path, include_root_name: bool = False) -> Dict[str, Path]:
    """ローカルのファイルを、基準ディレクトリからの相対パス -> 実ファイルの辞書で返す。

    ``include_root_name=False``（既定）のときは、``src`` 自身の名前を付けない
    （rclone の ``copy`` と同じで、ディレクトリの中身が宛先へ展開される）。
    ``include_root_name=True`` のときは ``src`` の名前を 1 段として含める
    （``src`` ごと運びたいとき）。
    """
    src = src.expanduser()
    out: Dict[str, Path] = {}
    if src.is_symlink():
        raise UsageError(f"Local path is a symlink, which is not supported: {src}")
    if src.is_file():
        root_prefix = f"{src.parent.name}/" if include_root_name else ""
        out[f"{root_prefix}{src.name}"] = src
        return out
    if not src.is_dir():
        raise UsageError(f"Local path does not exist: {src}")
    for item in sorted(src.rglob("*")):
        if item.is_symlink():
            continue
        if item.is_dir():
            continue
        if item.name in (".DS_Store",) or item.name.startswith("._"):
            continue
        if any(part in (".clayfs", ".git") for part in item.relative_to(src).parts):
            continue
        rel = item.relative_to(src).as_posix()
        out[f"{src.name}/{rel}" if include_root_name else rel] = item
    return out


def _local_chunk_plain_ids(path: Path, crypto: Any) -> List[str]:
    """ローカルファイルを送信時と同じ境界で区切り、各塊の plain_id を返す。"""
    result: List[str] = []
    with path.open("rb") as source:
        while True:
            chunk = source.read(FILE_CHUNK_BYTES)
            if not chunk and result:
                break
            result.append(crypto.compute_plain_id(chunk).hex())
            if len(chunk) < FILE_CHUNK_BYTES:
                break
    return result


def _tar_member_path(name: str, strip_components: int) -> str:
    """tar member 名を安全な相対パスにする（危険なら UsageError）。"""
    if "\x00" in name:
        raise UsageError(f"tar member 名に NUL があります: {name!r}")
    text = name.replace("\\", "/")
    if text.startswith("/"):
        raise UsageError(f"tar に絶対パスがあります: {name!r}")
    parts = [part for part in text.split("/") if part not in ("", ".")]
    if any(part == ".." for part in parts):
        raise UsageError(f"tar member が親ディレクトリを参照しています: {name!r}")
    if len(parts) <= strip_components:
        return ""
    rel = "/".join(parts[strip_components:])
    if any(part == ".clayfs" for part in parts):
        raise UsageError(f"tar に DFS の管理ディレクトリが含まれています: {name!r}")
    if rel.endswith("/"):
        rel = rel.rstrip("/")
    return rel


def _extract_tar_safely(
    archive_path: Path,
    staging: Path,
    strip_components: int,
) -> Tuple[Dict[str, Path], set]:
    """tar を検証しながら staging に展開する。

    symlink / hardlink / device / FIFO は拒否する。通常ファイルとディレクトリだけを
    許可し、作成したファイルと明示的なディレクトリを返す。
    """
    files: Dict[str, Path] = {}
    dirs = set()
    try:
        with tarfile.open(archive_path, mode="r:*") as archive:
            for member in archive:
                rel = _tar_member_path(member.name, strip_components)
                if not rel:
                    continue
                if member.issym() or member.islnk():
                    raise UsageError(f"tar のリンクはインポートできません: {member.name!r}")
                if not (member.isfile() or member.isdir()):
                    raise UsageError(
                        f"tar の特殊ファイルはインポートできません: {member.name!r}"
                    )
                if rel == ".DS_Store" or rel.startswith("._"):
                    continue
                if member.isdir():
                    dirs.add(rel)
                    continue
                target = safe_target(staging, rel, create_parents=True)
                source = archive.extractfile(member)
                if source is None:
                    raise UsageError(f"tar member を読めません: {member.name!r}")
                with source, target.open("wb") as dest:
                    shutil.copyfileobj(source, dest, length=1024 * 1024)
                files[rel] = target
    except (tarfile.TarError, OSError, EOFError) as e:
        raise UsageError(f"tar を読み込めません: {archive_path}: {e}") from e
    return files, dirs


def _tree_path(node: DFSNode, rel: str) -> Path:
    try:
        return safe_target(node.clayfs.work_tree, rel)
    except UnsafePathError as e:
        raise UsageError(f"Invalid path in tree: {rel!r} ({e})") from e


def _validate_snapshot_id(snap_id: str) -> str:
    """snapshot ID を単一のパス要素に限定する（``..`` や区切りを拒否）。"""
    if (
        not snap_id
        or snap_id in (".", "..")
        or "/" in snap_id
        or "\\" in snap_id
        or "\x00" in snap_id
    ):
        raise UsageError(f"Invalid snapshot ID: {snap_id!r}")
    return snap_id


def plan_changes(
    node: DFSNode,
    prefix: str,
    local: Dict[str, Path],
    checksum: str = "size",
    path_filter: Optional[PathFilter] = None,
) -> Tuple[List[Tuple[str, Path, str]], List[str], List[str]]:
    """ローカルとリモートを比べ、(書くもの, 消すもの, 変わらないもの) を返す。

    転送の判定は rclone の既定と同じく大きさを先に見る。``checksum`` が
    ``size`` 以外なら内容の checksum まで比べる。``plain_id`` は dfs の
    内容アドレス、``crc32`` / ``sha1`` は互換用の軽い比較。dfs は書き手側の索引で塊を
    重複排除するため、内容が同じなら ``push`` しても本文は送られない。それでも
    版が増えるのは無駄なので、「変わらないなら版を作らない」をここで決める。

    返り値の「書くもの」は ``(リモートのパス, ローカルの実ファイル, "add"|"update")``。
    ``path_filter`` が指定された場合、削除候補もフィルタの内側だけに限定する。
    """
    if checksum is True:
        checksum = "plain_id"
    elif checksum is False or checksum is None:
        checksum = "size"
    if checksum not in CHECKSUM_MODES:
        raise UsageError(f"unknown checksum mode: {checksum!r}")
    path_filter = path_filter or PathFilter()
    remote = {
        e["path"]: e
        for e in _all_entries(node, prefix)
        if e["type"] == "file"
        and path_filter.allows(e["path"][len(prefix) + 1 if prefix else 0:])
    }
    wanted = {
        _join_prefix(prefix, rel): src
        for rel, src in local.items()
        if path_filter.allows(rel)
    }

    to_write: List[Tuple[str, Path, str]] = []
    unchanged: List[str] = []
    for path, src in sorted(wanted.items()):
        entry = remote.get(path)
        if entry is None:
            to_write.append((path, src, "add"))
            continue
        size = src.stat().st_size
        if int(entry.get("size", 0)) != size:
            to_write.append((path, src, "update"))
            continue
        data: Optional[bytes] = None
        if checksum in ("plain_id", "crc32", "sha1"):
            data = src.read_bytes()
        if checksum == "plain_id":
            local_ids = _local_chunk_plain_ids(src, node.crypto)
            remote_ids = [
                str(chunk.get("plain_id", ""))
                for chunk in (entry.get("chunks") or [entry])
            ]
            if local_ids != remote_ids:
                to_write.append((path, src, "update"))
                continue
        elif checksum in ("crc32", "sha1"):
            remote_data = node.read_remote(path)
            if checksum == "crc32":
                local_sum = zlib.crc32(data) & 0xFFFFFFFF
                remote_sum = zlib.crc32(remote_data) & 0xFFFFFFFF
            else:
                local_sum = hashlib.sha1(data).hexdigest()
                remote_sum = hashlib.sha1(remote_data).hexdigest()
            if local_sum != remote_sum:
                to_write.append((path, src, "update"))
                continue
        unchanged.append(path)

    to_delete = sorted(set(remote) - set(wanted))
    return to_write, to_delete, unchanged


def apply_writes(node: DFSNode, writes: List[Tuple[str, Path, str]]) -> None:
    """``plan_changes`` の「書くもの」を、作業ツリーへ反映する。"""
    for path, src, _kind in writes:
        relative = path
        try:
            target = safe_target(node.clayfs.work_tree, relative, create_parents=True)
        except UnsafePathError as e:
            raise UsageError(f"Invalid path in tree: {relative!r} ({e})") from e
        try:
            copyfile_no_follow(src, target)
        except UnsafePathError as e:
            raise UsageError(f"Refusing symlink write: {relative!r} ({e})") from e


def apply_deletes(node: DFSNode, paths: List[str], prune_empty: bool = True) -> None:
    """消すものを作業ツリーから取り除く。

    ``prune_empty=True`` のときは、空になったディレクトリも片付ける（rclone の
    `sync --delete` と同じで、ローカルの見た目に合わせる）。``rm`` / ``rmdir`` では
    消した階層だけを片付けたいので、呼び出し側で範囲を決める。
    """
    for path in paths:
        victim = _tree_path(node, path)
        if victim.exists():
            victim.unlink()
    if prune_empty:
        prune_empty_parents(node, paths)


def prune_empty_dirs(node: DFSNode, start: Optional[Path] = None) -> List[str]:
    """空のディレクトリを、下から順に取り除く。消したパスを返す。"""
    root = start if start is not None else node.clayfs.work_tree
    removed: List[str] = []
    for d in sorted(
        (p for p in root.rglob("*") if p.is_dir()),
        key=lambda p: len(p.parts), reverse=True,
    ):
        try:
            if not any(d.iterdir()):
                d.rmdir()
                removed.append(str(d.relative_to(node.clayfs.work_tree)))
        except OSError:
            pass
    return removed


def prune_empty_parents(node: DFSNode, paths: List[str]) -> List[str]:
    """削除したファイルの先祖だけを、下から順に空なら取り除く。"""
    work_root = node.clayfs.work_tree.resolve(strict=False)
    candidates: set[Path] = set()
    for rel in paths:
        try:
            target = _tree_path(node, rel)
        except UsageError:
            continue
        current = target.parent
        while True:
            try:
                current.resolve(strict=False).relative_to(work_root)
            except ValueError:
                break
            if current == work_root:
                break
            candidates.add(current)
            current = current.parent

    removed: List[str] = []
    for directory in sorted(candidates, key=lambda p: len(p.parts), reverse=True):
        try:
            if directory.is_dir() and not any(directory.iterdir()):
                directory.rmdir()
                removed.append(str(directory.relative_to(node.clayfs.work_tree)))
        except OSError:
            pass
    return removed


def _remote_file_paths(node: DFSNode, prefix: str = "") -> set:
    return {e["path"] for e in _all_entries(node, prefix) if e["type"] == "file"}


def _remote_dir_paths(node: DFSNode, prefix: str = "") -> set:
    return {e["path"] for e in _all_entries(node, prefix) if e["type"] == "dir"}


def _remove_from_tree(node: DFSNode, paths: List[str]) -> None:
    """作業ツリーから、ファイルまたはディレクトリ（中身ごと）を取り除く。"""
    for rel in sorted(paths, key=lambda p: len(p.split("/")), reverse=True):
        victim = _tree_path(node, rel)
        if victim.is_dir():
            try:
                remove_tree(victim)
            except OSError:
                pass
        elif victim.exists():
            victim.unlink()


# ==========================================
# 表示の補助
# ==========================================
def _human_size(n: int) -> str:
    units = ["B", "KiB", "MiB", "GiB", "TiB"]
    value = float(n)
    for u in units:
        if value < 1024 or u == units[-1]:
            return f"{value:.0f}{u}" if u == "B" else f"{value:.1f}{u}"
        value /= 1024
    return f"{n}B"


def _rel_entries(node: DFSNode, prefix: str) -> List[Dict[str, Any]]:
    """リモートの一覧を prefix で絞り、prefix からの相対パスを付けて返す。"""
    entries = node.list_remote()
    keep = []
    for e in entries:
        path = e["path"]
        if prefix:
            if not path.startswith(prefix + "/"):
                continue
            if "/" in path[len(prefix) + 1 :]:
                continue  # 直下だけ（rclone の ls と同じ挙動）
            e = dict(e)
            e["rel"] = path[len(prefix) + 1 :]
        else:
            if "/" in path:
                continue
            e = dict(e)
            e["rel"] = path
        keep.append(e)
    keep.sort(key=lambda e: e["rel"])
    return keep


def _all_entries(node: DFSNode, prefix: str) -> List[Dict[str, Any]]:
    entries = node.list_remote()
    if not prefix:
        return entries
    return [e for e in entries if e["path"] == prefix or e["path"].startswith(prefix + "/")]


# ==========================================
# サブコマンド
# ==========================================
def _probe_registry_tcp(url: str, timeout: float = 0.4) -> bool:
    """名簿 URL の host:port へ短時間で TCP 到達できるか調べる。"""
    from urllib.parse import urlsplit

    parts = urlsplit(url)
    host = parts.hostname
    if not host:
        return False
    port = parts.port or (443 if parts.scheme == "https" else 80)
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _remote_domain_candidate(remote: Remote) -> str:
    """リモート定義から DNSSEC 検証対象のドメイン名候補を取り出す。"""
    import ipaddress
    from urllib.parse import urlsplit

    def _is_domain(val: str) -> bool:
        s = (val or "").strip().rstrip(".")
        if not s or "." not in s or s == "localhost":
            return False
        try:
            ipaddress.ip_address(s.strip("[]"))
            return False
        except ValueError:
            return True

    if _is_domain(remote.name):
        return remote.name.strip().rstrip(".")
    host = urlsplit(remote.registry).hostname or ""
    if _is_domain(host):
        return host.strip().rstrip(".")
    return ""


def _probe_remote_status(remote: Remote) -> Dict[str, Any]:
    """L2 (root/domain dfs) への問い合わせと ``_dfs.<domain>`` DNSSEC 検証を行う。"""
    from .dnssec import DEFAULT_RECORD_PREFIX, has_txt_record

    online = _probe_registry_tcp(remote.registry)
    status: Dict[str, Any] = {
        "online": online,
        "l2_ok": None,
        "l2_error": "",
        "role": None,
        "root_anchor": "",
        "paths_count": None,
        "pubkey_match": None,
        "dnssec": None,
        "dnssec_record": "",
        "dnssec_error": "",
    }
    if online:
        try:
            urls = [u for u in [remote.registry, *remote.registry_alternates] if u]
            info = cli_mod.RemoteRegistryClient(urls).list_paths()
            anchor = str(info.get("root_anchor") or "")
            server_pub = str(info.get("root_pubkey") or "").strip()
            paths = info.get("paths")
            status["l2_ok"] = True
            status["root_anchor"] = anchor
            domain_cand = _remote_domain_candidate(remote)
            if anchor == "/" or remote.name in DEFAULT_ROOT_DFS_DOMAINS or domain_cand in DEFAULT_ROOT_DFS_DOMAINS:
                status["role"] = "root"
            elif anchor:
                status["role"] = "domain"
            status["paths_count"] = len(paths) if isinstance(paths, dict) else 0
            if remote.root_pubkey and server_pub:
                status["pubkey_match"] = (remote.root_pubkey == server_pub)
        except Exception as e:  # noqa: BLE001
            status["l2_ok"] = False
            status["l2_error"] = str(e)

    domain = _remote_domain_candidate(remote)
    if domain:
        record_name = f"{DEFAULT_RECORD_PREFIX}.{domain}"
        try:
            if has_txt_record(record_name):
                status["dnssec_record"] = record_name
                try:
                    disc = discover_domain(domain, record_name=record_name)
                    if remote.root_pubkey and disc.root_pubkey and remote.root_pubkey != disc.root_pubkey:
                        status["dnssec"] = "mismatch"
                        status["dnssec_error"] = "root_pubkey mismatch with DNSSEC"
                    else:
                        status["dnssec"] = "verified"
                except DiscoveryError as e:
                    status["dnssec"] = "failed"
                    status["dnssec_error"] = str(e)
        except Exception:  # noqa: BLE001
            pass

    return status


DEFAULT_ROOT_DFS_DOMAINS = ("yashiki.top",)


def _probe_root_dfs_domain(domain: str) -> Dict[str, Any]:
    """既定の root dfs ドメインを決め打ちで DNSSEC 検証し、L2 へ問い合わせる。"""
    from .dnssec import DEFAULT_RECORD_PREFIX, has_txt_record

    record_name = f"{DEFAULT_RECORD_PREFIX}.{domain}"
    status: Dict[str, Any] = {
        "name": domain,
        "registered": False,
        "registry": "",
        "path": f"/{domain}",
        "online": False,
        "l2_ok": None,
        "l2_error": "",
        "role": "root",
        "root_anchor": "",
        "paths_count": None,
        "dnssec": None,
        "dnssec_record": record_name,
        "dnssec_error": "",
    }
    try:
        if not has_txt_record(record_name):
            status["dnssec"] = "none"
            status["dnssec_error"] = f"{record_name} TXT not found"
            return status
        disc = discover_domain(domain, record_name=record_name)
        status["dnssec"] = "verified"
        status["registry"] = disc.primary_url
        status["path"] = disc.root_anchor or f"/{domain}"
        urls = [u for u in [disc.primary_url, *disc.alternate_urls] if u]
        online = _probe_registry_tcp(disc.primary_url) if disc.primary_url else False
        status["online"] = online
        if online and urls:
            try:
                info = cli_mod.RemoteRegistryClient(urls).list_paths()
                paths = info.get("paths")
                status["l2_ok"] = True
                status["root_anchor"] = str(info.get("root_anchor") or status["path"])
                status["paths_count"] = len(paths) if isinstance(paths, dict) else 0
            except Exception as e:  # noqa: BLE001
                status["l2_ok"] = False
                status["l2_error"] = str(e)
    except DiscoveryError as e:
        status["dnssec"] = "failed"
        status["dnssec_error"] = str(e)
    except Exception as e:  # noqa: BLE001
        status["dnssec"] = "failed"
        status["dnssec_error"] = str(e)
    return status


def _format_remote_status_details(st: Dict[str, Any]) -> str:
    """``_probe_remote_status`` / ``_probe_root_dfs_domain`` の詳細文字列を組み立てる。"""
    details: List[str] = []
    if st.get("l2_ok") is True:
        role_label = "root dfs" if st.get("role") == "root" else "domain dfs"
        anchor = st.get("root_anchor") or "/"
        paths_count = st.get("paths_count")
        l2_part = f"{role_label} (anchor={anchor}"
        if paths_count is not None:
            l2_part += f", paths={paths_count}"
        if st.get("pubkey_match") is False:
            l2_part += ", pubkey=MISMATCH"
        l2_part += ")"
        details.append(l2_part)
    elif st.get("l2_ok") is False and st.get("l2_error"):
        details.append(f"L2 error ({st['l2_error']})")
    dnssec_state = st.get("dnssec")
    if dnssec_state == "verified":
        details.append(f"DNSSEC: verified ({st.get('dnssec_record')})")
    elif dnssec_state in ("failed", "mismatch"):
        details.append(f"DNSSEC: FAILED ({st.get('dnssec_record')}: {st.get('dnssec_error')})")
    elif dnssec_state == "none":
        details.append(f"DNSSEC: none ({st.get('dnssec_record')})")
    return ", ".join(details)


def cmd_listremotes(args: argparse.Namespace) -> int:
    from concurrent.futures import ThreadPoolExecutor
    from .svc import ServiceStore

    store = RemoteStore()
    names = store.names()
    no_check = bool(getattr(args, "no_check", False))
    is_prune = bool(getattr(args, "prune", False))

    known_domains = {n for n in names} | {
        _remote_domain_candidate(store.remotes[n]) for n in names
    }
    builtin_roots_to_probe = (
        []
        if (no_check or is_prune)
        else [d for d in DEFAULT_ROOT_DFS_DOMAINS if d not in known_domains]
    )

    if not names:
        root_statuses: List[Dict[str, Any]] = []
        if builtin_roots_to_probe:
            with ThreadPoolExecutor(max_workers=len(builtin_roots_to_probe)) as pool:
                root_statuses = list(pool.map(_probe_root_dfs_domain, builtin_roots_to_probe))
        if getattr(args, "json", False):
            print(json.dumps(root_statuses, ensure_ascii=False, indent=2))
            return 0
        print("(登録済みリモートはありません。'dfssvc start' または 'dfscli join <url>' を実行してください)")
        if root_statuses:
            print("\n既定の root dfs:")
            for rst in root_statuses:
                state_tag = "online" if rst["online"] else "unreachable"
                reg_disp = rst["registry"] or "-"
                print(f"dfs://{rst['name']}/ -> {reg_disp} {rst['path']} [{state_tag}, unregistered]")
                detail_str = _format_remote_status_details(rst)
                if detail_str:
                    print(f"  status: {detail_str}")
                print(f"  参加するには: dfscli join dfs://{rst['name']}")
        return 0

    svc_store = ServiceStore()
    running_svcs = {n for n, s in svc_store.services.items() if s.is_running()}

    if no_check:
        statuses = {
            n: {
                "online": None,
                "l2_ok": None,
                "l2_error": "",
                "role": None,
                "root_anchor": "",
                "paths_count": None,
                "pubkey_match": None,
                "dnssec": None,
                "dnssec_record": "",
                "dnssec_error": "",
            }
            for n in names
        }
        root_statuses = []
    else:
        total_jobs = len(names) + len(builtin_roots_to_probe)
        with ThreadPoolExecutor(max_workers=min(8, max(1, total_jobs))) as pool:
            futs = {n: pool.submit(_probe_remote_status, store.remotes[n]) for n in names}
            root_futs = [pool.submit(_probe_root_dfs_domain, d) for d in builtin_roots_to_probe]
            statuses = {n: futs[n].result() for n in names}
            root_statuses = [f.result() for f in root_futs]
    reachable = {n: statuses[n]["online"] for n in names}

    if getattr(args, "json", False):
        out = []
        for n in names:
            r = store.remotes[n]
            st = statuses[n]
            out.append({
                "name": n,
                "registered": True,
                "registry": r.registry,
                "path": r.path or "/",
                "read_only": bool(r.read_only),
                "online": st["online"],
                "dfssvc": n in running_svcs,
                "role": st["role"],
                "l2_ok": st["l2_ok"],
                "l2_error": st["l2_error"] or None,
                "root_anchor": st["root_anchor"] or None,
                "paths_count": st["paths_count"],
                "pubkey_match": st["pubkey_match"],
                "dnssec": st["dnssec"],
                "dnssec_record": st["dnssec_record"] or None,
                "dnssec_error": st["dnssec_error"] or None,
            })
        for rst in root_statuses:
            out.append(rst)
        print(json.dumps(out, ensure_ascii=False, indent=2))
        return 0

    if getattr(args, "prune", False):
        protected = set(svc_store.services) if not getattr(args, "all", False) else set(running_svcs)
        targets = [
            n for n in names
            if reachable[n] is False and n not in protected
        ]
        if not targets:
            skipped = [n for n in names if reachable[n] is False and n in protected]
            if skipped:
                print(
                    f"削除対象の unreachable リモートはありません（dfssvc 管理下を保護: {', '.join(skipped)}）。"
                )
            else:
                print("削除対象の unreachable リモートはありません。")
            return 0

        print("以下の unreachable リモートを削除します:")
        for n in targets:
            r = store.remotes[n]
            print(f"  - dfs://{n}/ ({r.registry} {r.path or '/'})")
        if not getattr(args, "yes", False):
            if not sys.stdin.isatty():
                raise UsageError("非対話環境で削除するには -y / --yes を付けてください")
            ans = input("削除してよろしいですか? [y/N]: ").strip().lower()
            if ans not in ("y", "yes"):
                print("中止しました")
                return 0
        for n in targets:
            store.delete(n)
        print(f"削除しました: {', '.join(targets)}")
        return 0

    first_online = None
    unreachable_count = 0
    for name in names:
        r = store.remotes[name]
        tags = []
        if reachable[name] is True:
            tags.append("online")
            if first_online is None:
                first_online = name
        elif reachable[name] is False:
            tags.append("unreachable")
            unreachable_count += 1
        tags.append("ro" if r.read_only else "rw")
        if name in running_svcs:
            tags.append("dfssvc")
        tag_str = ", ".join(tags)
        print(f"dfs://{name}/ -> {r.registry} {r.path or '/'} [{tag_str}]")
        detail_str = _format_remote_status_details(statuses[name])
        if detail_str:
            print(f"  status: {detail_str}")

    if root_statuses:
        print("\n既定の root dfs:")
        for rst in root_statuses:
            state_tag = "online" if rst["online"] else "unreachable"
            reg_disp = rst["registry"] or "-"
            print(f"dfs://{rst['name']}/ -> {reg_disp} {rst['path']} [{state_tag}, unregistered]")
            detail_str = _format_remote_status_details(rst)
            if detail_str:
                print(f"  status: {detail_str}")
            print(f"  参加するには: dfscli join dfs://{rst['name']}")

    hint_name = first_online or names[0]
    print(
        "\nScheme: dfs://<リモート名>/<パス>  (従来の <リモート名>:<パス> も利用可)\n"
        f"使い方例: dfscli ls dfs://{hint_name}/  /  dfscli copy ./file.txt dfs://{hint_name}/"
    )
    if unreachable_count:
        print("※ 到達できないリモートを削除するには: dfscli listremotes --prune")
    return 0


def normalize_registry(value: str, default_port: int = DEFAULT_REGISTRY_PORT) -> str:
    """``--registry`` を URL に正規化する。

    ``172.16.1.60`` のようにホスト名（または IP）だけでも受け、足りない部分を補う。

    - スキームが無ければ ``http://`` を付ける
    - ポートが無ければ ``default_port`` を付ける
    - 末尾の ``/`` は落とす

    ``urlparse`` で判定するので、``host:port`` と ``host`` を取り違えない。
    """
    text = (value or "").strip()
    if not text:
        raise UsageError("--registry が空です")
    if "://" not in text:
        text = "http://" + text
    from urllib.parse import urlsplit, urlunsplit

    parts = urlsplit(text)
    if not parts.hostname:
        raise UsageError(f"--registry のホスト名が読み取れません: {value!r}")
    host = parts.hostname
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    netloc = host
    if parts.port is None:
        netloc = f"{netloc}:{default_port}"
    else:
        netloc = f"{netloc}:{parts.port}"
    return urlunsplit((parts.scheme or "http", netloc, parts.path.rstrip("/"), "", ""))


def prompt_secret(
    prompt: str = "tree_secret: ",
    confirm_prompt: Optional[str] = None,
    max_tries: int = 3,
) -> str:
    """``--secret`` が無いときに、端末からエコーなしで読む（2 回聞いて照合する）。

    標準の ``getpass`` を使う。macOS には ``pinentry`` / ``dialog`` / ``whiptail``
    が無いので、外部コマンドに頼らずこれで足りる。``getpass.getpass`` は
    ``/dev/tty`` から読み、入力は画面に出ない。

    ``secret`` は打ち間違えると復号できないツリーになる（サーバに平文を置かないので
    取り返しがつかない）。そこで確認用にもう一度聞き、一致しなければやり直す。
    空文字は「未設定」として認める（あとで ``--secret`` を設定する運用があるため）。

    パイプやリダイレクトの中では端末が無いため読めないので、空を返して
    「--secret を渡す」ように促す。
    """
    import getpass
    import warnings

    # 端末が無い（パイプ・リダイレクト・テスト）ときは読まない。
    # getpass は端末を制御しようとして GetPassWarning を出すので、ここで止める。
    if not sys.stdin.isatty() or not Path("/dev/tty").exists():
        return ""

    confirm_prompt = confirm_prompt or f"{prompt}（確認のためもう一度）"

    def _ask(text: str) -> Optional[str]:
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("error", getpass.GetPassWarning)
                return getpass.getpass(text)
        except getpass.GetPassWarning:
            return None
        except (EOFError, KeyboardInterrupt):
            print("", file=sys.stderr)
            raise
        except Exception:  # noqa: BLE001 - 端末が無いときは読めない
            return None

    for attempt in range(1, max_tries + 1):
        try:
            first = _ask(prompt)
            second = _ask(confirm_prompt)
        except (EOFError, KeyboardInterrupt):
            raise
        if first is None or second is None:
            return ""  # 端末を制御できない
        if first != second:
            print(
                f"[dfscli] 入力が一致しません。もう一度入力してください"
                f"（{attempt}/{max_tries}）",
                file=sys.stderr,
            )
            continue
        if first == "":
            print("[dfscli] 空のまま進めます（あとで設定できます）", file=sys.stderr)
            return ""
        return first.strip()

    print("[dfscli] 何度も一致しませんでした。--secret で渡すか、あとで設定してください", file=sys.stderr)
    return ""


def _normalize_path_arg(value: Optional[str]) -> str:
    """``--path`` を正規化する。``/`` 始まりでも、無くても受ける。

    ``example.com/alice/notes`` も ``/example.com/alice/notes`` も同じ結果になる。
    """
    if value is None or value.strip() == "":
        return ""
    text = value.strip()
    if not text.startswith("/"):
        text = "/" + text
    return normalize_subtree_path(text)


def normalize_subtree_path(text: str) -> str:
    """余分な ``/`` や末尾 ``/`` を落とし、``..`` を弾く。"""
    parts = [p for p in text.split("/") if p not in ("", ".")]
    if not parts:
        raise UsageError("--path が空です")
    if any(p == ".." for p in parts):
        raise UsageError(f"--path に '..' は使えません: {text!r}")
    return "/" + "/".join(parts)


def _read_root_pubkey_arg(raw_value: str) -> str:
    text = str(raw_value or "").strip()
    if text.startswith("ssh-"):
        return text
    rp = Path(text).expanduser()
    if not rp.is_file():
        raise UsageError(f"--root-pubkey のファイルがありません: {rp}")
    return rp.read_text(encoding="utf-8").strip()


def cmd_config(args: argparse.Namespace) -> int:
    store = RemoteStore()
    if args.action == "create":
        dnssec_domain = getattr(args, "dnssec_domain", None)
        candidacy_urls = [
            value.strip()
            for value in (getattr(args, "candidacy_url", None) or [])
            if value.strip()
        ]
        candidacy_file = getattr(args, "candidacy_file", None)
        if dnssec_domain and (candidacy_urls or candidacy_file):
            raise UsageError("--dnssec-domain と --candidacy-url / --candidacy-file は併用できません")
        if not args.registry and not dnssec_domain and not candidacy_urls and not candidacy_file:
            raise UsageError(
                "config create には --registry、--dnssec-domain、--candidacy-url、--candidacy-file のいずれかが必要です"
            )

        discovery: Optional[Discovery] = None
        candidacy_mode = bool(candidacy_urls or candidacy_file)
        if dnssec_domain:
            try:
                discovery = discover_domain(
                    dnssec_domain,
                    record_name=getattr(args, "dnssec_name", None),
                    require_ad=not getattr(args, "dnssec_no_ad", False),
                    validate=not getattr(args, "dnssec_no_validate", False),
                )
            except DiscoveryError as e:
                raise UsageError(f"DNSSEC discovery に失敗しました: {e}") from e
            registry = discovery.primary_url
            registry_alternates = discovery.alternate_urls
            if args.registry:
                explicit = normalize_registry(args.registry, args.registry_port)
                if explicit != registry:
                    raise UsageError(
                        f"--registry ({explicit}) が DNSSEC discovery の primary "
                        f"({registry}) と一致しません"
                    )
            explicit_alts = [
                normalize_registry(value, args.registry_port)
                for value in (getattr(args, "registry_alternate", None) or [])
                if value.strip()
            ]
            if explicit_alts and explicit_alts != registry_alternates:
                raise UsageError(
                    "--registry-alternate が DNSSEC discovery の secondary 一覧と一致しません"
                )
        elif candidacy_mode:
            if not args.root_pubkey:
                raise UsageError(
                    "--candidacy-url / --candidacy-file を使うときは --root-pubkey が必須です"
                )
            expected_pub = _read_root_pubkey_arg(args.root_pubkey)
            try:
                if candidacy_file:
                    env_data = json.loads(
                        Path(candidacy_file).expanduser().read_text(encoding="utf-8")
                    )
                    discovery = verify_candidacy_envelope(env_data, expected_pub)
                else:
                    discovery = fetch_candidacy(candidacy_urls, expected_pub)
            except (OSError, json.JSONDecodeError, CandidacyError) as e:
                raise UsageError(f"立候補情報の検証に失敗しました: {e}") from e
            registry = discovery.primary_url
            registry_alternates = discovery.alternate_urls
        else:
            registry = normalize_registry(args.registry, args.registry_port)
            registry_alternates = [
                normalize_registry(value, args.registry_port)
                for value in (getattr(args, "registry_alternate", None) or [])
                if value.strip()
            ]
        ost_alternates = [
            Remote.normalize_ost(value)
            for value in (getattr(args, "ost_alternate", None) or [])
            if value.strip()
        ]
        libp2p_peers = [
            value.strip()
            for value in (getattr(args, "libp2p_peer", None) or [])
            if value.strip()
        ]

        # --key が無ければ、その場で Ed25519 の鍵を作る。
        # 書き手の鍵は dfscli が初めて使うものなので、利用者に用意させない。
        key_path: Path
        created_key = False
        if args.key:
            key_path = Path(args.key).expanduser()
            if not key_path.is_file():
                raise UsageError(f"指定された書き手鍵がありません: {key_path}")
        else:
            key_dir = Path(args.key_dir).expanduser() if args.key_dir else (
                config_dir() / "keys"
            )
            key_dir.mkdir(parents=True, exist_ok=True)
            key_path = key_dir / f"{args.name}_ed25519"
            if not key_path.is_file():
                res = subprocess.run(
                    ["ssh-keygen", "-t", "ed25519", "-N", "",
                     "-C", f"dfscli-{args.name}@{socket.gethostname()}", "-f", str(key_path)],
                    capture_output=True, text=True,
                )
                if res.returncode != 0:
                    raise UsageError(f"鍵を作れませんでした: {res.stderr.strip()}")
                restrict_to_owner(key_path)
                created_key = True

        # root アンカーの公開鍵を決める（信頼の根）。
        #   --root-pubkey FILE があれば、その中身を使う（本番はこちら）。
        #   無ければ名簿から取り、指紋を表示して記録する（TOFU。初回だけ）。
        root_pubkey = ""
        root_fingerprint = ""
        root_source = "未取得"
        if discovery is not None:
            root_pubkey = discovery.root_pubkey
            root_fingerprint = ssh_key_fingerprint(root_pubkey)
            root_source = "署名付き立候補" if candidacy_mode else "DNSSEC"
            if args.root_pubkey:
                explicit_root = _read_root_pubkey_arg(args.root_pubkey)
                if " ".join(explicit_root.split()) != " ".join(root_pubkey.split()):
                    raise UsageError(
                        f"--root-pubkey が {root_source} の root 公開鍵と一致しません"
                    )
        elif args.root_pubkey:
            root_pubkey = _read_root_pubkey_arg(args.root_pubkey)
            root_fingerprint = ssh_key_fingerprint(root_pubkey)
            root_source = f"指定（{args.root_pubkey}）"
        else:
            registry_client = cli_mod.RemoteRegistryClient(
                [registry, *registry_alternates]
            )
            info = registry_client.root_anchor_info()
            root_pubkey = (info.get("root_pubkey") or "").strip()
            if root_pubkey:
                root_fingerprint = ssh_key_fingerprint(root_pubkey)
                root_source = "名簿から取得（TOFU）"

        # --secret が無ければ端末から読む（エコーなし）。
        secret = args.secret
        secret_from_prompt = False
        if not secret and not args.no_prompt:
            secret = prompt_secret(
                f"{args.name} の tree_secret: ",
                f"{args.name} の tree_secret（確認のためもう一度）: ",
            )
            secret_from_prompt = bool(secret)

        effective_role_epoch = (
            int(discovery.epoch)
            if candidacy_mode and discovery is not None
            else int(getattr(args, "role_epoch", 1))
        )
        remote = Remote(
            name=args.name,
            registry=registry,
            registry_alternates=registry_alternates,
            key=str(key_path),
            ost=args.ost or "",
            ost_alternates=ost_alternates,
            libp2p_peers=libp2p_peers,
            libp2p_psk=getattr(args, "libp2p_psk", None) or "",
            path=_normalize_path_arg(args.path),
            secret=secret or "",
            workdir=args.workdir or "",
            epoch=int(args.epoch),
            role_epoch=effective_role_epoch,
            compression=str(getattr(args, "compression", "auto") or "auto"),
            node_name=args.node_name or args.name,
            root_pubkey=root_pubkey,
            root_fingerprint=root_fingerprint,
        )
        store.set(remote)
        print(f"[dfscli] リモート {remote.name!r} を保存しました: {store.path}")
        print(f"  registry    : {remote.registry}")
        if remote.registry_alternates:
            print(f"  代替名簿    : {', '.join(remote.registry_alternates)}")
        if created_key:
            print(f"  書き手の鍵  : {key_path}（作った。OpenSSH 形式の Ed25519）")
        else:
            print(f"  書き手の鍵  : {key_path}")
        print(f"  作業ディレクトリ: {remote.resolved_workdir()}")
        if remote.ost:
            print(f"  L3 OST      : {remote.ost}")
        else:
            print("  L3 OST      : （未指定。使うときに L2 のロケータから解決します）")
        if remote.ost_alternates:
            print(f"  複製 OST    : {', '.join(remote.ost_alternates)}")
        if remote.libp2p_peers:
            print(f"  libp2p peer : {', '.join(remote.libp2p_peers)}")
        if remote.path:
            print(f"  サブツリー  : {remote.path}")
        else:
            print("  サブツリー  : （未指定。使うときに L2 で書き手鍵から探します）")
        if remote.secret:
            how = "端末から読みました" if secret_from_prompt else "指定どおり"
            print(f"  tree_secret : *** （{how}）")
        else:
            print("  tree_secret : （未指定。書く前に設定してください）")
        if root_pubkey:
            print(f"  root アンカー: {root_fingerprint} （{root_source}）")
            print("                 これ以降この指紋だけを信頼します（違う値を返す名簿は拒否）")
        else:
            print("  root アンカー: （取得できませんでした。--root-pubkey で指定してください）")
        return 0

    if args.action == "delete":
        if store.delete(args.name):
            print(f"[dfscli] リモート {args.name!r} を削除しました")
            return 0
        raise UsageError(f"Unknown remote {args.name!r}")

    if args.action == "show":
        r = store.get(args.name)
        for key in ("name", "registry", "registry_alternates", "ost", "ost_alternates",
                    "libp2p_peers", "libp2p_psk", "path", "key", "workdir", "epoch",
                    "role_epoch", "compression", "node_name", "root_fingerprint"):
            value = getattr(r, key)
            if key in ("secret", "libp2p_psk"):
                value = "***"
            if key == "workdir":
                value = str(r.resolved_workdir())
            print(f"{key:{18}}: {value}")
        # root 公開鍵そのものは長いので、指紋だけ出す（--json を足す余地はある）
        if r.root_pubkey:
            algo = r.root_pubkey.split()[0] if r.root_pubkey.split() else "?"
            print(f"{'root_pubkey':{18}}: {algo} ...（指紋は上に表示）")
        else:
            print(f"{'root_pubkey':{18}}: （未取得）")
        return 0

    if args.action == "list":
        return cmd_listremotes(args)

    raise UsageError(f"Unknown config action: {args.action}")


def cmd_discover(args: argparse.Namespace) -> int:
    """DNSSEC の discovery レコードを表示する（設定は変更しない）。"""
    try:
        discovery = discover_domain(
            args.domain,
            record_name=args.dnssec_name,
            require_ad=not args.dnssec_no_ad,
            validate=not getattr(args, "dnssec_no_validate", False),
        )
    except DiscoveryError as e:
        raise UsageError(f"DNSSEC discovery に失敗しました: {e}") from e
    if args.json:
        print(json.dumps(discovery.raw, indent=2, sort_keys=True, ensure_ascii=False))
        return 0
    print(f"domain      : {discovery.domain}")
    print(f"root_anchor : {discovery.root_anchor}")
    print(f"root_pubkey : {ssh_key_fingerprint(discovery.root_pubkey)}")
    print(f"epoch       : {discovery.epoch}")
    print(f"ttl         : {discovery.ttl}")
    for row in discovery.registries:
        print(f"{row.role:10}: {row.url}")
    return 0


def cmd_candidacy(args: argparse.Namespace) -> int:
    """小規模運用向けの署名付き立候補レコードを作成・取得する。"""
    if args.action == "create":
        if not args.root_key or not args.primary:
            raise UsageError("candidacy create には --root-key と --primary が必要です")
        root_pub = _read_root_pubkey_arg(args.root_pubkey)
        registries: List[Dict[str, str]] = [
            {"role": "primary", "url": normalize_registry(args.primary, args.registry_port)}
        ]
        for sec in (args.secondary or []):
            if sec.strip():
                registries.append(
                    {"role": "secondary", "url": normalize_registry(sec, args.registry_port)}
                )
        try:
            envelope = create_candidacy_envelope(
                args.root_key,
                args.root_anchor,
                root_pub,
                registries,
                epoch=int(args.epoch),
                ttl_days=int(args.ttl_days),
            )
        except (CandidacyError, ValueError) as e:
            raise UsageError(f"立候補レコードの生成に失敗しました: {e}") from e
        if args.out:
            out_path = Path(args.out).expanduser()
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(
                json.dumps(envelope, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
        for reg_url in (args.announce or []):
            if reg_url.strip():
                client = cli_mod.RemoteRegistryClient(normalize_registry(reg_url, args.registry_port))
                client.announce_candidacy(envelope)
        if args.json or not args.out:
            print(json.dumps(envelope, indent=2, sort_keys=True, ensure_ascii=False))
        return 0

    if args.action == "discover":
        root_pub = _read_root_pubkey_arg(args.root_pubkey)
        urls = [
            normalize_registry(u, args.registry_port)
            for u in (args.url or [])
            if u.strip()
        ]
        try:
            discovery = fetch_candidacy(
                urls,
                root_pub,
                expected_root_anchor=args.root_anchor,
                min_epoch=args.min_epoch,
            )
        except CandidacyError as e:
            raise UsageError(f"立候補情報の取得・検証に失敗しました: {e}") from e
        if args.json:
            print(json.dumps(discovery.raw, indent=2, sort_keys=True, ensure_ascii=False))
            return 0
        print(f"root_anchor : {discovery.root_anchor}")
        print(f"root_pubkey : {ssh_key_fingerprint(discovery.root_pubkey)}")
        print(f"epoch       : {discovery.epoch}")
        print(f"ttl         : {discovery.ttl}")
        for row in discovery.registries:
            print(f"{row.role:10}: {row.url}")
        return 0

    raise UsageError(f"Unknown candidacy action: {args.action}")


def _archive_registry_context(
    store: RemoteStore,
    remote: Remote,
    version: Optional[int],
) -> Tuple[str, Dict[str, Any], Dict[str, Any]]:
    """ローカル設定を起点に、L2公開descriptorと対応L4 headを検証して返す。"""
    registry = cli_mod.RemoteRegistryClient(remote.registry_urls())
    path = resolve_path(remote, registry)
    if not remote.root_pubkey:
        info = registry.root_anchor_info()
        root_pubkey = str(info.get("root_pubkey", "") or "").strip()
        if not root_pubkey:
            raise UsageError(
                f"Registry {remote.registry} did not provide a root public key; "
                "pass --root-pubkey when creating the remote"
            )
        remote.root_pubkey = root_pubkey
        remote.root_fingerprint = ssh_key_fingerprint(root_pubkey)
        store.set(remote)

    entries = registry.archives(path, version=version)
    if not entries:
        label = f"v{version}" if version is not None else "latest"
        raise UsageError(f"No published archive descriptor for {path!r} ({label})")

    pubkey = public_key_of(Path(remote.key).expanduser()) if remote.key else ""
    verifier = L4LogClient(
        path,
        remote.key,
        pubkey,
        pin_file=None,
        root_pubkey=remote.root_pubkey,
    )
    candidates = sorted(
        (
            envelope
            for envelope in entries
            if isinstance(envelope, dict)
            and isinstance(envelope.get("payload"), dict)
            and isinstance(envelope["payload"].get("version"), int)
            and (
                version is None
                or int(envelope["payload"]["version"]) == int(version)
            )
        ),
        key=lambda envelope: int(envelope["payload"]["version"]),
        reverse=True,
    )
    if not candidates:
        raise UsageError("Registry returned only malformed archive descriptors")

    last_error: Optional[BaseException] = None
    for selected in candidates:
        selected_version = int(selected["payload"]["version"])
        try:
            head, delegation, _locator = verifier.resolve_verified(
                registry, version=selected_version
            )
            leaf = verify_delegation_chain(
                root_anchor_path=str(delegation.get("root_anchor") or ""),
                root_anchor_pubkey=remote.root_pubkey,
                chain=list(delegation.get("chain") or []),
                now=int(head["payload"]["timestamp"]),
                requested_path=path,
            )
            verify_archive_descriptor(
                selected,
                path,
                str(leaf["writer"]),
                head_log=head,
            )
            return path, selected, head
        except ServiceUnavailableError:
            raise
        except Exception as e:  # noqa: BLE001 - 名簿の候補ごとに検証して不正候補を読み飛ばす
            last_error = e
    raise UsageError(
        f"すべてのpublished archive descriptorを検証できません: {last_error}"
    )


def cmd_archive(args: argparse.Namespace) -> int:
    """版単位の archive bundle / torrent を作成・公開・取得・復元する。"""
    if args.action == "create":
        store = RemoteStore()
        name, _sub = split_remote_spec(args.source, args.remote_name)
        remote = store.get(name)
        node = open_remote(remote, create=False)
        out = (
            Path(args.out).expanduser()
            if args.out
            else Path.cwd() / f"dfs-archive-{remote.name}-{int(time.time())}"
        )
        try:
            result = create_archive(
                node, out, announce=args.announce, version=args.version
            )
        except ArchiveError as e:
            raise UsageError(f"archive create に失敗しました: {e}") from e
        print(f"archive     : {result.bundle}")
        print(f"torrent     : {result.torrent}")
        print(f"descriptor  : {result.descriptor}")
        print(f"infohash    : {result.infohash}")
        print(f"version     : v{result.version}")
        print(f"chunks      : {result.chunk_count}")
        print(
            f"magnet      : magnet:?xt=urn:btih:{result.infohash}"
            f"&dn={result.bundle.name}"
        )
        if args.publish:
            registry = cli_mod.RemoteRegistryClient(remote.registry_urls())
            registry.publish_archive(
                result.descriptor_envelope,
                role_epoch=int(remote.role_epoch),
            )
            print(
                f"published   : {remote.registry} "
                f"{remote.path or node.sub_path} v{result.version}"
            )
        return 0

    if args.action == "catalog":
        try:
            rows = catalog(Path(args.source).expanduser())
        except ArchiveError as e:
            raise UsageError(f"archive catalog に失敗しました: {e}") from e
        for row in rows:
            print(
                f"{row.get('path', '?')} v{row.get('version', '?')} "
                f"{row.get('infohash', '?')} {row.get('bundle', '')}"
            )
        return 0

    if args.action == "publish":
        if not args.remote_name:
            raise UsageError("archive publish には --remote NAME が必要です")
        store = RemoteStore()
        remote = store.get(args.remote_name)
        bundle = Path(args.source).expanduser()
        descriptor_path = bundle.with_suffix(".archive.json")
        try:
            descriptor = json.loads(descriptor_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            raise UsageError(
                f"archive descriptor を読めません: {descriptor_path}: {e}"
            ) from e
        envelope = (
            descriptor.get("descriptor_envelope")
            if isinstance(descriptor, dict)
            else None
        )
        if not isinstance(envelope, dict):
            raise UsageError(
                "この bundle には署名済みdescriptorがありません。作成し直してください"
            )
        registry = cli_mod.RemoteRegistryClient(remote.registry_urls())
        verified = registry.publish_archive(
            envelope, role_epoch=int(remote.role_epoch)
        )
        print(
            f"published   : {remote.registry} "
            f"{verified['path']} v{verified['version']}"
        )
        return 0

    bundle = Path(args.source).expanduser()
    if args.action == "verify":
        try:
            meta = verify_bundle(bundle)
        except ArchiveError as e:
            raise UsageError(f"archive verify に失敗しました: {e}") from e
        print(f"archive     : {bundle}")
        print(f"version     : v{meta['version']}")
        print(f"chunks      : {len(meta['chunks'])}")
        print("signatures  : OK")
        return 0

    if args.action == "extract":
        if not args.dest:
            raise UsageError("archive extract には出力先が必要です")
        secret = args.secret
        if not secret and not args.no_prompt:
            secret = prompt_secret("tree_secret: ", "tree_secret（確認）: ")
        if not secret:
            raise UsageError("archive extract には --secret が必要です")
        try:
            out = extract_bundle(bundle, Path(args.dest).expanduser(), secret)
        except ArchiveError as e:
            raise UsageError(f"archive extract に失敗しました: {e}") from e
        print(f"extracted   : {out}")
        return 0

    if args.action == "fetch":
        store = RemoteStore()
        name, _sub = split_remote_spec(args.source, args.remote_name)
        remote = store.get(name)
        try:
            path, descriptor, _head = _archive_registry_context(
                store, remote, args.version
            )
        except ArchiveError as e:
            raise UsageError(
                f"archive descriptor の検証に失敗しました: {e}"
            ) from e
        payload = descriptor["payload"]
        version = int(payload["version"])
        out = (
            Path(args.out).expanduser()
            if args.out
            else Path.cwd() / f"dfs-fetch-{remote.name}-v{version}"
        )
        if int(args.torrent_timeout) <= 0:
            raise UsageError("--torrent-timeout は正の秒数にしてください")
        magnet = magnet_for_descriptor(payload)
        print(
            f"[dfscli] archive fetch: {path} v{version} "
            f"infohash={payload['infohash'][:12]}..."
        )
        try:
            download_torrent(
                magnet,
                out,
                torrent_client=args.torrent_client,
                timeout=int(args.torrent_timeout),
            )
            bundle = locate_downloaded_bundle(out, descriptor)
            meta = verify_bundle(bundle)
        except ArchiveError as e:
            raise UsageError(f"archive fetch に失敗しました: {e}") from e
        print(f"archive     : {bundle}")
        print(f"verified    : v{meta['version']} ({len(meta['chunks'])} chunks)")
        if args.dest:
            secret = args.secret or remote.secret
            if not secret and not args.no_prompt:
                secret = prompt_secret("tree_secret: ", "tree_secret（確認）: ")
            if not secret:
                raise UsageError("archive fetch --dest には tree_secret が必要です")
            try:
                restored = extract_bundle(
                    bundle, Path(args.dest).expanduser(), secret
                )
            except ArchiveError as e:
                raise UsageError(
                    f"archive fetch の復号に失敗しました: {e}"
                ) from e
            print(f"extracted   : {restored}")
        return 0

    raise UsageError(f"unknown archive action: {args.action}")


def cmd_history(args: argparse.Namespace) -> int:
    """L2 の署名済み L4 ログ履歴を表示する。"""
    store = RemoteStore()
    name, sub = split_remote_spec(args.remote, args.remote_name)
    remote = _resolve_remote(store, name)
    path = ("/" + sub.lstrip("/")) if sub else remote.path
    if not path:
        raise UsageError(
            "history にはパスが必要です（例: dfscli history remote:/example.com/alice）"
        )
    client = cli_mod.RemoteRegistryClient(remote.registry_urls())
    try:
        rows = client.history(path, limit=args.limit)
    except Exception as e:  # noqa: BLE001
        raise UsageError(f"history の取得に失敗しました: {e}") from e
    for row in rows:
        print(
            f"v{row.get('version', '?'):<6} {row.get('timestamp', '?')} "
            f"{str(row.get('entry_hash', ''))[:16]}"
        )
    return 0


def cmd_ls(args: argparse.Namespace) -> int:
    store = RemoteStore()
    name, sub = split_remote_spec(args.remote, args.remote_name)
    node = open_remote(_resolve_remote(store, name), create=True)
    for e in _rel_entries(node, _norm_prefix(sub)):
        if e["type"] == "dir":
            print(e["rel"] + "/")
        else:
            print(e["rel"])
    return 0


def cmd_lsd(args: argparse.Namespace) -> int:
    """リモートの直下にあるディレクトリだけを一覧する。"""
    store = RemoteStore()
    name, sub = split_remote_spec(args.remote, args.remote_name)
    node = open_remote(_resolve_remote(store, name), create=True)
    for e in _rel_entries(node, _norm_prefix(sub)):
        if e["type"] == "dir":
            print(e["rel"] + "/")
    return 0


def cmd_lsl(args: argparse.Namespace) -> int:
    store = RemoteStore()
    name, sub = split_remote_spec(args.remote, args.remote_name)
    node = open_remote(_resolve_remote(store, name), create=True)
    for e in _rel_entries(node, _norm_prefix(sub)):
        rel = e["rel"] + ("/" if e["type"] == "dir" else "")
        size = e.get("size", 0)
        print(f"{size:>12}  {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())}  {rel}")
    return 0


def cmd_lsjson(args: argparse.Namespace) -> int:
    store = RemoteStore()
    name, sub = split_remote_spec(args.remote, args.remote_name)
    node = open_remote(_resolve_remote(store, name), create=True)
    rows = []
    for e in _all_entries(node, _norm_prefix(sub)):
        row = {
            "Path": e["path"],
            "Name": e["path"].rsplit("/", 1)[-1],
            "Size": int(e.get("size", 0)),
            "IsDir": e["type"] == "dir",
            "Type": e["type"],
            "WireId": e.get("wire_id", ""),
            "Chunks": e.get("chunks", []),
        }
        rows.append(row)
    print(json.dumps(rows, ensure_ascii=False, indent=2))
    return 0


def cmd_size(args: argparse.Namespace) -> int:
    store = RemoteStore()
    name, sub = split_remote_spec(args.remote, args.remote_name)
    node = open_remote(_resolve_remote(store, name), create=True)
    files = [e for e in _all_entries(node, _norm_prefix(sub)) if e["type"] == "file"]
    total = sum(int(e.get("size", 0)) for e in files)
    print(f"Total objects: {len(files)}")
    print(f"Total size: {total} ({_human_size(total)})")
    unique_chunks = {
        chunk["wire_id"]
        for entry in files
        for chunk in (entry.get("chunks") or [entry])
    }
    print(f"Unique chunks (wire_id): {len(unique_chunks)}")
    return 0


def cmd_cat(args: argparse.Namespace) -> int:
    store = RemoteStore()
    name, sub = split_remote_spec(args.remote, args.remote_name)
    if not sub:
        raise UsageError("cat にはファイルのパスが必要です（例: remote:dir/file.txt）")
    node = open_remote(_resolve_remote(store, name), create=True)
    try:
        data = node.read_remote(sub)
    except (FileNotFoundError, IsADirectoryError, NotADirectoryError) as e:
        raise UsageError(str(e)) from e
    sys.stdout.buffer.write(data)
    sys.stdout.buffer.flush()
    return 0


def _print_plan(action: str, items: List[str], dry_run: bool) -> None:
    head = "[dfscli] " + ("(dry-run) " if dry_run else "")
    print(f"{head}{action}: {len(items)} 件", file=sys.stderr)
    if dry_run:
        for i in items[:40]:
            print(f"  {i}", file=sys.stderr)
        if len(items) > 40:
            print(f"  ... ほか {len(items) - 40} 件", file=sys.stderr)


def cmd_copy(args: argparse.Namespace) -> int:
    """ローカルのファイルをリモートへ足す（リモートにしかないものは残す）。

    変更が無ければ版を作らない（rclone と同じく冪等）。判定は大きさを先に見て、
    ``--checksum size|crc32|sha1|plain_id`` で変更検出方法を選ぶ。
    """
    store = RemoteStore()
    name, sub = split_remote_spec(args.dest, args.remote_name)
    remote = store.get(name)
    _require_writable(remote)
    prefix = _norm_prefix(sub)
    path_filter = _path_filter(args)
    local = _filter_local(_collect_local(Path(args.src)), path_filter)
    if not local:
        print("[dfscli] コピーするファイルがありません", file=sys.stderr)
        return 0

    node = open_remote(remote, create=True)
    refresh_cache(node)
    writes, _deletes, unchanged = plan_changes(
        node, prefix, local, checksum=args.checksum, path_filter=path_filter
    )

    plan = [
        f"{kind:6} {src} -> {remote.name}:{path}"
        for path, src, kind in writes
    ] + [f"same   {remote.name}:{path}" for path in unchanged][:0]
    _print_plan("copy", plan, args.dry_run)
    if args.dry_run:
        return 0
    if not writes:
        print(
            f"[dfscli] copy: 変更なし（{len(unchanged)} ファイルが同じ）。新しい版は作りません",
            file=sys.stderr,
        )
        return 0

    apply_writes(node, writes)
    t0 = time.perf_counter()
    log_env, sent = _push(node, remote)
    ms = (time.perf_counter() - t0) * 1000.0
    print(
        f"[dfscli] copy OK -> v{log_env['payload']['version']} "
        f"| 追加/更新 {len(writes)} 件（同じ {len(unchanged)} 件） | sent={sent} B | {ms:.1f} ms"
    )
    return 0


def cmd_copyto(args: argparse.Namespace) -> int:
    """ローカルの 1 ファイルを、リモートの指定パスへそのまま置く。"""
    store = RemoteStore()
    name, sub = split_remote_spec(args.dest, args.remote_name)
    remote = store.get(name)
    _require_writable(remote)
    if not sub:
        raise UsageError("copyto の宛先にはファイル名が必要です（例: remote:dir/name.txt）")
    src = Path(args.src).expanduser()
    if not src.is_file():
        raise UsageError(f"Local file does not exist: {src}")

    _print_plan("copyto", [f"{src} -> {remote.name}:{sub}"], args.dry_run)
    if args.dry_run:
        return 0

    node = open_remote(remote, create=True)
    refresh_cache(node)
    writes, _deletes, unchanged = plan_changes(node, "", {sub: src}, checksum=args.checksum)
    if not writes:
        print(
            f"[dfscli] copyto: 変更なし（{sub} は同じ）。新しい版は作りません",
            file=sys.stderr,
        )
        return 0
    apply_writes(node, writes)

    log_env, sent = _push(node, remote)
    print(
        f"[dfscli] copyto OK -> v{log_env['payload']['version']} "
        f"| {sub} | sent={sent} B"
    )
    return 0


def cmd_import_tar(args: argparse.Namespace) -> int:
    """tar / tar.gz / tar.xz / tar.bz2 をリモートへインポートする。

    archive 内の通常ファイルとディレクトリだけを、1 版として反映する。
    既存のリモートにしかないファイルは削除しない（copy と同じ追加・更新）。
    """
    if args.strip_components < 0:
        raise UsageError("--strip-components は 0 以上にしてください")
    store = RemoteStore()
    name, sub = split_remote_spec(args.dest, args.remote_name)
    remote = store.get(name)
    _require_writable(remote)
    prefix = _norm_prefix(sub)
    archive = Path(args.archive).expanduser()
    if not archive.is_file():
        raise UsageError(f"tar ファイルがありません: {archive}")

    with tempfile.TemporaryDirectory(prefix="dfs_import_tar_") as tmp:
        staging = Path(tmp) / "extract"
        staging.mkdir()
        files, dirs = _extract_tar_safely(
            archive, staging, args.strip_components
        )
        if not files and not dirs:
            print(f"[dfscli] import_tar: インポートするものがありません: {archive}")
            return 0

        node = open_remote(remote, create=True)
        refresh_cache(node)
        remote_files = _remote_file_paths(node)
        remote_dirs = _remote_dir_paths(node)
        target_files = {_join_prefix(prefix, rel) for rel in files}
        target_dirs = {_join_prefix(prefix, rel) for rel in dirs}
        file_dir_conflicts = sorted(target_files & remote_dirs)
        dir_file_conflicts = sorted(target_dirs & remote_files)
        if file_dir_conflicts or dir_file_conflicts:
            detail = ", ".join(file_dir_conflicts + dir_file_conflicts[:5])
            raise UsageError(f"ファイルとディレクトリが衝突します: {detail}")

        # staging を再走査せず、安全展開で確定したファイルだけを使う。
        local = files
        writes, _deletes, unchanged = plan_changes(
            node, prefix, local, checksum="plain_id"
        )
        new_dirs = sorted(
            rel for rel in dirs
            if _join_prefix(prefix, rel) not in remote_dirs
        )
        plan = (
            [f"{kind:6} {name}:{path}" for path, _src, kind in writes]
            + [f"mkdir  {name}:{_join_prefix(prefix, rel)}/" for rel in new_dirs]
        )
        _print_plan("import_tar", plan, args.dry_run)
        if args.dry_run:
            return 0
        if not writes and not new_dirs:
            print(
                f"[dfscli] import_tar: 変更なし（{len(unchanged)} ファイルが同じ）。"
                "新しい版は作りません",
                file=sys.stderr,
            )
            return 0

        apply_writes(node, writes)
        for rel in new_dirs:
            target = _tree_path(node, _join_prefix(prefix, rel))
            try:
                target.mkdir(parents=True, exist_ok=True)
            except OSError as e:
                raise UsageError(f"ディレクトリを作成できません: {rel}: {e}") from e

        log_env, sent = _push(node, remote)
        print(
            f"[dfscli] import_tar OK -> v{log_env['payload']['version']} "
            f"| files={len(writes)} dirs={len(new_dirs)} same={len(unchanged)} "
            f"| sent={sent} B"
        )
    return 0


def _configure_fuse_library(explicit: Optional[str] = None) -> None:
    """macOS では fuse-t を必須にし、fusepy の macFUSE フォールバックを防ぐ。"""
    if explicit:
        os.environ["FUSE_LIBRARY_PATH"] = str(Path(explicit).expanduser())
        return
    if sys.platform != "darwin":
        return
    env_path = os.environ.get("FUSE_LIBRARY_PATH", "")
    if env_path and "fuse-t" in Path(env_path).name.lower():
        return
    candidates = (
        Path("/usr/local/lib/libfuse-t.dylib"),
        *sorted(Path("/Library/Application Support/fuse-t/lib").glob("libfuse-t-*.dylib")),
    )
    for path in candidates:
        if path.is_file():
            os.environ["FUSE_LIBRARY_PATH"] = str(path)
            return
    raise UsageError(
        "マウント機能には fuse-t が必要です。"
        "macOS では "
        "`brew install macos-fuse-t/homebrew-cask/fuse-t` "
        "でインストールしてください"
    )


def cmd_mount(args: argparse.Namespace) -> int:
    """リモートのサブツリーを fuse-t / fusepy でローカルにマウントする。

    作業ツリーを FUSE に公開し、flush / fsync / unmount 時に DFS へ push する。
    """
    store = RemoteStore()
    name, sub = split_remote_spec(args.remote, args.remote_name)
    remote = store.get(name)
    mountpoint = Path(args.mountpoint).expanduser()
    if not mountpoint.exists():
        mountpoint.mkdir(parents=True, exist_ok=True)
    if not mountpoint.is_dir():
        raise UsageError(f"マウントポイントがディレクトリではありません: {mountpoint}")

    node = open_remote(remote, create=True)
    refresh_cache(node)

    def flush_to_dfs() -> None:
        log_env, sent = _push(node, remote)
        print(
            f"[dfscli] mount flush -> v{log_env['payload']['version']} "
            f"| sent={sent} B",
            file=sys.stderr,
        )

    try:
        from .fuse_mount import LocalTreeFuse
    except ImportError as e:  # pragma: no cover - 依存環境
        raise UsageError(
            "mount には fusepy と fuse-t / FUSE が必要です "
            "(pip install 'dfs[fuse]')"
        ) from e

    _configure_fuse_library(args.fuse_library)
    try:
        from fuse import FUSE
    except (ImportError, OSError) as e:
        raise UsageError(
            "fuse-t / libfuse を読み込めません。"
            "macOS では FUSE-T をインストールし、必要なら --fuse-library を指定してください"
        ) from e

    effective_read_only = bool(args.read_only or remote.read_only)
    operations = LocalTreeFuse(
        node.clayfs.work_tree,
        flush_to_dfs,
        read_only=effective_read_only,
        sync_delay=0.5,
    )
    options = {
        "fsname": f"dfs:{name}:{node.sub_path}",
        "volname": f"dfs-{name}",
        "foreground": True,
        "nothreads": True,
    }
    if args.allow_other:
        options["allow_other"] = True
    if effective_read_only:
        options["ro"] = True
    if args.debug:
        options["debug"] = True
    try:
        FUSE(operations, str(mountpoint), **options)
    except KeyboardInterrupt:
        print("\n[dfscli] mount を終了します", file=sys.stderr)
    finally:
        operations.destroy("/")
    return 0


def cmd_mv(args: argparse.Namespace) -> int:
    """リモート内でファイルまたはディレクトリを移動・改名する。

    移動は作業ツリー上の rename として行い、最後に 1 版だけ push する。宛先が
    既に存在する場合は既定で拒否する。ファイル同士の置換だけは ``--overwrite``
    で許可する（ディレクトリの merge は行わない）。
    """
    store = RemoteStore()
    src_name, src_sub = split_remote_spec(args.src, args.remote_name)
    dst_name, dst_sub = split_remote_spec(args.dst, args.remote_name)
    if src_name != dst_name:
        raise UsageError("mv は同じリモート内だけで使えます（別リモート間は copy + rm）")

    src = _norm_prefix(src_sub)
    dst = _norm_prefix(dst_sub)
    if not src or not dst:
        raise UsageError("mv には移動元と移動先のパスが必要です（例: remote:old remote:new）")
    if src == dst:
        print(f"[dfscli] mv: 移動元と移動先が同じです（{src_name}:{src}）", file=sys.stderr)
        return 0

    remote = store.get(src_name)
    _require_writable(remote)
    node = open_remote(remote, create=True)
    refresh_cache(node)

    files = _remote_file_paths(node)
    dirs = _remote_dir_paths(node)
    if src in files:
        src_kind = "file"
    elif src in dirs:
        src_kind = "dir"
    else:
        raise UsageError(f"{src_name}:{src} は見つかりません")

    if src_kind == "dir" and dst.startswith(src + "/"):
        raise UsageError("ディレクトリを自分自身の下へ移動することはできません")

    dst_kind = "file" if dst in files else ("dir" if dst in dirs else None)
    if dst_kind is not None:
        if not (src_kind == "file" and dst_kind == "file" and args.overwrite):
            raise UsageError(
                f"移動先 {src_name}:{dst} は既に存在します"
                + ("（ファイル同士なら --overwrite で置換できます）" if src_kind == "file" else "")
            )

    _print_plan(
        "mv",
        [f"{src_name}:{src}{'/' if src_kind == 'dir' else ''} -> "
         f"{src_name}:{dst}{'/' if src_kind == 'dir' else ''}"],
        args.dry_run,
    )
    if args.dry_run:
        return 0

    src_path = _tree_path(node, src)
    dst_path = _tree_path(node, dst)
    try:
        dst_path.parent.mkdir(parents=True, exist_ok=True)
        if dst_kind == "file":
            os.replace(src_path, dst_path)
        else:
            src_path.rename(dst_path)
    except OSError as e:
        raise UsageError(f"移動に失敗しました: {e}") from e

    log_env, sent = _push(node, remote)
    print(
        f"[dfscli] mv OK -> v{log_env['payload']['version']} "
        f"| {src} -> {dst} | sent={sent} B"
    )
    return 0


def cmd_sync(args: argparse.Namespace) -> int:
    """リモートの指定パスを、ローカルディレクトリと完全に一致させる。

    既定では追加と更新だけを行う。``--delete`` を付けると、リモートにしかない
    ものも消す。変更が無ければ版を作らない。
    """
    store = RemoteStore()
    name, sub = split_remote_spec(args.dest, args.remote_name)
    remote = store.get(name)
    _require_writable(remote)
    prefix = _norm_prefix(sub)
    path_filter = _path_filter(args)
    local = _filter_local(_collect_local(Path(args.src)), path_filter)

    node = open_remote(remote, create=True)
    refresh_cache(node)
    writes, deletes, unchanged = plan_changes(
        node, prefix, local, checksum=args.checksum, path_filter=path_filter
    )
    if not args.delete:
        deletes = []

    plan = ([f"add    {remote.name}:{path}" for path, _src, kind in writes if kind == "add"]
            + [f"update {remote.name}:{path}" for path, _src, kind in writes if kind == "update"]
            + [f"delete {remote.name}:{path}" for path in deletes])
    if not plan:
        print(
            f"[dfscli] sync: 変更なし（{len(unchanged)} ファイルが同じ）。新しい版は作りません",
            file=sys.stderr,
        )
        return 0
    _print_plan("sync", plan, args.dry_run)
    if args.dry_run:
        return 0

    apply_writes(node, writes)
    if deletes:
        apply_deletes(node, deletes)

    log_env, sent = _push(node, remote)
    n_add = sum(1 for _p, _s, k in writes if k == "add")
    n_upd = sum(1 for _p, _s, k in writes if k == "update")
    print(
        f"[dfscli] sync OK -> v{log_env['payload']['version']} "
        f"| add={n_add} update={n_upd} delete={len(deletes)} "
        f"| same={len(unchanged)} | sent={sent} B"
    )
    return 0


def _pull_once(
    node: DFSNode,
    remote: Remote,
    prefix: str,
    dest: Path,
    path_filter: Any,
    *,
    force: bool = False,
) -> Tuple[int, int]:
    version = refresh_cache(node, force=force)
    work_root = node.clayfs.work_tree.resolve(strict=False)
    src_root = work_root if not prefix else work_root / prefix
    try:
        src_root.resolve(strict=False).relative_to(work_root)
    except ValueError as e:
        raise UsageError(f"Remote path escapes the work tree: {prefix!r}") from e
    if not src_root.exists():
        raise UsageError(f"Remote path does not exist: {remote.name}:{prefix}")

    dest.mkdir(parents=True, exist_ok=True)
    count = 0
    for item in sorted(src_root.rglob("*")):
        rel = item.relative_to(src_root)
        if any(part in (".clayfs",) for part in rel.parts):
            continue
        if item.name in (".DS_Store",) or item.name.startswith("._"):
            continue
        if item.is_symlink():
            print(f"[dfscli] warning: skipping symlink: {item}", file=sys.stderr)
            continue
        rel_text = rel.as_posix()
        if not path_filter.allows(rel_text):
            continue
        try:
            target = safe_target(dest, rel_text, create_parents=True)
        except UnsafePathError as e:
            raise UsageError(f"Invalid pull destination: {rel_text!r} ({e})") from e
        if item.is_dir():
            target.mkdir(parents=True, exist_ok=True)
            continue
        try:
            copyfile_no_follow(item, target)
        except UnsafePathError as e:
            raise UsageError(f"Refusing symlink write: {rel_text!r} ({e})") from e
        count += 1
    return version, count


def cmd_pull(args: argparse.Namespace) -> int:
    """リモートの指定パスを、ローカルディレクトリへ取り出す。"""
    store = RemoteStore()
    name, sub = split_remote_spec(args.src, args.remote_name)
    remote = store.get(name)
    prefix = _norm_prefix(sub)
    node = open_remote(remote, create=True)
    path_filter = _path_filter(args)
    dest = Path(args.dest).expanduser()

    version, count = _pull_once(
        node, remote, prefix, dest, path_filter, force=args.force
    )
    print(f"[dfscli] pull OK <- v{version} | {count} ファイル -> {dest}")
    if not getattr(args, "watch", False):
        return 0

    poll = max(1, int(getattr(args, "poll", 30) or 30))
    last_version = version
    try:
        while True:
            time.sleep(poll)
            try:
                latest = node.remote_version()
            except Exception as e:  # noqa: BLE001 - 一時的な通信断では終了しない
                print(f"[dfscli] watch poll failed: {e}", file=sys.stderr)
                continue
            if latest > last_version:
                version, count = _pull_once(
                    node, remote, prefix, dest, path_filter, force=False
                )
                last_version = version
                print(f"[dfscli] pull OK <- v{version} | {count} ファイル -> {dest}")
    except KeyboardInterrupt:
        print("\n[dfscli] watch を終了します", file=sys.stderr)
    return 0


def _create_invite_token(args: argparse.Namespace, remote: Remote) -> str:
    """リモート定義から招待トークン (`dfs-ro-v1:...` / `dfs-rw-v1:...`) を生成する。"""
    if not remote.root_pubkey:
        raise UsageError(
            f"Remote {remote.name!r} に root_pubkey がありません。TOFU を避けるため必須です"
        )
    remote = _ensure_remote_secret(remote)
    write_path = getattr(args, "write_path", None)
    registries = list(remote.registry_urls())
    ost_primary = remote.ost
    ost_alts = list(remote.ost_alternates)
    try:
        info = cli_mod.RemoteRegistryClient(registries).ost_info()
        if not ost_primary and info.get("endpoint"):
            ost_primary = Remote.normalize_ost(str(info["endpoint"]))
        raw_relays = list(info.get("relay_endpoints") or [])
        if info.get("relay_endpoint"):
            raw_relays.insert(0, info["relay_endpoint"])
        for raw_ep in raw_relays:
            relay_ep = str(raw_ep or "").strip().rstrip("/")
            if not relay_ep:
                continue
            if relay_ep not in registries:
                registries.append(relay_ep)
            if relay_ep != ost_primary and relay_ep not in ost_alts:
                ost_alts.append(relay_ep)
        for alt in info.get("alternates") or []:
            norm_alt = Remote.normalize_ost(str(alt))
            if norm_alt and norm_alt != ost_primary and norm_alt not in ost_alts:
                ost_alts.append(norm_alt)
    except Exception:
        pass
    try:
        if write_path:
            root_key_arg = getattr(args, "root_key", None)
            if not root_key_arg:
                raise UsageError(
                    "--write-path を使うときは L1 委譲署名用の --root-key が必須です"
                )
            root_key_path = Path(root_key_arg).expanduser()
            if not root_key_path.is_file():
                raise UsageError(f"--root-key が見つかりません: {root_key_path}")
            norm_write_path = _normalize_path_arg(write_path)
            parent_path = norm_write_path.rsplit("/", 1)[0] or "/"

            reg_client = cli_mod.RemoteRegistryClient(remote.registry_urls())
            existing_row = next(
                (
                    r
                    for r in reg_client.list_paths().get("paths", [])
                    if r.get("path") == norm_write_path
                ),
                None,
            )
            curr_epoch = int(existing_row.get("epoch") or 0) if existing_row else 0
            curr_head_ver = int(existing_row.get("head_version") or 0) if existing_row else 0
            write_epoch = (
                int(args.write_epoch)
                if getattr(args, "write_epoch", None) is not None
                else curr_epoch + 1
            )

            with tempfile.TemporaryDirectory(prefix="dfs_inv_key_") as tmpdir:
                eph_key = Path(tmpdir) / "ephemeral_ed25519"
                res = subprocess.run(
                    [
                        "ssh-keygen", "-t", "ed25519", "-N", "",
                        "-C", f"dfs-ephemeral@{norm_write_path}",
                        "-f", str(eph_key),
                    ],
                    capture_output=True,
                    text=True,
                )
                if res.returncode != 0:
                    raise UsageError(f"一時鍵の生成に失敗しました: {res.stderr.strip()}")
                eph_priv_text = eph_key.read_text(encoding="utf-8")
                eph_pub_text = Path(f"{eph_key}.pub").read_text(encoding="utf-8").strip()

            now = int(time.time())
            ttl_days = max(1, int(getattr(args, "ttl_days", 1) or 1))
            del_env = create_delegation_envelope(
                parent_priv_key=root_key_path,
                parent=parent_path,
                path=norm_write_path,
                writer_pubkey=eph_pub_text,
                epoch=write_epoch,
                base_version=curr_head_ver,
                issued_at=now - 5,
                expires_at=now + ttl_days * 86400,
            )
            reg_client.register_delegation(del_env, now=now)
            write_name = getattr(args, "write_name", None) or f"{args.name or remote.name}-out"
            return encode_rw_invite(
                name=args.name or remote.name,
                registries=registries,
                root_pubkey=remote.root_pubkey,
                tree_secret=remote.secret,
                write_name=write_name,
                write_path=norm_write_path,
                write_priv_key=eph_priv_text,
                write_pub_key=eph_pub_text,
                write_epoch=write_epoch,
                path=remote.path,
                ost=ost_primary,
                ost_alternates=ost_alts,
                role_epoch=remote.role_epoch,
                poll_seconds=int(args.poll),
                use_candidacy=bool(args.candidacy),
            )
        return encode_ro_invite(
            name=args.name or remote.name,
            registries=registries,
            root_pubkey=remote.root_pubkey,
            tree_secret=remote.secret,
            path=remote.path,
            ost=ost_primary,
            ost_alternates=ost_alts,
            role_epoch=remote.role_epoch,
            poll_seconds=int(args.poll),
            use_candidacy=bool(args.candidacy),
        )
    except (InviteError, DelegationError, cli_mod.RegistryError) as e:
        raise UsageError(f"招待トークンを作成できませんでした: {e}") from e


def _default_bootstrap_url(remote: Remote) -> str:
    from urllib.parse import urlsplit, urlunsplit

    env_url = os.environ.get("DFS_BOOTSTRAP_URL", "").strip()
    if env_url:
        return env_url
    parts = urlsplit(remote.registry)
    return urlunsplit((parts.scheme or "https", parts.netloc, "/bootstrap.sh", "", ""))


def cmd_share(args: argparse.Namespace) -> int:
    """RunPod 等向けの 1 行ブートストラップコマンドを簡潔に発行する。"""
    store = RemoteStore()
    remote = store.get(args.remote)
    token = _create_invite_token(args, remote)
    if getattr(args, "token_only", False):
        print(token)
        return 0
    bootstrap_url = getattr(args, "bootstrap_url", None) or _default_bootstrap_url(remote)
    print(f"curl -sSL {bootstrap_url} | bash -s -- {token}")
    return 0


def cmd_invite(args: argparse.Namespace) -> int:
    """読み取り専用 / 出力委譲付きの招待トークンを作成・参加する（RunPod 等の使い捨て環境向け）。"""
    store = RemoteStore()
    if args.action == "create":
        if not args.target:
            raise UsageError("invite create にはリモート名が必要です")
        remote = store.get(args.target)
        token = _create_invite_token(args, remote)
        if args.bootstrap_url:
            print(f"curl -sSL {args.bootstrap_url} | bash -s -- {token}")
        else:
            print(token)
        return 0

    if args.action == "join":
        if not args.target:
            raise UsageError("invite join には招待トークンが必要です")
        try:
            info = decode_invite(args.target)
        except InviteError as e:
            raise UsageError(f"招待トークンが不正です: {e}") from e

        registries = list(info["registries"])
        role_epoch = int(info["role_epoch"])
        if info.get("use_candidacy"):
            try:
                disc = fetch_candidacy(
                    registries,
                    info["root_pubkey"],
                    expected_root_anchor=None,
                    min_epoch=role_epoch,
                )
                registries = [disc.primary_url, *disc.alternate_urls]
                role_epoch = disc.epoch
            except CandidacyError as e:
                print(
                    f"[dfscli] warning: candidacy refresh skipped ({e})",
                    file=sys.stderr,
                )

        remote_name = (args.name or info["name"]).strip()
        workdir = str(Path(args.workdir).expanduser()) if args.workdir else ""
        remote = Remote(
            name=remote_name,
            registry=registries[0],
            registry_alternates=registries[1:],
            key="",
            ost=info["ost"],
            ost_alternates=info["ost_alternates"],
            path=info["path"],
            secret=info["tree_secret"],
            workdir=workdir,
            role_epoch=role_epoch,
            node_name=remote_name,
            root_pubkey=info["root_pubkey"],
            root_fingerprint=ssh_key_fingerprint(info["root_pubkey"]),
            read_only=True,
        )
        store.set(remote)
        print(f"[dfscli] 読み取り専用リモート {remote.name!r} を登録しました: {store.path}")

        write_info = info.get("write")
        if isinstance(write_info, dict):
            write_name = str(write_info.get("name") or "")
            if not NAME_RE.match(write_name):
                raise UsageError(
                    f"招待トークン内の write.name が不正です: {write_name!r}"
                )
            key_dir = (config_dir() / "keys").resolve()
            ensure_private_dir(key_dir)
            eph_key_path = (key_dir / f"{write_name}_ed25519").resolve()
            eph_pub_path = (key_dir / f"{write_name}_ed25519.pub").resolve()
            if (
                not eph_key_path.is_relative_to(key_dir)
                or not eph_pub_path.is_relative_to(key_dir)
            ):
                raise UsageError(
                    f"招待トークン内の write.name が鍵ディレクトリ外を指しています: {write_name!r}"
                )
            if eph_key_path.exists() or eph_pub_path.exists():
                raise UsageError(
                    f"既存の鍵ファイルが既に存在するため上書きを拒否しました: {eph_key_path}"
                )
            eph_key_path.write_text(write_info["priv_key"], encoding="utf-8")
            restrict_to_owner(eph_key_path)
            eph_pub_path.write_text(write_info["pub_key"] + "\n", encoding="utf-8")
            write_workdir = (
                str(Path(args.workdir).expanduser() / write_name)
                if args.workdir
                else ""
            )
            out_remote = Remote(
                name=write_name,
                registry=registries[0],
                registry_alternates=registries[1:],
                key=str(eph_key_path),
                ost=info["ost"],
                ost_alternates=info["ost_alternates"],
                path=write_info["path"],
                secret=info["tree_secret"],
                workdir=write_workdir,
                epoch=int(write_info["epoch"]),
                role_epoch=role_epoch,
                node_name=write_name,
                root_pubkey=info["root_pubkey"],
                root_fingerprint=ssh_key_fingerprint(info["root_pubkey"]),
                read_only=False,
            )
            store.set(out_remote)
            print(
                f"[dfscli] 出力用リモート {out_remote.name!r} ({out_remote.path}, "
                f"epoch={out_remote.epoch}) を登録しました"
            )

        if args.sync or args.watch:
            node = open_remote(remote, create=True)
            dest = Path(args.dest).expanduser() if args.dest else remote.resolved_workdir() / "out"
            path_filter = _path_filter(argparse.Namespace(include=[], exclude=[]))
            version, count = _pull_once(
                node, remote, "", dest, path_filter, force=False
            )
            print(f"[dfscli] pull OK <- v{version} | {count} ファイル -> {dest}")
            if args.watch:
                poll = max(1, int(args.poll or info["poll_seconds"]))
                last_version = version
                try:
                    while True:
                        time.sleep(poll)
                        try:
                            latest = node.remote_version()
                        except Exception as e:  # noqa: BLE001
                            print(f"[dfscli] watch poll failed: {e}", file=sys.stderr)
                            continue
                        if latest > last_version:
                            version, count = _pull_once(
                                node, remote, "", dest, path_filter, force=False
                            )
                            last_version = version
                            print(f"[dfscli] pull OK <- v{version} | {count} ファイル -> {dest}")
                except KeyboardInterrupt:
                    print("\n[dfscli] watch を終了します", file=sys.stderr)
        return 0

    raise UsageError(f"Unknown invite action: {args.action}")


def _detect_external_ip(timeout: float = 0.8) -> str:
    """外部 IP（取得できなければローカルの送出元 IP）を返す。"""
    import urllib.request

    try:
        with urllib.request.urlopen("https://api.ipify.org", timeout=timeout) as resp:
            ip_txt = resp.read().decode("utf-8", errors="ignore").strip()
            if ip_txt:
                return ip_txt
    except Exception:  # noqa: BLE001
        pass
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return str(s.getsockname()[0])
    except OSError:
        return "127.0.0.1"


def default_subtree_name(
    external_ip: Optional[str] = None,
    hostname: Optional[str] = None,
) -> str:
    """外部 IP とホスト名から決定的な URL-safe Base64 部分木名を生成する。"""
    import base64

    ext_ip = (external_ip if external_ip is not None else _detect_external_ip()).strip()
    host = (hostname if hostname is not None else socket.gethostname()).strip()
    digest = hashlib.sha256(f"{ext_ip}\n{host}".encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest[:12]).decode("ascii").rstrip("=")


def cmd_join(args: argparse.Namespace) -> int:
    """別のドメイン / root ハブ / 招待 URI に後から参加する。"""
    target = str(args.target or "").strip()
    if not target:
        raise UsageError("参加先のドメイン・URL または招待 URI を指定してください")
    if target.startswith("dfs-invite://"):
        clean_target = target[len("dfs-invite://"):].lstrip("/")
        inv_args = argparse.Namespace(
            action="join",
            target=clean_target,
            name=args.name,
            workdir=getattr(args, "workdir", None),
            sync=getattr(args, "sync", False),
            dest=getattr(args, "dest", None),
            watch=False,
            poll=30,
            candidacy=True,
        )
        return cmd_invite(inv_args)

    if target.startswith("dfs://"):
        stripped = target[len("dfs://"):].lstrip("/")
        if stripped.startswith("dfs-ro-v1:") or stripped.startswith("dfs-rw-v1:"):
            inv_args = argparse.Namespace(
                action="join",
                target=stripped,
                name=args.name,
                workdir=getattr(args, "workdir", None),
                sync=getattr(args, "sync", False),
                dest=getattr(args, "dest", None),
                watch=False,
                poll=30,
                candidacy=True,
            )
            return cmd_invite(inv_args)
        target = stripped.split("/", 1)[0].rstrip(":")

    from urllib.parse import urlsplit
    from .dnssec import DEFAULT_RECORD_PREFIX, has_txt_record
    from .relay import discover_ice_candidates

    discovered = None
    if "://" not in target:
        if "." in target and ":" not in target and not target.startswith("["):
            rec_name = f"{DEFAULT_RECORD_PREFIX}.{target}"
            if has_txt_record(rec_name):
                try:
                    discovered = discover_domain(target, record_name=rec_name)
                except DiscoveryError as e:
                    raise UsageError(
                        f"{rec_name} に TXT レコードが存在するため DNSSEC 検証が必須ですが失敗しました: {e}"
                    ) from e
        if discovered is not None:
            base_url = discovered.primary_url
        else:
            base_url = f"http://{target}" if (":" in target and not target.startswith("[")) else f"https://{target}"
    else:
        base_url = target
    base_url = base_url.rstrip("/")
    parsed = urlsplit(base_url)
    host_label = parsed.hostname or "remote"

    # 0) L2 名簿への疎通確認
    urls = [base_url, *(list(discovered.alternate_urls) if discovered is not None else [])]
    reg_client = cli_mod.RemoteRegistryClient(urls)
    try:
        l2_info = reg_client.list_paths()
    except Exception as e:  # noqa: BLE001
        raise UsageError(f"L2 名簿 ({base_url}) への疎通確認に失敗しました: {e}") from e
    if discovered is not None:
        server_pub = str(l2_info.get("root_pubkey") or "").strip()
        if server_pub and discovered.root_pubkey and server_pub != discovered.root_pubkey:
            raise UsageError(
                f"L2 名簿 ({base_url}) の root_pubkey が DNSSEC 記録と一致しません"
            )

    # 1) /_ice/candidates から直接ピア候補を取得
    cands = discover_ice_candidates(base_url, timeout=2.0)
    direct_eps = [
        str(c["endpoint"])
        for c in cands
        if c.get("type") in ("host", "srflx") and c.get("endpoint")
    ]

    # 2) ローカルの dfssvc 設定があれば join 先を保存
    svc_name = getattr(args, "svc", None) or "local"
    svc_dir = Path.home() / "dfssvc" / svc_name
    cfg_file = svc_dir / "dfssvc.json"
    if svc_dir.is_dir():
        cfg: Dict[str, Any] = {}
        if cfg_file.is_file():
            try:
                loaded = json.loads(cfg_file.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    cfg = loaded
            except (OSError, ValueError, TypeError):
                cfg = {}
        cfg["join"] = base_url
        if not cfg.get("relay_node"):
            import socket as _sock

            cfg["relay_node"] = svc_name if svc_name != "local" else _sock.gethostname().split(".")[0]
        cfg_file.write_text(json.dumps(cfg, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"[dfscli] dfssvc ({svc_name}) の参加先を {base_url} に設定しました: {cfg_file}")

    # 3) --path / --secret または DNSSEC 自動発見があれば RemoteStore にリモートを登録
    if args.path or args.secret or discovered is not None:
        store = RemoteStore()
        remote_name = (args.name or (discovered.domain if discovered is not None else host_label)).strip()
        existing_remote = store.remotes.get(remote_name)
        key_value = str(args.key or "")
        if not key_value and existing_remote is not None and existing_remote.key:
            key_value = existing_remote.key
        if not key_value:
            from . import svc as svc_mod

            svc_rec = svc_mod.ServiceStore().services.get(remote_name)
            if svc_rec is not None and svc_rec.writer_key and Path(svc_rec.writer_key).expanduser().is_file():
                key_value = svc_rec.writer_key
            elif remote_name == svc_name:
                cand_writer = svc_dir / "keys" / "writer"
                if cand_writer.is_file():
                    key_value = str(cand_writer)
        secret_value = str(args.secret or "")
        if not secret_value and existing_remote is not None and existing_remote.secret:
            secret_value = existing_remote.secret
        primary_ost = direct_eps[0] if direct_eps else ""
        alt_osts = direct_eps[1:] if len(direct_eps) > 1 else []
        base_anchor = discovered.root_anchor if discovered is not None else f"/{host_label}"
        if args.path:
            remote_path = str(args.path)
        elif key_value:
            anchor_clean = base_anchor.rstrip("/")
            subtree_label = default_subtree_name()
            if anchor_clean.endswith(f"/{subtree_label}"):
                remote_path = anchor_clean or f"/{subtree_label}"
            else:
                remote_path = f"{anchor_clean}/{subtree_label}"
        else:
            remote_path = base_anchor
        remote = Remote(
            name=remote_name,
            registry=base_url,
            registry_alternates=list(discovered.alternate_urls) if discovered is not None else [],
            key=key_value,
            ost=primary_ost,
            ost_alternates=alt_osts,
            path=remote_path,
            secret=secret_value,
            role_epoch=int(discovered.epoch) if discovered is not None else 1,
            node_name=remote_name,
            root_pubkey=discovered.root_pubkey if discovered is not None else "",
            root_fingerprint=ssh_key_fingerprint(discovered.root_pubkey) if discovered is not None else "",
            read_only=not bool(key_value),
        )
        store.set(remote)
        if existing_remote is not None and (
            existing_remote.path != remote.path
            or (
                remote.root_pubkey
                and existing_remote.root_pubkey
                and existing_remote.root_pubkey != remote.root_pubkey
            )
        ):
            _reset_workdir_pin(remote.resolved_workdir().expanduser())
        print(f"[dfscli] リモート {remote.name!r} を登録しました: {store.path}")
        if key_value:
            try:
                writer_pub = public_key_of(Path(key_value).expanduser())
            except UsageError:
                writer_pub = ""
            if writer_pub:
                rows = l2_info.get("paths")
                already = isinstance(rows, list) and any(
                    isinstance(r, dict)
                    and r.get("path") == remote.path
                    and str(r.get("writer") or "").strip() == writer_pub
                    for r in rows
                )
                auto_fn = getattr(reg_client, "auto_delegate", None)
                if not already and callable(auto_fn):
                    try:
                        auto_fn(remote.path, writer_pub)
                        print(f"[dfscli] L2 自動委譲を登録しました: {remote.path}")
                    except Exception as e:  # noqa: BLE001
                        print(
                            f"[dfscli] warning: L2 自動委譲に失敗しました ({e})。"
                            "必要に応じて手動で dfscli delegate を実行してください",
                            file=sys.stderr,
                        )

    print(f"[dfscli] join 対象: {base_url}")
    anchor_info = str(l2_info.get("root_anchor") or "").strip() or "/"
    print(f"[dfscli] L2 疎通確認 OK: {base_url} (anchor={anchor_info})")
    if direct_eps:
        print(f"[dfscli] 発見した直接 OST 候補 ({len(direct_eps)} 件): {', '.join(direct_eps)}")
    if svc_dir.is_dir():
        from . import svc as svc_mod

        svc_store = svc_mod.ServiceStore()
        running_svc = svc_store.services.get(svc_name)
        if running_svc is not None and (
            running_svc.is_running() or svc_mod._recorded_server_is_alive(running_svc)
        ):
            print(f"[dfscli] 稼働中の dfssvc ({svc_name}) を再起動して参加先を反映します...")
            rc_svc = svc_mod.main(["start", "--name", svc_name, "--force"])
            if rc_svc != 0:
                print(
                    f"[dfscli] warning: dfssvc の自動再起動に失敗しました (code={rc_svc})。"
                    f"手動で 'dfssvc start --name {svc_name} --force' を実行してください",
                    file=sys.stderr,
                )
        else:
            print(f"[dfscli] 反映するには 'dfssvc start --name {svc_name} --force' を実行してください")
    return 0


def cmd_quit(args: argparse.Namespace) -> int:
    """参加中のドメインから安全に離脱し、ローカル単独モードへ戻す。"""
    svc_name = getattr(args, "svc", None) or "local"
    svc_dir = Path.home() / "dfssvc" / svc_name
    cfg_file = svc_dir / "dfssvc.json"
    prev_join = ""
    cleared_svc = False

    if cfg_file.is_file():
        try:
            cfg = json.loads(cfg_file.read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError):
            cfg = {}
        if isinstance(cfg, dict):
            prev_join = str(cfg.get("join") or "")
            if prev_join or cfg.get("relay_node") or cfg.get("relay_token"):
                cfg["join"] = ""
                cfg["relay_node"] = ""
                cfg["relay_token"] = ""
                cfg_file.write_text(
                    json.dumps(cfg, ensure_ascii=False, indent=2) + "\n",
                    encoding="utf-8",
                )
                cleared_svc = True
                print(f"[dfscli] dfssvc ({svc_name}) の参加設定 ({prev_join or 'relay'}) を解除しました")

    store = RemoteStore()
    targets: List[str] = []
    if getattr(args, "name", None):
        targets.append(str(args.name).strip())
    elif getattr(args, "all", False) and prev_join:
        norm_prev = prev_join.rstrip("/")
        for rname in store.names():
            r = store.get(rname)
            if r.registry.rstrip("/") == norm_prev:
                targets.append(rname)

    removed_remotes: List[str] = []
    for rname in targets:
        if rname not in store.names():
            continue
        r = store.get(rname)
        if r.workdir:
            cache_file = Path(r.workdir).expanduser() / ".clayfs" / "transport_cache.json"
            if cache_file.is_file():
                try:
                    cache_file.unlink()
                except OSError:
                    pass
        if store.delete(rname):
            removed_remotes.append(rname)
            print(f"[dfscli] リモート {rname!r} と接続キャッシュを削除しました")

    if not cleared_svc and not removed_remotes:
        print("[dfscli] 離脱対象のドメイン設定・リモートは見つかりませんでした")
    elif cleared_svc:
        print(f"[dfscli] 反映するには 'dfssvc start --name {svc_name} --force' を実行してください")
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    """リモートの指定パスとローカルディレクトリを比べる。"""
    store = RemoteStore()
    name, sub = split_remote_spec(args.remote, args.remote_name)
    remote = store.get(name)
    prefix = _norm_prefix(sub)
    node = open_remote(remote, create=True)

    remote_files = {
        e["path"][len(prefix) + 1 if prefix else 0:]: int(e.get("size", 0))
        for e in _all_entries(node, prefix) if e["type"] == "file"
    }
    local_files = {}
    base = Path(args.local).expanduser()
    for rel, path in _collect_local(base).items():
        local_files[rel] = path.stat().st_size

    only_remote = sorted(set(remote_files) - set(local_files))
    only_local = sorted(set(local_files) - set(remote_files))
    size_diff = sorted(
        rel for rel in set(remote_files) & set(local_files)
        if remote_files[rel] != local_files[rel]
    )

    for rel in only_remote:
        print(f"* {rel}: リモートにのみ存在")
    for rel in only_local:
        print(f"* {rel}: ローカルにのみ存在")
    for rel in size_diff:
        print(f"* {rel}: 大きさが違う (remote={remote_files[rel]} local={local_files[rel]})")

    if only_remote or only_local or size_diff:
        print(
            f"[dfscli] check: 一致しません "
            f"(remote のみ {len(only_remote)} / local のみ {len(only_local)} / 差 {len(size_diff)})"
        )
        return 1
    print(f"[dfscli] check: 一致しました（{len(remote_files)} ファイル）")
    return 0


def cmd_about(args: argparse.Namespace) -> int:
    store = RemoteStore()
    name, sub = split_remote_spec(args.remote, args.remote_name)
    remote = store.get(name)
    node = open_remote(remote, create=True)
    pin = node.l4.pin
    # 定義に書かれていない ost / path は、実際に使った値（作業ディレクトリの設定）を出す。
    cfg = json.loads((node.clayfs.clayfs_meta / cli_mod.CONFIG_FILENAME).read_text(encoding="utf-8"))
    effective_path = cfg.get("sub_path") or remote.path
    effective_ost = remote.ost or f"{cfg.get('ost_host', '')}:{cfg.get('ost_port', '')}"
    print(f"Remote      : {name}")
    print(f"Registry    : {remote.registry}")
    print(f"OST         : {effective_ost}" + ("" if remote.ost else "  (L2 のロケータから解決)"))
    print(f"Subtree     : {effective_path}" + ("" if remote.path else "  (L2 で書き手鍵から解決)"))
    print(f"Workdir     : {remote.resolved_workdir()}")
    print(f"Local Pin   : v{pin.version} (epoch={pin.delegation_epoch})")
    try:
        del_env, _loc, head_env = node.registry.resolve(effective_path)
        if del_env:
            dp = del_env["payload"]
            print(f"Active L1   : epoch={dp['epoch']} base_version={dp['base_version']}")
        if head_env:
            hp = head_env["payload"]
            print(
                f"Remote Head : v{hp['version']} (epoch={hp['delegation_epoch']}, "
                f"root={hp['root_plain_id'][:12]}...)"
            )
        else:
            print("Remote Head : (empty)")
    except Exception as e:  # noqa: BLE001 - 表示のためのコマンドなので落とさない
        print(f"Remote Head : [unreachable: {e}]")
    return 0


def cmd_fs(args: argparse.Namespace) -> int:
    """ローカルディレクトリの CoW 検出とスナップショット (リモート不要)。"""
    from .fs import FileSystem, detect_backends

    root = Path(args.path).expanduser()
    if args.action == "info":
        for info in detect_backends(root):
            mark = "*" if info.available else " "
            print(f"{mark} {info.name:<10} {info.capability.value:<10} {info.detail}")
        f = FileSystem(root, backend=args.backend)
        print()
        print(f"selected    : {f.backend.name} (cow={f.is_cow})")
        return 0
    if args.action == "snapshot":
        f = FileSystem(root, backend=args.backend)
        snap_id = _validate_snapshot_id(args.snap_id)
        result = f.take_snapshot(snap_id)
        print(f"snapshot    : {result.snapshot_id}")
        print(f"path        : {result.path}")
        print(f"backend     : {result.backend}")
        print(f"files       : {result.files}")
        print(f"bytes       : {result.bytes_copied}")
        for w in result.warnings:
            print(f"warning     : {w}", file=sys.stderr)
        return 0
    if args.action == "materialize":
        snap_id = _validate_snapshot_id(args.snap_id) if args.snap_id else None
        if args.src:
            src = Path(args.src).expanduser()
        elif snap_id:
            src = root / ".clayfs" / "snapshots" / snap_id
        else:
            raise UsageError("materialize には --src か snap_id が必要")
        if not args.dst:
            raise UsageError("materialize には出力先が必要")
        f = FileSystem(root, backend=args.backend)
        out = f.materialize(src, Path(args.dst).expanduser())
        print(f"materialize : {out}")
        return 0
    raise UsageError(f"unknown fs action: {args.action}")


def cmd_mkdir(args: argparse.Namespace) -> int:
    """リモートにディレクトリを作る（空のディレクトリも版に残る）。"""
    store = RemoteStore()
    name, sub = split_remote_spec(args.remote, args.remote_name)
    remote = store.get(name)
    _require_writable(remote)
    sub = _norm_prefix(sub)
    if not sub:
        raise UsageError("mkdir にはディレクトリのパスが必要です（例: remote:dir/sub）")

    node = open_remote(remote, create=True)
    refresh_cache(node)
    existing = _remote_dir_paths(node) | _remote_file_paths(node)
    if sub in existing:
        print(f"[dfscli] mkdir: すでにあります: {name}:{sub}", file=sys.stderr)
        return 0

    target = _tree_path(node, sub)
    target.mkdir(parents=True, exist_ok=True)
    log_env, sent = _push(node, remote)
    print(f"[dfscli] mkdir OK -> v{log_env['payload']['version']} | {sub}/ | sent={sent} B")
    return 0


def cmd_rm(args: argparse.Namespace) -> int:
    """リモートのファイル（または ``--recursive`` でディレクトリ）を消す。

    rclone の ``delete`` / ``deletefile`` に当たる。消した後に空になったディレクトリは、
    ``--rmdirs`` を付けたときだけ片付ける（既定は空ディレクトリを残す。dfs は空の
    ディレクトリも版に残すため、消すか残すかを選べるようにしてある）。
    """
    store = RemoteStore()
    name, sub = split_remote_spec(args.remote, args.remote_name)
    remote = store.get(name)
    _require_writable(remote)
    sub = _norm_prefix(sub)
    if not sub:
        raise UsageError("rm にはパスが必要です（例: remote:dir/file.txt）")

    node = open_remote(remote, create=True)
    refresh_cache(node)

    files = _remote_file_paths(node)
    dirs = _remote_dir_paths(node)
    is_dir = sub in dirs
    targets: List[str] = []
    if sub in files:
        targets = [sub]
    elif is_dir:
        if not args.recursive:
            raise UsageError(
                f"{name}:{sub} はディレクトリです。中身ごと消すなら --recursive を付けてください"
            )
        targets = sorted(p for p in files if p == sub or p.startswith(sub + "/"))
        if not targets and not args.rmdirs:
            # 中身が無いディレクトリ。消すには --rmdirs が要る
            raise UsageError(
                f"{name}:{sub} は空のディレクトリです。消すなら --rmdirs を付けてください"
            )
    else:
        raise UsageError(f"{name}:{sub} は見つかりません")

    if not targets:
        if not args.rmdirs:
            print(f"[dfscli] rm: 消すファイルがありません（{name}:{sub}）", file=sys.stderr)
            return 0
        # --rmdirs なら、ファイルが無くても空ディレクトリの掃除に進む
        print(
            f"[dfscli] rm: {name}:{sub} にファイルはありません。空ディレクトリを片付けます",
            file=sys.stderr,
        )

    _print_plan("rm", [f"delete {name}:{p}" for p in targets], args.dry_run)
    if args.dry_run:
        return 0

    _remove_from_tree(node, targets)
    removed_dirs: List[str] = []
    if args.rmdirs:
        if is_dir:
            _remove_from_tree(node, [sub])
        removed_dirs.extend(prune_empty_parents(node, [sub]))

    log_env, sent = _push(node, remote)
    extra = f" | 空になったディレクトリ {len(removed_dirs)} 件も削除" if removed_dirs else ""
    print(
        f"[dfscli] rm OK -> v{log_env['payload']['version']} "
        f"| 削除 {len(targets)} 件{extra} | sent={sent} B"
    )
    return 0


def cmd_rmdir(args: argparse.Namespace) -> int:
    """空のディレクトリを消す（中身があれば断る）。"""
    store = RemoteStore()
    name, sub = split_remote_spec(args.remote, args.remote_name)
    remote = store.get(name)
    _require_writable(remote)
    sub = _norm_prefix(sub)
    if not sub:
        raise UsageError("rmdir にはディレクトリのパスが必要です（例: remote:dir/sub）")

    node = open_remote(remote, create=True)
    refresh_cache(node)

    dirs = _remote_dir_paths(node)
    files = _remote_file_paths(node)
    if sub not in dirs:
        raise UsageError(f"{name}:{sub} はディレクトリではありません")
    children = [p for p in files if p.startswith(sub + "/")] + [
        d for d in dirs if d.startswith(sub + "/")
    ]
    if children:
        raise UsageError(
            f"{name}:{sub} は空ではありません（{len(children)} 件が下にあります）"
        )

    _print_plan("rmdir", [f"delete {name}:{sub}/"], args.dry_run)
    if args.dry_run:
        return 0

    _remove_from_tree(node, [sub])
    prune_empty_parents(node, [sub])
    log_env, sent = _push(node, remote)
    print(f"[dfscli] rmdir OK -> v{log_env['payload']['version']} | {sub}/ | sent={sent} B")
    return 0


def cmd_purge(args: argparse.Namespace) -> int:
    """指定パスの中身をすべて消す（ディレクトリ自身も消す）。"""
    store = RemoteStore()
    name, sub = split_remote_spec(args.remote, args.remote_name)
    remote = store.get(name)
    _require_writable(remote)
    sub = _norm_prefix(sub)

    node = open_remote(remote, create=True)
    refresh_cache(node)

    files = _remote_file_paths(node)
    dirs = _remote_dir_paths(node)
    if sub:
        targets = sorted(p for p in files if p == sub or p.startswith(sub + "/"))
        target_dirs = sorted((d for d in dirs if d == sub or d.startswith(sub + "/")),
                             key=lambda d: len(d.split("/")), reverse=True)
    else:
        targets = sorted(files)
        target_dirs = sorted(dirs, key=lambda d: len(d.split("/")), reverse=True)

    if not targets and not target_dirs:
        print(f"[dfscli] purge: 消すものがありません（{name}:{sub}）", file=sys.stderr)
        return 0

    _print_plan(
        "purge",
        [f"delete {name}:{p}" for p in targets] + [f"rmdir  {name}:{d}/" for d in target_dirs],
        args.dry_run,
    )
    if args.dry_run:
        return 0

    _remove_from_tree(node, targets + target_dirs)
    prune_empty_dirs(node)
    log_env, sent = _push(node, remote)
    print(
        f"[dfscli] purge OK -> v{log_env['payload']['version']} "
        f"| ファイル {len(targets)} 件・ディレクトリ {len(target_dirs)} 件 | sent={sent} B"
    )
    return 0


def cmd_touch(args: argparse.Namespace) -> int:
    """リモートの作業ディレクトリを初期化する（push/pull はしない）。"""
    store = RemoteStore()
    name, _sub = split_remote_spec(args.remote, args.remote_name)
    remote = store.get(name)
    node = open_remote(remote, create=True)
    print(f"[dfscli] 初期化しました: {node.clayfs.mount_root}")
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    cli_mod.cmd_serve(args)
    return 0


def cmd_promote(args: argparse.Namespace) -> int:
    cli_mod.cmd_promote(args)
    return 0


def cmd_libp2p_serve(args: argparse.Namespace) -> int:
    """ローカルの OST chunk ディレクトリを libp2p/QUIC で配布する。"""
    try:
        from .libp2p_chunk import Libp2pChunkServer, load_chunks_dir
    except ImportError as e:  # pragma: no cover - 依存環境
        raise UsageError("libp2p-serve には libp2p パッケージが必要です") from e
    try:
        store = load_chunks_dir(args.chunks_dir)
        server = Libp2pChunkServer(
            store,
            listen=args.listen or ["/ip4/0.0.0.0/udp/0/quic-v1"],
            psk=args.psk,
        )
    except Exception as e:  # noqa: BLE001
        raise UsageError(f"libp2p-serve を開始できません: {e}") from e

    def ready(addrs: List[str]) -> None:
        print("[dfscli] libp2p/QUIC ready")
        for addr in addrs:
            print(f"  peer: {addr}")

    server.serve_forever(ready)
    return 0


def cmd_delegate(args: argparse.Namespace) -> int:
    cli_mod.cmd_delegate(args)
    return 0


# ==========================================
# 引数の組み立て
# ==========================================
def _add_create_args(p: argparse.ArgumentParser, args_name_required: bool) -> None:
    """``create`` と ``config create`` で共有する引数。"""
    p.add_argument(
        "--registry",
        help=f"L2 名簿。ホスト名だけでよい（例: 172.16.1.60）。"
             f"ポートを省くと {DEFAULT_REGISTRY_PORT} を補う",
    )
    p.add_argument(
        "--registry-port", type=int, default=DEFAULT_REGISTRY_PORT,
        help=f"--registry にポートが無いときに補う番号（既定 {DEFAULT_REGISTRY_PORT}）",
    )
    p.add_argument(
        "--registry-alternate", action="append", default=[],
        help="読み取り用の代替 L2 名簿（複数指定可。書き込みは --registry のみ）",
    )
    p.add_argument("--ost", help="L3 OST の host:port（例: 172.16.1.60:19443）")
    p.add_argument(
        "--ost-alternate", action="append", default=[],
        help="読み取り用の複製 OST の host:port（複数指定可）",
    )
    p.add_argument(
        "--libp2p-peer", action="append", default=[],
        help="読み取り用 libp2p QUIC multiaddr（複数指定可）",
    )
    p.add_argument("--libp2p-psk", help="libp2p private swarm の pre-shared key")
    p.add_argument("--path", help="サブツリーのパス（例: /example.com/alice/notes）")
    p.add_argument("--key", help="書き手の OpenSSH Ed25519 秘密鍵（省略すると作る）")
    p.add_argument(
        "--key-dir",
        help="--key を省いたときに鍵を置く場所（既定 ~/.config/dfs/keys）",
    )
    p.add_argument(
        "--secret",
        help="tree_secret（Convergent AEAD の共有秘密）。省略すると端末からエコーなしで読む",
    )
    p.add_argument(
        "--no-prompt", action="store_true",
        help="--secret を省いても端末から読まない（パイプで使うとき）",
    )
    p.add_argument("--workdir", help="作業ディレクトリ（既定 ~/.cache/dfs/<name>）")
    p.add_argument("--epoch", type=int, default=1, help="委譲のエポック（既定 1）")
    p.add_argument(
        "--role-epoch", type=int, default=1,
        help="registry primary/secondary の fencing 世代（既定 1）",
    )
    p.add_argument(
        "--compression", choices=["auto", "none", "zstd"], default="auto",
        help="フォルダ xattr が無い場合の既定圧縮（既定 auto）",
    )
    p.add_argument("--node-name", help="端末名（既定はリモート名）")
    p.add_argument(
        "--root-pubkey",
        help="root アンカーの公開鍵ファイル（信頼の根）。省略時は名簿から取得して記録する（TOFU）",
    )
    p.add_argument(
        "--dnssec-domain",
        help="DNSSEC の _dfs.<domain> TXT から root 公開鍵と registry 一覧を取得する",
    )
    p.add_argument(
        "--dnssec-name",
        help="DNSSEC の TXT レコード名（既定 _dfs.<domain>）",
    )
    p.add_argument(
        "--dnssec-no-ad", action="store_true",
        help="DNSSEC の AD ビットを要求しない（--dnssec-no-validate と併用する旧経路）",
    )
    p.add_argument(
        "--dnssec-no-validate", action="store_true",
        help="クライアント側 DNSSEC 検証を省略する（診断用。本番では使わない）",
    )
    p.add_argument(
        "--candidacy-url", action="append", default=[],
        help="小規模運用向けの署名付き立候補名簿 (/v1/candidacy) を取得する URL（複数指定可）",
    )
    p.add_argument(
        "--candidacy-file",
        help="小規模運用向けの署名付き立候補ファイル (dfs-candidacy-v1 JSON)",
    )
    if args_name_required:
        p.add_argument("name", help="リモートの名前（例: scw）")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dfscli",
        description="dfscli: dfs を rclone ライクに扱う CLI（リモート名で場所を指す）",
    )
    parser.add_argument(
        "--remote", dest="remote_name", metavar="NAME",
        help="リモート名（例: local、`dfscli listremotes` で確認）。省略時は dfs://remote/path 形式で指定",
    )
    parser.add_argument("--version", action="version", version=f"dfscli {_version()}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("listremotes", help="定義済みのリモートと接続状態・権限を一覧する")
    p.add_argument("--no-check", action="store_true", help="接続確認を省略して高速表示する")
    p.add_argument("--prune", action="store_true", help="到達できないリモートを削除する（dfssvc 管理下は保護）")
    p.add_argument("--all", action="store_true", help="--prune 時に停止中の dfssvc 管理リモートも対象にする")
    p.add_argument("-y", "--yes", action="store_true", help="--prune 時に確認なしで削除する")
    p.add_argument("--json", action="store_true", help="JSON で出力する")
    p.set_defaults(func=cmd_listremotes)

    # `dfscli create NAME ...` は `dfscli config create NAME ...` と同じ。
    # 登録は一番よく打つので短い入口を用意する。
    p = sub.add_parser("create", help="リモートを登録する（= config create）")
    _add_create_args(p, args_name_required=True)
    p.set_defaults(func=cmd_config, action="create")

    p_conf = sub.add_parser("config", help="リモート定義の作成・表示・削除")
    p_conf.add_argument("action", choices=["create", "show", "delete", "list"])
    p_conf.add_argument("name", nargs="?", default="")
    _add_create_args(p_conf, args_name_required=False)
    p_conf.set_defaults(func=cmd_config)

    p_disc = sub.add_parser("discover", help="DNSSEC から root/registry 情報を取得して表示する")
    p_disc.add_argument("domain", help="例: example.com")
    p_disc.add_argument("--dnssec-name", help="TXT レコード名（既定 _dfs.<domain>）")
    p_disc.add_argument("--dnssec-no-ad", action="store_true", help="AD ビットを要求しない")
    p_disc.add_argument(
        "--dnssec-no-validate",
        action="store_true",
        help="クライアント側 DNSSEC 検証を省略する（診断用。本番では使わない）",
    )
    p_disc.add_argument("--json", action="store_true", help="レコード JSON をそのまま出す")
    p_disc.set_defaults(func=cmd_discover)

    p_cand = sub.add_parser(
        "candidacy",
        help="小規模運用向けの署名付き立候補レコードを作成・取得する",
    )
    p_cand.add_argument("action", choices=["create", "discover"])
    p_cand.add_argument("--root-key", help="root の OpenSSH 秘密鍵 (create 用)")
    p_cand.add_argument("--root-anchor", default="/example.com", help="root アンカーパス")
    p_cand.add_argument("--root-pubkey", required=True, help="root 公開鍵ファイルまたは文字列")
    p_cand.add_argument("--primary", help="primary registry URL (create 用)")
    p_cand.add_argument("--secondary", action="append", default=[], help="secondary registry URL (複数可)")
    p_cand.add_argument("--epoch", type=int, default=1, help="立候補世代 / role_epoch (create 用)")
    p_cand.add_argument("--ttl-days", type=int, default=30, help="有効期間（日）")
    p_cand.add_argument("--out", help="出力 JSON ファイルパス (create 用)")
    p_cand.add_argument("--announce", action="append", default=[], help="登録先の registry URL (create 用)")
    p_cand.add_argument("--url", action="append", default=[], help="問い合わせる候補 registry URL (discover 用)")
    p_cand.add_argument("--min-epoch", type=int, help="受け入れる最小 epoch (discover 用)")
    p_cand.add_argument("--registry-port", type=int, default=DEFAULT_REGISTRY_PORT)
    p_cand.add_argument("--json", action="store_true", help="JSON をそのまま出す")
    p_cand.set_defaults(func=cmd_candidacy)

    p_arch = sub.add_parser(
        "archive", help="版の archive bundle / BitTorrent を作成・公開・取得する"
    )
    p_arch.add_argument(
        "action",
        choices=["create", "publish", "verify", "extract", "catalog", "fetch"],
    )
    p_arch.add_argument(
        "source",
        help="create/fetch は remote:path、verify/extract は bundle ディレクトリ",
    )
    p_arch.add_argument("dest", nargs="?", help="extract/fetch の出力先")
    p_arch.add_argument(
        "--out",
        help="create の bundle 出力先、または fetch のダウンロード先",
    )
    p_arch.add_argument("--announce", help="torrent の announce URL（省略可）")
    p_arch.add_argument("--version", type=int, help="archive する版（省略時は先頭版）")
    p_arch.add_argument("--secret", help="extract の tree_secret")
    p_arch.add_argument("--no-prompt", action="store_true", help="secret を端末から読まない")
    p_arch.add_argument(
        "--publish",
        action="store_true",
        help="create 後、署名済みdescriptorをL2へ公開する",
    )
    p_arch.add_argument(
        "--torrent-client",
        help="fetchで使う外部BT CLI（既定: aria2c、次に transmission-cli）",
    )
    p_arch.add_argument(
        "--torrent-timeout",
        type=int,
        default=7200,
        help="fetchのダウンロードタイムアウト秒（既定 7200）",
    )
    p_arch.set_defaults(func=cmd_archive)

    p_history = sub.add_parser("history", help="L4 の版履歴を表示する")
    p_history.add_argument("remote", nargs="?", default="", help="remote:path（--remote 指定時は省略可）")
    p_history.add_argument("--limit", type=int, default=50, help="表示件数（既定 50）")
    p_history.set_defaults(func=cmd_history)

    p = sub.add_parser("ls", help="リモートの直下を一覧する（内容は取らない）")
    p.add_argument("remote", nargs="?", default="", help="remote:path（--remote 指定時は省略可）")
    p.set_defaults(func=cmd_ls)

    p = sub.add_parser("lsd", help="リモートの直下にあるディレクトリだけを一覧する")
    p.add_argument("remote", nargs="?", default="", help="remote:path（--remote 指定時は省略可）")
    p.set_defaults(func=cmd_lsd)

    p = sub.add_parser("mount", help="リモートを fuse-t / FUSE でマウントする")
    p.add_argument("remote", help="remote:path")
    p.add_argument("mountpoint", help="ローカルのマウントポイント")
    p.add_argument("--read-only", action="store_true", help="読み取り専用でマウントする")
    p.add_argument("--allow-other", action="store_true", help="allow_other を FUSE に渡す")
    p.add_argument("--debug", action="store_true", help="FUSE のデバッグログを出す")
    p.add_argument(
        "--fuse-library",
        help="fusepy が使う FUSE ライブラリ（macOS の fuse-t など）",
    )
    p.set_defaults(func=cmd_mount)

    p = sub.add_parser("lsl", help="リモートの直下を大きさ付きで一覧する")
    p.add_argument("remote", nargs="?", default="", help="remote:path（--remote 指定時は省略可）")
    p.set_defaults(func=cmd_lsl)

    p = sub.add_parser("lsjson", help="リモートの一覧を JSON で出す")
    p.add_argument("remote", nargs="?", default="", help="remote:path（--remote 指定時は省略可）")
    p.set_defaults(func=cmd_lsjson)

    p = sub.add_parser("size", help="リモートの合計と重複排除後の塊の数を出す")
    p.add_argument("remote", nargs="?", default="", help="remote:path（--remote 指定時は省略可）")
    p.set_defaults(func=cmd_size)

    p = sub.add_parser("cat", help="リモートの 1 ファイルを標準出力へ出す")
    p.add_argument("remote")
    p.set_defaults(func=cmd_cat)

    p = sub.add_parser("copy", help="ローカルのファイルをリモートへ足す（残す）")
    p.add_argument("src", help="ローカルのファイルまたはディレクトリ")
    p.add_argument("dest", help="remote:path")
    p.add_argument(
        "--checksum", nargs="?", const="plain_id", default="size",
        choices=CHECKSUM_MODES,
        help="変更検出: size / crc32 / sha1 / plain_id（単独指定は plain_id）",
    )
    p.add_argument("--include", action="append", default=[], metavar="PATTERN",
                   help="含める相対パターン（複数指定可）")
    p.add_argument("--exclude", action="append", default=[], metavar="PATTERN",
                   help="除外する相対パターン（複数指定可、include より優先）")
    p.add_argument("-n", "--dry-run", action="store_true", help="何をするかだけ表示する")
    p.set_defaults(func=cmd_copy)

    p = sub.add_parser("copyto", help="ローカルの 1 ファイルをリモートの指定パスへ置く")
    p.add_argument("src")
    p.add_argument("dest", help="remote:path/file")
    p.add_argument(
        "--checksum", nargs="?", const="plain_id", default="size",
        choices=CHECKSUM_MODES,
        help="変更検出: size / crc32 / sha1 / plain_id（単独指定は plain_id）",
    )
    p.add_argument("-n", "--dry-run", action="store_true")
    p.set_defaults(func=cmd_copyto)

    p = sub.add_parser(
        "import_tar",
        aliases=["import-tar"],
        help="tar / tar.gz / tar.xz / tar.bz2 をリモートへインポートする",
    )
    p.add_argument("archive", help="ローカルの tar ファイル")
    p.add_argument("dest", help="remote:path")
    p.add_argument(
        "--strip-components", type=int, default=0, metavar="N",
        help="tar member の先頭 N 要素を除く（既定 0）",
    )
    p.add_argument("-n", "--dry-run", action="store_true")
    p.set_defaults(func=cmd_import_tar)

    p = sub.add_parser("mv", help="リモート内でファイルまたはディレクトリを移動する")
    p.add_argument("src", help="移動元 remote:path")
    p.add_argument("dst", help="移動先 remote:path")
    p.add_argument("--overwrite", action="store_true",
                   help="移動先のファイルを置換する（ディレクトリの merge はしない）")
    p.add_argument("-n", "--dry-run", action="store_true")
    p.set_defaults(func=cmd_mv)

    p = sub.add_parser("sync", help="リモートをローカルディレクトリと一致させる")
    p.add_argument("src", help="ローカルのディレクトリ")
    p.add_argument("dest", help="remote:path")
    p.add_argument("--delete", action="store_true", help="リモートにしかないものを消す")
    p.add_argument(
        "--checksum", nargs="?", const="plain_id", default="size",
        choices=CHECKSUM_MODES,
        help="変更検出: size / crc32 / sha1 / plain_id（単独指定は plain_id）",
    )
    p.add_argument("--include", action="append", default=[], metavar="PATTERN",
                   help="含める相対パターン（複数指定可）")
    p.add_argument("--exclude", action="append", default=[], metavar="PATTERN",
                   help="除外する相対パターン（複数指定可、include より優先）")
    p.add_argument("-n", "--dry-run", action="store_true")
    p.set_defaults(func=cmd_sync)

    p = sub.add_parser("pull", help="リモートをローカルディレクトリへ取り出す")
    p.add_argument("src", help="remote:path")
    p.add_argument("dest", help="ローカルのディレクトリ")
    p.add_argument("--force", action="store_true", help="写しが同じ版でも取り直す")
    p.add_argument("--watch", action="store_true", help="更新を監視して自動同期し続ける")
    p.add_argument("--poll", type=int, default=30, help="--watch 時のポーリング間隔（秒）")
    p.add_argument("--include", action="append", default=[], metavar="PATTERN",
                   help="含める相対パターン（複数指定可）")
    p.add_argument("--exclude", action="append", default=[], metavar="PATTERN",
                   help="除外する相対パターン（複数指定可、include より優先）")
    p.set_defaults(func=cmd_pull)

    p_inv = sub.add_parser(
        "invite",
        help="RunPod 等向けの読み取り専用招待トークン (Base64) を作成・参加する",
    )
    p_inv.add_argument("action", choices=["create", "join"])
    p_inv.add_argument("target", nargs="?", default="", help="create 時はリモート名、join 時はトークン")
    p_inv.add_argument("--name", help="作成先 / 参加先のリモート名")
    p_inv.add_argument("--bootstrap-url", help="create 時に curl | bash 用の 1 行コマンドを生成する URL")
    p_inv.add_argument("--write-path", help="create 時に RunPod 出力専用のサブパスを L1 委譲してトークンに含める")
    p_inv.add_argument("--write-name", help="join 時に登録する出力用リモート名（既定 <name>-out）")
    p_inv.add_argument("--root-key", help="--write-path 用の L1 委譲を署名する親/root 秘密鍵")
    p_inv.add_argument("--ttl-days", type=int, default=1, help="一時書き手委譲の有効期間（日、既定 1）")
    p_inv.add_argument("--write-epoch", type=int, help="一時書き手委譲の epoch（省略時は自動 +1）")
    p_inv.add_argument("--candidacy", action="store_true", help="join 時に /v1/candidacy で primary を再解決する")
    p_inv.add_argument("--workdir", help="join 時の作業ディレクトリ")
    p_inv.add_argument("--dest", help="join --sync/--watch 時の出力先ディレクトリ")
    p_inv.add_argument("--sync", action="store_true", help="join 後に初回 pull を実行する")
    p_inv.add_argument("--watch", action="store_true", help="join 後に自動同期ループを開始する")
    p_inv.add_argument("--poll", type=int, default=30, help="自動同期のポーリング間隔（秒）")
    p_inv.set_defaults(func=cmd_invite)

    p_share = sub.add_parser(
        "share",
        help="RunPod 等向けの 1 行ブートストラップコマンド (curl | bash) を発行する",
    )
    p_share.add_argument("remote", help="共有元のリモート名")
    p_share.add_argument("--name", help="参加先のリモート名")
    p_share.add_argument(
        "--bootstrap-url",
        help="bootstrap.sh の URL（省略時は DFS_BOOTSTRAP_URL または registry の /bootstrap.sh）",
    )
    p_share.add_argument("--token-only", action="store_true", help="curl コマンドではなくトークン文字列だけを出す")
    p_share.add_argument("--write-path", help="RunPod 出力専用のサブパスを L1 委譲してトークンに含める")
    p_share.add_argument("--write-name", help="参加先に登録する出力用リモート名（既定 <name>-out）")
    p_share.add_argument("--root-key", help="--write-path 用の L1 委譲を署名する親/root 秘密鍵")
    p_share.add_argument("--ttl-days", type=int, default=1, help="一時書き手委譲の有効期間（日、既定 1）")
    p_share.add_argument("--write-epoch", type=int, help="一時書き手委譲の epoch（省略時は自動 +1）")
    p_share.add_argument("--candidacy", action="store_true", help="join 時に /v1/candidacy で primary を再解決する")
    p_share.add_argument("--poll", type=int, default=30, help="自動同期のポーリング間隔（秒）")
    p_share.set_defaults(func=cmd_share)

    p_join = sub.add_parser(
        "join",
        help="後から別ドメイン / root ハブ / 招待 URI に参加する",
    )
    p_join.add_argument("target", help="参加先ドメイン・URL または dfs-invite:// URI")
    p_join.add_argument("--name", help="登録するリモート名（既定: 接続先ホスト名）")
    p_join.add_argument("--path", help="サブツリーパス（例: /example.com/shared）")
    p_join.add_argument("--key", help="書き込み用 Ed25519 秘密鍵パス")
    p_join.add_argument("--secret", help="ツリー共有シークレット")
    p_join.add_argument("--svc", default="local", help="設定を更新するローカル dfssvc 名（既定: local）")
    p_join.add_argument("--workdir", help="作業ディレクトリ（招待 URI 利用時）")
    p_join.add_argument("--sync", action="store_true", help="join 後に即時 pull する（招待 URI 利用時）")
    p_join.set_defaults(func=cmd_join)

    p_quit = sub.add_parser(
        "quit",
        help="参加中のドメインから離脱し、ローカル単独モードへ戻す",
    )
    p_quit.add_argument("name", nargs="?", help="削除するリモート名（省略時は dfssvc の参加設定のみ解除）")
    p_quit.add_argument("--svc", default="local", help="解除するローカル dfssvc 名（既定: local）")
    p_quit.add_argument("--all", action="store_true", help="同じドメインの登録済みリモートも一括削除する")
    p_quit.set_defaults(func=cmd_quit)

    p_fs = sub.add_parser("fs", help="ローカルの CoW 検出・スナップショット（リモート不要）")
    p_fs.add_argument("action", choices=["info", "snapshot", "materialize"])
    p_fs.add_argument("path", help="対象ディレクトリ")
    p_fs.add_argument("snap_id", nargs="?", help="snapshot の ID (例: v1)")
    p_fs.add_argument("dst", nargs="?", help="materialize の出力先")
    p_fs.add_argument(
        "--src", dest="src",
        help="materialize の入力 (省略時は path/.clayfs/snapshots/<snap_id>)",
    )
    p_fs.add_argument(
        "--backend", default="auto",
        help="copy / reflink / fast_clone / auto (既定 auto)",
    )
    p_fs.set_defaults(func=cmd_fs)

    p = sub.add_parser("mkdir", help="リモートにディレクトリを作る")
    p.add_argument("remote", nargs="?", default="", help="remote:dir（--remote 指定時は省略可）")
    p.set_defaults(func=cmd_mkdir)

    p = sub.add_parser("rm", help="リモートのファイル（または --recursive でディレクトリ）を消す")
    p.add_argument("remote", nargs="?", default="", help="remote:path（--remote 指定時は省略可）")
    p.add_argument("-R", "--recursive", action="store_true", help="ディレクトリを中身ごと消す")
    p.add_argument("--rmdirs", action="store_true",
                   help="消した後に空になったディレクトリも片付ける")
    p.add_argument("-n", "--dry-run", action="store_true")
    p.set_defaults(func=cmd_rm)

    p = sub.add_parser("rmdir", help="空のディレクトリを消す（中身があれば断る）")
    p.add_argument("remote", nargs="?", default="", help="remote:dir（--remote 指定時は省略可）")
    p.add_argument("-n", "--dry-run", action="store_true")
    p.set_defaults(func=cmd_rmdir)

    p = sub.add_parser("purge", help="指定パスの中身をすべて消す")
    p.add_argument("remote", nargs="?", default="", help="remote:path（--remote 指定時は省略可）")
    p.add_argument("-n", "--dry-run", action="store_true")
    p.set_defaults(func=cmd_purge)

    p = sub.add_parser("check", help="リモートとローカルを比べる")
    p.add_argument("remote", help="remote:path")
    p.add_argument("local", help="ローカルのディレクトリ")
    p.set_defaults(func=cmd_check)

    p = sub.add_parser("about", help="リモートの設定と先頭版を表示する")
    p.add_argument("remote", nargs="?", default="", help="remote:path（--remote 指定時は省略可）")
    p.set_defaults(func=cmd_about)

    p = sub.add_parser("touch", help="リモートの作業ディレクトリを初期化する")
    p.add_argument("remote", nargs="?", default="", help="remote:path（--remote 指定時は省略可）")
    p.set_defaults(func=cmd_touch)

    # サーバ側は cli.py のものをそのまま使う
    p_serve = sub.add_parser("serve", help="L2 名簿 (HTTP) と L3 OST (TLS) を起動する")
    p_serve.add_argument("--bind", default="0.0.0.0")
    p_serve.add_argument("--registry-port", type=int, default=9440)
    p_serve.add_argument("--ost-port", type=int, default=9443)
    p_serve.add_argument("--root-anchor", default="/example.com")
    p_serve.add_argument("--root-pubkey", required=True)
    p_serve.add_argument("--state-dir", default="~/.dfs_server")
    p_serve.add_argument(
        "--ost-dir",
        help="L3 OST チャンクの保存先（既定: <state-dir>/ost_chunks）",
    )
    p_serve.add_argument("--role", choices=["primary", "secondary"])
    p_serve.add_argument("--role-epoch", type=int)
    p_serve.add_argument(
        "--advertise",
        help="L2 が L3 OST の場所として広告するホスト名/IP（既定は bind から推定）",
    )
    p_serve.add_argument(
        "--replica", action="append", default=[],
        help="主名簿から複製する代替名簿 URL（複数指定可）",
    )
    p_serve.set_defaults(func=cmd_serve)

    p_promote = sub.add_parser(
        "promote", help="停止中の registry state を primary に昇格する"
    )
    p_promote.add_argument("--state-dir", default="~/.dfs_server")
    p_promote.add_argument("--role-epoch", type=int)
    p_promote.set_defaults(func=cmd_promote)

    p_libp2p = sub.add_parser(
        "libp2p-serve", help="OST の chunk ディレクトリを libp2p/QUIC で配布する"
    )
    p_libp2p.add_argument(
        "--chunks-dir", required=True,
        help="過去に save_ost_chunks が作った .blk ディレクトリ",
    )
    p_libp2p.add_argument(
        "--listen", action="append", default=[],
        help="QUIC multiaddr（既定 /ip4/0.0.0.0/udp/0/quic-v1）",
    )
    p_libp2p.add_argument("--psk", help="private swarm 用 pre-shared key")
    p_libp2p.set_defaults(func=cmd_libp2p_serve)

    p_del = sub.add_parser("delegate", help="L1 委譲を作って L2 名簿へ登録する")
    p_del.add_argument("--parent", required=True)
    p_del.add_argument("--path", required=True)
    p_del.add_argument("--signing-key", required=True)
    p_del.add_argument("--writer-pubkey", required=True)
    p_del.add_argument("--epoch", type=int, default=1)
    p_del.add_argument("--base-version", type=int, default=0)
    p_del.add_argument("--ttl-days", type=int, default=365)
    p_del.add_argument("--registry")
    p_del.add_argument("--output")
    p_del.set_defaults(func=cmd_delegate)

    p_web = sub.add_parser(
        "web",
        help="スマホ等から使えるブラウザ向けファイル共有 & Web CLI サーバを起動する",
    )
    p_web.add_argument(
        "remote",
        nargs="?",
        help="対象リモート名（登録が 1 つだけなら省略可）",
    )
    p_web.add_argument(
        "--bind",
        default=None,
        help="待機アドレス（既定 0.0.0.0、--base-path/--public-url 指定時は 127.0.0.1）",
    )
    p_web.add_argument(
        "--port",
        type=int,
        default=None,
        help="待機ポート（省略時は 8080 から空きポートを自動選択）",
    )
    p_web.add_argument(
        "--read-only",
        action="store_true",
        help="閲覧・ダウンロード専用で公開する",
    )
    p_web.add_argument(
        "--token",
        help="アクセストークン（省略時は起動ごとにランダム生成）",
    )
    p_web.add_argument(
        "--ttl",
        type=int,
        default=0,
        help="共有リンクの有効期限（秒。0 は無期限、既定 0）",
    )
    p_web.add_argument(
        "--base-path",
        default="",
        help="Caddy 等のリバースプロキシ配下プレフィックス（例: /dfs）",
    )
    p_web.add_argument(
        "--public-url",
        default="",
        help="案内表示用の公開 URL（例: https://yashiki.top/dfs）",
    )
    p_web.add_argument(
        "--secure-cookie",
        action="store_true",
        help="セッションクッキーに常に Secure 属性を付ける",
    )
    p_web.set_defaults(func=cmd_web)

    return parser


def _lan_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("192.0.2.1", 80))
            return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"


def _resolve_self_claimed_domain_remote(name: str) -> Optional[Remote]:
    """未登録のドメイン名（例: yashiki.top）を解決する。

    実在する公開 root の偽装を防ぐため、先に ``_dfs.<domain>`` の TXT レコード有無を確認し、
    存在する場合は DNSSEC 検証済みレコードのみを受け入れる。TXT が無い場合のみ自称ドメインを許可する。
    """
    if "." not in name or "/" in name:
        return None
    from .dnssec import DEFAULT_RECORD_PREFIX, has_txt_record
    import ipaddress

    is_ip = False
    try:
        ipaddress.ip_address(name.strip("[]"))
        is_ip = True
    except ValueError:
        pass

    record_name = f"{DEFAULT_RECORD_PREFIX}.{name}"
    if not is_ip and has_txt_record(record_name):
        try:
            disc = discover_domain(name, record_name=record_name)
        except DiscoveryError as e:
            raise UsageError(
                f"{record_name} に TXT レコードが存在するため DNSSEC 検証が必須ですが失敗しました: {e}"
            ) from e
        return Remote(
            name=name,
            registry=disc.primary_url,
            registry_alternates=list(disc.alternate_urls),
            key="",
            path=disc.root_anchor,
            secret="",
            role_epoch=int(disc.epoch),
            root_pubkey=disc.root_pubkey,
            root_fingerprint=ssh_key_fingerprint(disc.root_pubkey),
            read_only=True,
        )

    candidates = [f"http://{name}:{DEFAULT_REGISTRY_PORT}", f"https://{name}"]
    for url in candidates:
        if not _probe_registry_tcp(url, timeout=1.0):
            continue
        try:
            reg = cli_mod.RemoteRegistryClient([url])
            info = reg.root_anchor_info()
            root_pub = str(info.get("root_pubkey") or "").strip()
            anchor = str(info.get("root_anchor") or f"/{name}").strip() or f"/{name}"
            if root_pub:
                return Remote(
                    name=name,
                    registry=url,
                    key="",
                    path=anchor,
                    secret="",
                    root_pubkey=root_pub,
                    root_fingerprint=ssh_key_fingerprint(root_pub),
                    read_only=True,
                )
        except Exception:  # noqa: BLE001
            continue
    return None


def _resolve_remote(store: RemoteStore, name: str) -> Remote:
    """登録済みリモート・dfssvc・自称ドメインの順に解決する。"""
    if name in store.remotes:
        return store.remotes[name]
    svc_remote = _ensure_remote_from_service(store, name)
    if svc_remote is not None:
        return svc_remote
    domain_remote = _resolve_self_claimed_domain_remote(name)
    if domain_remote is not None:
        return domain_remote
    return store.get(name)


def _ensure_remote_from_service(store: RemoteStore, service_name: str) -> Optional[Remote]:
    """dfssvc の起動済みサービスからリモート定義を自動生成して登録する。"""
    from .svc import ServiceStore

    svc_store = ServiceStore()
    svc = svc_store.services.get(service_name)
    if svc is None:
        return None
    root_pub_text = ""
    if svc.root_pub and Path(svc.root_pub).is_file():
        root_pub_text = Path(svc.root_pub).read_text(encoding="utf-8").strip()
    remote = Remote(
        name=svc.name,
        registry=svc.registry_url,
        key=svc.writer_key,
        ost=svc.ost_endpoint,
        path=svc.sub_path or f"{svc.root_anchor.rstrip('/')}/{svc.name}",
        secret=secrets.token_urlsafe(18),
        role_epoch=int(svc.role_epoch or 1),
        root_pubkey=root_pub_text,
        root_fingerprint=ssh_key_fingerprint(root_pub_text) if root_pub_text else "",
        read_only=not bool(svc.writer_key),
    )
    store.set(remote)
    print(f"[dfscli web] dfssvc '{svc.name}' からリモート設定を自動登録しました")
    return remote


def cmd_web(args: argparse.Namespace) -> int:
    """スマホ等のブラウザ向けファイル共有 & Web CLI サーバを起動する。"""
    from .svc import ServiceStore
    from .web import DFSWebBackend, WebConfig, find_free_port, start_web_server

    store = RemoteStore()
    remote_name = args.remote
    if remote_name:
        if remote_name not in store.remotes:
            _ensure_remote_from_service(store, remote_name)
        remote = store.get(remote_name)
    else:
        svc_store = ServiceStore()
        running_svcs = [n for n, s in svc_store.services.items() if s.is_running()]
        names = store.names()
        if running_svcs:
            pick = "local" if "local" in running_svcs else running_svcs[0]
            if pick not in store.remotes:
                _ensure_remote_from_service(store, pick)
            remote_name = pick
        elif names:
            remote_name = "local" if "local" in names else names[0]
        elif svc_store.services:
            pick = "local" if "local" in svc_store.services else next(iter(svc_store.services))
            _ensure_remote_from_service(store, pick)
            remote_name = pick
        else:
            raise UsageError(
                "リモートが未登録です。先に 'dfssvc start' または 'dfscli config create' を実行してください。"
            )
        print(f"[dfscli web] 自動選択: {remote_name}")
        remote = store.get(remote_name)
    read_only = bool(args.read_only or remote.read_only)
    node = open_remote(remote, create=True)

    def _sync(force: bool) -> int:
        return refresh_cache(node, force=force)

    def _push_now() -> int:
        env, _wire = _push(node, remote)
        return int(env["payload"]["version"])

    def _status_now() -> Dict[str, Any]:
        return {
            "registry": remote.registry,
            "path": remote.path or "/",
            "workdir": str(node.clayfs.work_tree),
        }

    backend = DFSWebBackend(
        work_tree=node.clayfs.work_tree,
        remote_name=remote.name,
        read_only=read_only,
        sync_fn=_sync,
        push_fn=_push_now,
        status_fn=_status_now,
    )
    version = backend.sync(force=False)
    token = (args.token or "").strip() or secrets.token_urlsafe(18)
    base_path = (args.base_path or "").strip()
    if base_path and not base_path.startswith("/"):
        base_path = "/" + base_path
    base_path = base_path.rstrip("/")

    bind = args.bind
    if bind is None:
        bind = "127.0.0.1" if (base_path or args.public_url) else "0.0.0.0"
    port = int(args.port) if args.port is not None else find_free_port(bind, 8080)

    cfg = WebConfig(
        remote_name=remote.name,
        token=token,
        read_only=read_only,
        ttl_seconds=max(0, int(args.ttl or 0)),
        base_path=base_path,
        secure_cookie=bool(args.secure_cookie),
    )
    httpd = start_web_server(backend, cfg, bind=bind, port=port)
    bound_port = httpd.server_address[1]
    host_display = _lan_ip() if bind in ("0.0.0.0", "::") else bind
    host_display = f"[{host_display}]" if ":" in host_display else host_display
    prefix_display = base_path + "/" if base_path else "/"
    access_url = f"http://{host_display}:{bound_port}{prefix_display}?token={token}"

    print(f"[dfscli web] Remote   : {remote.name} (v{version}, {'read-only' if read_only else 'read-write'})")
    print(f"[dfscli web] Listen   : {bind}:{bound_port}")
    print(f"[dfscli web] Open URL : {access_url}")
    if args.public_url:
        pub_base = args.public_url.rstrip("/")
        qr_target = f"{pub_base}/?token={token}"
        print(f"[dfscli web] Public   : {qr_target}")
    else:
        qr_target = access_url
    if cfg.ttl_seconds > 0:
        print(f"[dfscli web] TTL      : {cfg.ttl_seconds}s")
    if shutil.which("qrencode"):
        try:
            qr = subprocess.run(
                ["qrencode", "-t", "UTF8", qr_target],
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
            )
            if qr.returncode == 0 and qr.stdout.strip():
                print(qr.stdout.rstrip())
        except OSError:
            pass
    print("[dfscli web] Ctrl-C で停止します")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[dfscli web] 停止しました")
    finally:
        httpd.server_close()
    return 0


def _version() -> str:
    try:
        from . import __version__

        return __version__
    except Exception:  # noqa: BLE001
        return "unknown"


def _friendly_error(exc: BaseException) -> int:
    """例外を利用者向けの 1 行にして返す（終了コード付き）。"""
    if isinstance(exc, ConflictError):
        print(
            f"[dfscli] 単一書き手の競合: {exc}\n"
            "        他の端末が先に書きました。'dfscli pull' の後でやり直してください。",
            file=sys.stderr,
        )
        return 7
    if isinstance(exc, RollbackDetectedError):
        print(f"[dfscli] 巻き戻しを検出しました（B6）: {exc}", file=sys.stderr)
        return 8
    if isinstance(exc, SilentDropDetectedError):
        print(f"[dfscli] 黙った破棄を検出しました（B7）: {exc}", file=sys.stderr)
        return 9
    if isinstance(exc, ServiceUnavailableError):
        print(f"[dfscli] L2/L3 に到達できません: {exc}", file=sys.stderr)
        return 6
    if isinstance(exc, (UsageError, RemoteError)):
        print(f"[dfscli] {exc}", file=sys.stderr)
        return 2
    print(f"[dfscli] 予期しないエラー: {type(exc).__name__}: {exc}", file=sys.stderr)
    return 1


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args) or 0)
    except KeyboardInterrupt:
        print("\n[dfscli] 中断しました", file=sys.stderr)
        return 130
    except SystemExit:
        raise
    except BaseException as e:  # noqa: BLE001 - CLI の最外殻でまとめて扱う
        return _friendly_error(e)


if __name__ == "__main__":
    raise SystemExit(main())
