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
import tarfile
import tempfile
import zlib
import time
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from . import cli as cli_mod
from .archive import ArchiveError, catalog, create_archive, extract_bundle, verify_bundle
from .dnssec import Discovery, DiscoveryError, discover_domain

# L2 名簿の既定ポート。ホスト名だけで済むようにする（例: --registry 172.16.1.60）。
DEFAULT_REGISTRY_PORT = 9440
# dfssvc が立てるサーバの既定。こちらは連続した空きを選ぶので 19440 から。
DEFAULT_LOCAL_REGISTRY_PORT = 19440
from .l2_registry import ConflictError, ServiceUnavailableError
from .l4_log import (
    RollbackDetectedError,
    SilentDropDetectedError,
)
from .l5_clayfs import DFSNode
from .crypto import normalize_path, ssh_key_fingerprint
from .fs.core import remove_tree
from .path_safety import UnsafePathError, copyfile_no_follow, safe_target
from .paths import config_dir, restrict_to_owner
from .private_io import ensure_private_dir, write_private_json
from .remotes import Remote, RemoteError, RemoteStore, split_remote_spec

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
        priv_key = Path(remote.key).expanduser()
        _ensure_keypair(priv_key)
        if not remote.secret:
            # tree_secret はサーバに置かない共有秘密なので、L2 からは引けない。
            # 空のまま暗号化すると、誰でも復号できる木を作ってしまう。
            raise UsageError(
                f"Remote {remote.name!r} has no tree_secret.\n"
                f"Set it with 'dfscli config create {remote.name} ... --secret <共有秘密>' "
                f"(or edit {RemoteStore().path})."
            )
        registry = cli_mod.RemoteRegistryClient(remote.registry_urls())
        ost_value = resolve_ost(remote, registry)
        sub_path = resolve_path(remote, registry)
        host, _, port_str = ost_value.partition(":")
        if not port_str:
            raise UsageError(f"Cannot parse L3 OST endpoint {ost_value!r} for remote {remote.name!r}")
        mount_root.mkdir(parents=True, exist_ok=True)
        (mount_root / "tree").mkdir(exist_ok=True)
        ensure_private_dir(mount_root / ".clayfs")
        cfg = {
            "delegation_epoch": int(remote.epoch),
            "role_epoch": int(remote.role_epoch),
            "compression": remote.compression,
            "node_name": remote.node_name or remote.name,
            "ost_alternates": list(remote.ost_alternates),
            "libp2p_peers": list(remote.libp2p_peers),
            "libp2p_psk": remote.libp2p_psk,
            "ost_host": host,
            "ost_port": int(port_str),
            "priv_key": str(priv_key),
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
    if str(cfg.get("compression", "none") or "none") != remote.compression:
        cfg["compression"] = remote.compression
        changed = True
    if changed:
        write_private_json(cfg_path, cfg)
        node, cfg, _reg = cli_mod.load_node_from_mount(mount_root)
    # 作業ディレクトリの config に root_pubkey が無い（古い形式）なら、リモート定義から
    # 補って書き戻す。信頼の根はリモート定義（remotes.json）が持つ。
    if not cfg.get("root_pubkey") and remote.root_pubkey:
        cfg["root_pubkey"] = remote.root_pubkey
        write_private_json(cfg_path, cfg)
        node.l4.root_pubkey = remote.root_pubkey.strip()
    return node


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


def _push(node: DFSNode, remote: Remote, delegated_mounts: Optional[Dict[str, str]] = None) -> Tuple[dict, int]:
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
    if src.is_file():
        root_prefix = f"{src.parent.name}/" if include_root_name else ""
        out[f"{root_prefix}{src.name}"] = src
        return out
    if not src.is_dir():
        raise UsageError(f"Local path does not exist: {src}")
    for item in sorted(src.rglob("*")):
        if item.is_dir():
            continue
        if item.name in (".DS_Store",) or item.name.startswith("._"):
            continue
        if any(part in (".clayfs", ".git") for part in item.relative_to(src).parts):
            continue
        rel = item.relative_to(src).as_posix()
        out[f"{src.name}/{rel}" if include_root_name else rel] = item
    return out


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
            pid = node.crypto.compute_plain_id(data).hex()
            if pid != entry.get("plain_id", ""):
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
        prune_empty_dirs(node)


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
def cmd_listremotes(args: argparse.Namespace) -> int:
    store = RemoteStore()
    for name in store.names():
        r = store.remotes[name]
        print(f"{name}: {r.registry} {r.path}")
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
    netloc = parts.hostname
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


def cmd_config(args: argparse.Namespace) -> int:
    store = RemoteStore()
    if args.action == "create":
        dnssec_domain = getattr(args, "dnssec_domain", None)
        if not args.registry and not dnssec_domain:
            raise UsageError("config create には --registry か --dnssec-domain が必要です")

        discovery: Optional[Discovery] = None
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
            root_source = "DNSSEC"
            if args.root_pubkey:
                rp = Path(args.root_pubkey).expanduser()
                if not rp.is_file():
                    raise UsageError(f"--root-pubkey のファイルがありません: {rp}")
                explicit_root = rp.read_text(encoding="utf-8").strip()
                if explicit_root != root_pubkey:
                    raise UsageError(
                        "--root-pubkey が DNSSEC discovery の root 公開鍵と一致しません"
                    )
        elif args.root_pubkey:
            rp = Path(args.root_pubkey).expanduser()
            if not rp.is_file():
                raise UsageError(f"--root-pubkey のファイルがありません: {rp}")
            root_pubkey = rp.read_text(encoding="utf-8").strip()
            root_fingerprint = ssh_key_fingerprint(root_pubkey)
            root_source = f"指定（{rp}）"
        else:
            registry_client = cli_mod.RemoteRegistryClient(
                [registry, *registry_alternates]
            )
            info = registry_client.root_anchor_info()
            root_pubkey = (info.get("root_pubkey") or "").strip()
            if root_pubkey:
                root_fingerprint = ssh_key_fingerprint(root_pubkey)
                root_source = "名簿から取得（TOFU）"
                # 上書きされた root アンカーも記録して、あとで気づけるようにする
                info_anchor = info.get("root_anchor") or ""

        # --secret が無ければ端末から読む（エコーなし）。
        secret = args.secret
        secret_from_prompt = False
        if not secret and not args.no_prompt:
            secret = prompt_secret(
                f"{args.name} の tree_secret: ",
                f"{args.name} の tree_secret（確認のためもう一度）: ",
            )
            secret_from_prompt = bool(secret)

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
            role_epoch=int(getattr(args, "role_epoch", 1)),
            compression=str(getattr(args, "compression", "none") or "none"),
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
            print(f"                 これ以降この指紋だけを信頼します（違う値を返す名簿は拒否）")
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


def cmd_archive(args: argparse.Namespace) -> int:
    """版単位の archive bundle / torrent を作成・検証・復元する。"""
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

    raise UsageError(f"unknown archive action: {args.action}")


def cmd_history(args: argparse.Namespace) -> int:
    """L2 の署名済み L4 ログ履歴を表示する。"""
    store = RemoteStore()
    name, sub = split_remote_spec(args.remote, args.remote_name)
    remote = store.get(name)
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
    node = open_remote(store.get(name), create=True)
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
    node = open_remote(store.get(name), create=True)
    for e in _rel_entries(node, _norm_prefix(sub)):
        if e["type"] == "dir":
            print(e["rel"] + "/")
    return 0


def cmd_lsl(args: argparse.Namespace) -> int:
    store = RemoteStore()
    name, sub = split_remote_spec(args.remote, args.remote_name)
    node = open_remote(store.get(name), create=True)
    for e in _rel_entries(node, _norm_prefix(sub)):
        rel = e["rel"] + ("/" if e["type"] == "dir" else "")
        size = e.get("size", 0)
        print(f"{size:>12}  {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())}  {rel}")
    return 0


def cmd_lsjson(args: argparse.Namespace) -> int:
    store = RemoteStore()
    name, sub = split_remote_spec(args.remote, args.remote_name)
    node = open_remote(store.get(name), create=True)
    rows = []
    for e in _all_entries(node, _norm_prefix(sub)):
        row = {
            "Path": e["path"],
            "Name": e["path"].rsplit("/", 1)[-1],
            "Size": int(e.get("size", 0)),
            "IsDir": e["type"] == "dir",
            "Type": e["type"],
            "WireId": e.get("wire_id", ""),
        }
        rows.append(row)
    print(json.dumps(rows, ensure_ascii=False, indent=2))
    return 0


def cmd_size(args: argparse.Namespace) -> int:
    store = RemoteStore()
    name, sub = split_remote_spec(args.remote, args.remote_name)
    node = open_remote(store.get(name), create=True)
    files = [e for e in _all_entries(node, _norm_prefix(sub)) if e["type"] == "file"]
    total = sum(int(e.get("size", 0)) for e in files)
    print(f"Total objects: {len(files)}")
    print(f"Total size: {total} ({_human_size(total)})")
    print(f"Unique chunks (wire_id): {len({e['wire_id'] for e in files})}")
    return 0


def cmd_cat(args: argparse.Namespace) -> int:
    store = RemoteStore()
    name, sub = split_remote_spec(args.remote, args.remote_name)
    if not sub:
        raise UsageError("cat にはファイルのパスが必要です（例: remote:dir/file.txt）")
    node = open_remote(store.get(name), create=True)
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

    operations = LocalTreeFuse(
        node.clayfs.work_tree,
        flush_to_dfs,
        read_only=args.read_only,
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
    if args.read_only:
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


def cmd_pull(args: argparse.Namespace) -> int:
    """リモートの指定パスを、ローカルディレクトリへ取り出す。"""
    store = RemoteStore()
    name, sub = split_remote_spec(args.src, args.remote_name)
    remote = store.get(name)
    prefix = _norm_prefix(sub)
    node = open_remote(remote, create=True)
    version = refresh_cache(node, force=args.force)
    path_filter = _path_filter(args)

    work_root = node.clayfs.work_tree.resolve(strict=False)
    src_root = work_root if not prefix else work_root / prefix
    try:
        src_root.resolve(strict=False).relative_to(work_root)
    except ValueError as e:
        raise UsageError(f"Remote path escapes the work tree: {prefix!r}") from e
    if not src_root.exists():
        raise UsageError(f"Remote path does not exist: {remote.name}:{prefix}")

    dest = Path(args.dest).expanduser()
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

    print(f"[dfscli] pull OK <- v{version} | {count} ファイル -> {dest}")
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
        # 掃除の起点は、消したディレクトリがある位置にする。
        # 作業ツリー全体を掃除すると、無関係な空ディレクトリまで消えてしまう。
        start = _tree_path(node, sub) if is_dir and sub else node.clayfs.work_tree
        removed_dirs = prune_empty_dirs(node, start=start)

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
    parent = str(Path(sub).parent)
    prune_empty_dirs(node, start=_tree_path(node, parent) if parent != "." else node.clayfs.work_tree)
    log_env, sent = _push(node, remote)
    print(f"[dfscli] rmdir OK -> v{log_env['payload']['version']} | {sub}/ | sent={sent} B")
    return 0


def cmd_purge(args: argparse.Namespace) -> int:
    """指定パスの中身をすべて消す（ディレクトリ自身も消す）。"""
    store = RemoteStore()
    name, sub = split_remote_spec(args.remote, args.remote_name)
    remote = store.get(name)
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
        "--compression", choices=["none", "zstd"], default="none",
        help="フォルダ xattr が無い場合の既定圧縮（既定 none）",
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
    if args_name_required:
        p.add_argument("name", help="リモートの名前（例: scw）")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dfscli",
        description="dfscli: dfs を rclone ライクに扱う CLI（リモート名で場所を指す）",
    )
    parser.add_argument(
        "--remote", dest="remote_name", metavar="NAME",
        help="`path` だけを書いたときに使うリモート名（rclone の :backend: 相当）",
    )
    parser.add_argument("--version", action="version", version=f"dfscli {_version()}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("listremotes", help="定義済みのリモートを一覧する")
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

    p_arch = sub.add_parser("archive", help="版の archive bundle / BitTorrent を作る")
    p_arch.add_argument("action", choices=["create", "verify", "extract", "catalog"])
    p_arch.add_argument("source", help="create は remote:path、verify/extract は bundle ディレクトリ")
    p_arch.add_argument("dest", nargs="?", help="extract の出力先")
    p_arch.add_argument("--out", help="create の bundle 出力先（既定 .cwd/dfs-archive-...）")
    p_arch.add_argument("--announce", help="torrent の announce URL（省略可）")
    p_arch.add_argument("--version", type=int, help="archive する版（省略時は先頭版）")
    p_arch.add_argument("--secret", help="extract の tree_secret")
    p_arch.add_argument("--no-prompt", action="store_true", help="secret を端末から読まない")
    p_arch.set_defaults(func=cmd_archive)

    p_history = sub.add_parser("history", help="L4 の版履歴を表示する")
    p_history.add_argument("remote", help="remote:path")
    p_history.add_argument("--limit", type=int, default=50, help="表示件数（既定 50）")
    p_history.set_defaults(func=cmd_history)

    p = sub.add_parser("ls", help="リモートの直下を一覧する（内容は取らない）")
    p.add_argument("remote")
    p.set_defaults(func=cmd_ls)

    p = sub.add_parser("lsd", help="リモートの直下にあるディレクトリだけを一覧する")
    p.add_argument("remote")
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
    p.add_argument("remote")
    p.set_defaults(func=cmd_lsl)

    p = sub.add_parser("lsjson", help="リモートの一覧を JSON で出す")
    p.add_argument("remote")
    p.set_defaults(func=cmd_lsjson)

    p = sub.add_parser("size", help="リモートの合計と重複排除後の塊の数を出す")
    p.add_argument("remote")
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
    p.add_argument("--include", action="append", default=[], metavar="PATTERN",
                   help="含める相対パターン（複数指定可）")
    p.add_argument("--exclude", action="append", default=[], metavar="PATTERN",
                   help="除外する相対パターン（複数指定可、include より優先）")
    p.set_defaults(func=cmd_pull)

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
    p.add_argument("remote", help="remote:dir")
    p.set_defaults(func=cmd_mkdir)

    p = sub.add_parser("rm", help="リモートのファイル（または --recursive でディレクトリ）を消す")
    p.add_argument("remote", help="remote:path")
    p.add_argument("-R", "--recursive", action="store_true", help="ディレクトリを中身ごと消す")
    p.add_argument("--rmdirs", action="store_true",
                   help="消した後に空になったディレクトリも片付ける")
    p.add_argument("-n", "--dry-run", action="store_true")
    p.set_defaults(func=cmd_rm)

    p = sub.add_parser("rmdir", help="空のディレクトリを消す（中身があれば断る）")
    p.add_argument("remote", help="remote:dir")
    p.add_argument("-n", "--dry-run", action="store_true")
    p.set_defaults(func=cmd_rmdir)

    p = sub.add_parser("purge", help="指定パスの中身をすべて消す")
    p.add_argument("remote", help="remote:path")
    p.add_argument("-n", "--dry-run", action="store_true")
    p.set_defaults(func=cmd_purge)

    p = sub.add_parser("check", help="リモートとローカルを比べる")
    p.add_argument("remote", help="remote:path")
    p.add_argument("local", help="ローカルのディレクトリ")
    p.set_defaults(func=cmd_check)

    p = sub.add_parser("about", help="リモートの設定と先頭版を表示する")
    p.add_argument("remote")
    p.set_defaults(func=cmd_about)

    p = sub.add_parser("touch", help="リモートの作業ディレクトリを初期化する")
    p.add_argument("remote")
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

    return parser


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
