#!/usr/bin/env python3
"""
dfs/cli_main.py
rclone ライクな dfs の CLI。

`cli.py` の部品（L2 名簿クライアント、`serve`、`delegate`、ノード構築）をそのまま使い、
「リモート名で場所を指す」操作体系を被せる。

    dfscli listremotes
    dfscli config create scaleway --registry http://192.0.2.60:19440 \\
        --ost 192.0.2.60:19443 --path /example.com/alice/notes \\
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
    ARCHIVE_SCHEMA,
    ArchiveError,
    catalog,
    create_archive,
    download_torrent,
    extract_bundle,
    find_par2_binary,
    locate_downloaded_bundle,
    magnet_for_descriptor,
    repair_with_par2,
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

# L2 名簿の既定ポート。ホスト名だけで済むようにする（例: --registry 192.0.2.60）。
DEFAULT_REGISTRY_PORT = 9440
# dfssvc が立てるサーバの既定。こちらは連続した空きを選ぶので 19440 から。
DEFAULT_LOCAL_REGISTRY_PORT = 19440
from .l2_registry import ConflictError, ServiceUnavailableError
from .l1_delegation import DelegationError, create_delegation_envelope, verify_delegation_chain
from .l4_log import (
    FILE_CHUNK_BYTES,
    L4LogClient,
    MerkleTreeBuilder,
    RollbackDetectedError,
    SilentDropDetectedError,
)
from .l5_fs import DFSNode
from .crypto import KDF_DEFAULT, KDF_LEGACY_SHA256, ssh_key_fingerprint
from .fs.core import remove_tree
from .path_safety import UnsafePathError, copyfile_no_follow, safe_target
from .paths import config_dir, restrict_to_owner
from .private_io import ensure_private_dir, write_private_json
from .remotes import NAME_RE, Remote, RemoteError, RemoteStore, matching_ost_cert_pin, split_remote_spec

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

    try:
        res = subprocess.run(
            ["ssh-keygen", "-y", "-f", str(priv_key)],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=15,
        )
    except subprocess.TimeoutExpired as e:
        raise UsageError(f"Timed out reading public key from {priv_key}") from e
    if res.returncode != 0:
        raise UsageError(f"Cannot read public key from {priv_key}: {res.stderr.strip()}")
    return res.stdout.strip()


def _ensure_remote_secret(
    remote: Remote, store: Optional[RemoteStore] = None
) -> Remote:
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
        target_store = store if store is not None else RemoteStore()
        if target_store.get(remote.name) is not None:
            target_store.set(remote)
            print(
                f"[dfscli] 共有秘密鍵 (tree_secret) を保存しました: {target_store.path}",
                file=sys.stderr,
            )
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
        ost_cert_sha256 = (remote.ost_cert_sha256 or "").strip().lower()
        ost_info_cache: Optional[Dict[str, Any]] = None
        if not remote.ost or not ost_cert_sha256:
            try:
                ost_info_cache = registry.ost_info()
            except Exception:
                ost_info_cache = None
        if not remote.ost and ost_info_cache is not None:
            for alt in ost_info_cache.get("alternates") or []:
                norm_alt = Remote.normalize_ost(str(alt))
                if norm_alt and norm_alt != ost_value and norm_alt not in ost_alternates:
                    ost_alternates.append(norm_alt)
        for reg_u in remote.registry_urls():
            if "/relay/" in reg_u:
                norm_rel = Remote.normalize_ost(reg_u)
                if norm_rel and norm_rel != ost_value and norm_rel not in ost_alternates:
                    ost_alternates.append(norm_rel)
        if not ost_cert_sha256 and ost_info_cache is not None:
            ost_cert_sha256 = matching_ost_cert_pin(ost_value, ost_info_cache)
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
            "ost_cert_sha256": ost_cert_sha256,
            "allow_tofu": bool(remote.allow_tofu),
            "priv_key": priv_key_value,
            "read_only": bool(remote.read_only),
            "registry_url": remote.registry,
            "registry_alternates": list(remote.registry_alternates),
            "root_pubkey": remote.root_pubkey,
            "sub_path": sub_path,
            "tree_secret": remote.secret,
            "kdf": remote.kdf,
        }
        write_private_json(cfg_path, cfg)

    node, cfg, _reg = cli_mod.load_node_from_mount(mount_root)
    # リモート定義は接続先の正本。既存の作業 config が古い場合も、
    # 主名簿・代替名簿・複製 OST をリモート定義に合わせる。
    changed = False
    tree_identity_changed = False
    ost_changed = False
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
            ost_changed = True
    if (
        cfg.get("registry_url") != remote.registry
        or list(cfg.get("registry_alternates") or []) != list(remote.registry_alternates)
    ):
        cfg["registry_url"] = remote.registry
        cfg["registry_alternates"] = list(remote.registry_alternates)
        changed = True
    desired_alts = list(remote.ost_alternates) if remote.ost_alternates else list(cfg.get("ost_alternates") or [])
    for reg_u in remote.registry_urls():
        if "/relay/" in reg_u:
            norm_rel = Remote.normalize_ost(reg_u)
            if norm_rel and norm_rel != str(cfg.get("ost_endpoint", "")) and norm_rel not in desired_alts:
                desired_alts.append(norm_rel)
    if list(cfg.get("ost_alternates") or []) != desired_alts:
        cfg["ost_alternates"] = desired_alts
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
    elif not remote.path and (
        cfg.get("registry_url") != remote.registry
        or (remote.root_pubkey and cfg.get("root_pubkey") != remote.root_pubkey)
        or getattr(node.l4.pin, "version", 0) == 0
    ):
        try:
            resolved_sub = resolve_path(remote, node.registry)
        except Exception:
            resolved_sub = ""
        if resolved_sub and cfg.get("sub_path") != resolved_sub:
            cfg["sub_path"] = resolved_sub
            changed = True
            tree_identity_changed = True
    if not remote.secret and not str(cfg.get("tree_secret", "") or ""):
        remote = _ensure_remote_secret(remote)
    if remote.secret and cfg.get("tree_secret") != remote.secret:
        cfg["tree_secret"] = remote.secret
        changed = True
    current_kdf = cfg.get("kdf")
    if current_kdf is None:
        current_kdf = KDF_LEGACY_SHA256
    if str(current_kdf) != remote.kdf:
        cfg["kdf"] = remote.kdf
        changed = True
        tree_identity_changed = True
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
    desired_ost_pin = (remote.ost_cert_sha256 or "").strip().lower()
    current_ost_pin = str(cfg.get("ost_cert_sha256", "") or "").strip().lower()
    if desired_ost_pin:
        if current_ost_pin != desired_ost_pin:
            cfg["ost_cert_sha256"] = desired_ost_pin
            changed = True
    elif ost_changed and current_ost_pin:
        # OST endpoint が変更され、新しいリモート定義にピンが無い場合（HTTPS や別 OST 等）は古いピンを消す
        cfg["ost_cert_sha256"] = ""
        changed = True
    if bool(cfg.get("allow_tofu", False)) != bool(remote.allow_tofu):
        cfg["allow_tofu"] = bool(remote.allow_tofu)
        changed = True
    if changed:
        if tree_identity_changed:
            _reset_workdir_pin(mount_root)
        write_private_json(cfg_path, cfg)
        node, cfg, _reg = cli_mod.load_node_from_mount(mount_root)
    if create and not remote.read_only and getattr(node.l4.pin, "version", 0) == 0:
        auto_fn = getattr(node.registry, "auto_delegate", None)
        writer_pub = getattr(node.l4, "pub_key_str", "")
        if callable(auto_fn) and writer_pub:
            try:
                auto_fn(node.sub_path, writer_pub)
            except Exception:
                pass
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


def _is_zstd_file(path: Path) -> bool:
    try:
        with path.open("rb") as fh:
            hdr = fh.read(4)
    except OSError:
        return False
    if len(hdr) < 4:
        return False
    if hdr == b"\x28\xb5\x2f\xfd":
        return True
    magic_le = int.from_bytes(hdr, "little")
    return 0x184D2A50 <= magic_le <= 0x184D2A5F


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

    def _consume(archive: tarfile.TarFile) -> None:
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

    try:
        if _is_zstd_file(archive_path):
            try:
                import zstandard as zstd
            except ImportError as e:
                raise UsageError(
                    f"tar.zst の展開には zstandard が必要です: {archive_path}"
                ) from e
            dctx = zstd.ZstdDecompressor()
            try:
                with archive_path.open("rb") as raw_fh:
                    with dctx.stream_reader(raw_fh) as z_reader:
                        with tarfile.open(fileobj=z_reader, mode="r|") as archive:
                            _consume(archive)
            except zstd.ZstdError as e:
                raise UsageError(f"zstd tar を読み込めません: {archive_path}: {e}") from e
        else:
            with tarfile.open(archive_path, mode="r:*") as archive:
                _consume(archive)
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
            iter_fn = getattr(node, "iter_remote", None)
            if checksum == "crc32":
                local_sum_i = 0
                with src.open("rb") as fh:
                    while True:
                        blk = fh.read(8 * 1024 * 1024)
                        if not blk:
                            break
                        local_sum_i = zlib.crc32(blk, local_sum_i)
                local_sum: Any = local_sum_i & 0xFFFFFFFF
                remote_sum_i = 0
                if callable(iter_fn):
                    for chunk in iter_fn(path):
                        remote_sum_i = zlib.crc32(chunk, remote_sum_i)
                else:
                    remote_sum_i = zlib.crc32(node.read_remote(path))
                remote_sum: Any = remote_sum_i & 0xFFFFFFFF
            else:
                lh = hashlib.sha1()
                with src.open("rb") as fh:
                    while True:
                        blk = fh.read(8 * 1024 * 1024)
                        if not blk:
                            break
                        lh.update(blk)
                local_sum = lh.hexdigest()
                rh = hashlib.sha1()
                if callable(iter_fn):
                    for chunk in iter_fn(path):
                        rh.update(chunk)
                else:
                    rh.update(node.read_remote(path))
                remote_sum = rh.hexdigest()
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


from .commands.remote import (  # noqa: E402
    DEFAULT_ROOT_DFS_DOMAINS,
    _detect_external_ip,
    _format_remote_status_details,
    _probe_remote_status,
    _probe_root_dfs_domain,
    _remote_domain_candidate,
    cmd_candidacy,
    cmd_config,
    cmd_delegate,
    cmd_discover,
    cmd_invite,
    cmd_join,
    cmd_listremotes,
    cmd_quit,
    cmd_share,
    default_subtree_name,
)
def normalize_registry(value: str, default_port: int = DEFAULT_REGISTRY_PORT) -> str:
    """``--registry`` を URL に正規化する。

    ``192.0.2.60`` のようにホスト名（または IP）だけでも受け、足りない部分を補う。

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


from .commands.archive import _archive_registry_context, cmd_archive  # noqa: E402
from .commands.web import cmd_web  # noqa: E402


from .commands.transfer import (  # noqa: E402
    _configure_fuse_library,
    _print_plan,
    _pull_once,
    cmd_about,
    cmd_cat,
    cmd_check,
    cmd_copy,
    cmd_copyto,
    cmd_fs,
    cmd_history,
    cmd_import,
    cmd_import_tar,
    cmd_ls,
    cmd_lsd,
    cmd_lsl,
    cmd_lsjson,
    cmd_mkdir,
    cmd_mount,
    cmd_mv,
    cmd_pull,
    cmd_purge,
    cmd_rm,
    cmd_rmdir,
    cmd_size,
    cmd_sync,
    cmd_touch,
)
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
    ost_cert_sha256 = (remote.ost_cert_sha256 or "").strip().lower()
    try:
        info = cli_mod.RemoteRegistryClient(registries).ost_info()
        if not ost_primary and info.get("endpoint"):
            ost_primary = Remote.normalize_ost(str(info["endpoint"]))
        if not ost_cert_sha256 and ost_primary:
            ost_cert_sha256 = matching_ost_cert_pin(ost_primary, info)
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
                ost_cert_sha256=ost_cert_sha256,
                role_epoch=remote.role_epoch,
                poll_seconds=int(args.poll),
                use_candidacy=bool(args.candidacy),
                kdf=remote.kdf,
            )
        return encode_ro_invite(
            name=args.name or remote.name,
            registries=registries,
            root_pubkey=remote.root_pubkey,
            tree_secret=remote.secret,
            path=remote.path,
            ost=ost_primary,
            ost_alternates=ost_alts,
            ost_cert_sha256=ost_cert_sha256,
            role_epoch=remote.role_epoch,
            poll_seconds=int(args.poll),
            use_candidacy=bool(args.candidacy),
            kdf=remote.kdf,
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


def _add_create_args(p: argparse.ArgumentParser, args_name_required: bool) -> None:
    """``create`` と ``config create`` で共有する引数。"""
    p.add_argument(
        "--registry",
        help=f"L2 名簿。ホスト名だけでよい（例: 192.0.2.60）。"
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
    p.add_argument("--ost", help="L3 OST の host:port（例: 192.0.2.60:19443）")
    p.add_argument(
        "--ost-cert-sha256",
        help="L3 OST の TLS 証明書 SHA-256 ピン（ローテーション時や厳格ピン留め用）",
    )
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
        help="root アンカーの公開鍵ファイル（信頼の根）",
    )
    p.add_argument(
        "--allow-tofu", action="store_true",
        help="root 公開鍵を取得できない／未設定のリモートでも writer 検証を省略して TOFU を許可する",
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
    p_arch.add_argument(
        "--format",
        choices=["zstd:chunked", "tar.zst", "tar.gz"],
        default="zstd:chunked",
        help="create のアーカイブ形式（既定: zstd:chunked）",
    )
    p_arch.add_argument(
        "--keep-dir",
        action="store_true",
        help="create 時に展開済み bundle ディレクトリも削除せず残す",
    )
    p_arch.add_argument(
        "--recovery",
        type=int,
        default=None,
        metavar="PERCENT",
        help="PAR2 リカバリレコードの冗長率 %%（既定: par2 があれば 5、0 で無効）",
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
    p.add_argument(
        "--backend",
        choices=["auto", "fskit", "fuse-t", "macfuse"],
        default="auto",
        help="FUSE マウントのバックエンド（既定: auto = macfuse-fskit -> fuse-t -> macfuse）",
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
        "import",
        aliases=["import-tar", "import_tar"],
        help="tar / tar.gz や DFS archive bundle をリモートへインポートする",
    )
    p.add_argument("archive", help="ローカルの tar ファイルまたは DFS archive bundle")
    p.add_argument("dest", help="remote:path")
    p.add_argument(
        "--strip-components", type=int, default=0, metavar="N",
        help="tar member の先頭 N 要素を除く（既定 0）",
    )
    p.add_argument(
        "--source-secret",
        help="DFS archive bundle の復号に使う tree_secret（省略時は宛先リモートと同じ secret）",
    )
    p.add_argument("-n", "--dry-run", action="store_true")
    p.set_defaults(func=cmd_import)

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
    p_join.add_argument("--root-pubkey", help="root アンカーの公開鍵ファイル（信頼の根）")
    p_join.add_argument(
        "--allow-tofu", action="store_true",
        help="root 公開鍵を取得できない／未設定のリモートでも writer 検証を省略して TOFU を許可する",
    )
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
        help="待機アドレス（既定 127.0.0.1。LAN 内のスマホ等から直接接続するには --bind 0.0.0.0 を指定）",
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
        help="案内表示用の公開 URL（例: https://example.com/dfs）",
    )
    p_web.add_argument(
        "--secure-cookie",
        action="store_true",
        help="セッションクッキーに常に Secure 属性を付ける",
    )
    p_web.add_argument(
        "--trusted-proxy",
        action="append",
        default=[],
        help="X-Forwarded-For を信頼するリバースプロキシの IP または CIDR（複数指定可）",
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
    """未登録のドメイン名（例: example.com）を解決する。

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
    """dfssvc の記録が見つかった場合、tree_secret 不在のため不正な自動登録は行わず登録手順を案内する。"""
    from .svc import ServiceStore

    svc_store = ServiceStore()
    svc = svc_store.services.get(service_name)
    if svc is None:
        return None
    key_opt = f"--key {svc.writer_key} " if svc.writer_key else ""
    raise UsageError(
        f"リモート {service_name!r} は {store.path} に未登録です。\n"
        f"dfssvc は tree_secret を保持しないため、ランダムな secret で自動登録できません。\n"
        f"'dfssvc env {svc.name}' を確認し、次のコマンドで登録してください:\n"
        f"  dfscli config create {svc.name} --registry {svc.registry_url} "
        f"{key_opt}--secret <tree_secret>"
    )


def _version() -> str:
    try:
        from . import __version__

        return __version__
    except Exception:  # noqa: BLE001
        return "unknown"


def _friendly_error(exc: BaseException) -> int:
    """例外を利用者向けの 1 行にして返す（終了コード付き）。"""
    from .i18n import _

    if isinstance(exc, ConflictError):
        title = _("単一書き手の競合")
        hint = _("他の端末が先に書きました。'dfscli pull' の後でやり直してください。")
        print(
            f"[dfscli] {title}: {exc}\n"
            f"        {hint}",
            file=sys.stderr,
        )
        return 7
    if isinstance(exc, RollbackDetectedError):
        title = _("巻き戻しを検出しました（B6）")
        print(f"[dfscli] {title}: {exc}", file=sys.stderr)
        return 8
    if isinstance(exc, SilentDropDetectedError):
        title = _("黙った破棄を検出しました（B7）")
        print(f"[dfscli] {title}: {exc}", file=sys.stderr)
        return 9
    if isinstance(exc, ServiceUnavailableError):
        title = _("L2/L3 に到達できません")
        print(f"[dfscli] {title}: {exc}", file=sys.stderr)
        return 6
    if isinstance(exc, (UsageError, RemoteError)):
        print(f"[dfscli] {exc}", file=sys.stderr)
        return 2
    title = _("予期しないエラー")
    print(f"[dfscli] {title}: {type(exc).__name__}: {exc}", file=sys.stderr)
    return 1


def _normalize_intermixed_archive_argv(argv: List[str]) -> List[str]:
    if not argv:
        return argv
    prefix: List[str] = []
    idx = 0
    while idx < len(argv):
        tok = argv[idx]
        if tok in ("--remote", "-r"):
            if idx + 1 >= len(argv):
                return argv
            prefix.extend((tok, argv[idx + 1]))
            idx += 2
        elif tok.startswith("--remote="):
            prefix.append(tok)
            idx += 1
        else:
            break
    rest_all = argv[idx:]
    if len(rest_all) < 3 or rest_all[0] != "archive":
        return argv
    action = rest_all[1]
    if action not in ("fetch", "extract"):
        return argv
    source = rest_all[2]
    rest = rest_all[3:]
    non_opts = []
    opts = []
    i = 0
    val_options = {"--out", "--announce", "--version", "--secret", "--recovery", "--torrent-client", "--torrent-timeout"}
    while i < len(rest):
        arg = rest[i]
        if arg.startswith("-"):
            opts.append(arg)
            if arg in val_options and i + 1 < len(rest) and not rest[i + 1].startswith("-"):
                opts.append(rest[i + 1])
                i += 1
        else:
            non_opts.append(arg)
        i += 1
    if non_opts:
        return [*prefix, "archive", action, source, *non_opts, *opts]
    return argv


def main(argv: Optional[List[str]] = None) -> int:
    from .i18n import _, translate_parser

    raw_argv = list(sys.argv[1:] if argv is None else argv)
    norm_argv = _normalize_intermixed_archive_argv(raw_argv)
    parser = translate_parser(build_parser(), _)
    args = parser.parse_args(norm_argv)
    try:
        return int(args.func(args) or 0)
    except KeyboardInterrupt:
        print(f"\n[dfscli] {_('中断しました')}", file=sys.stderr)
        return 130
    except SystemExit:
        raise
    except BaseException as e:  # noqa: BLE001 - CLI の最外殻でまとめて扱う
        return _friendly_error(e)
    finally:
        DFSNode.close_all()
        MerkleTreeBuilder.close_all()


if __name__ == "__main__":
    raise SystemExit(main())
