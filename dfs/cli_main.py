#!/usr/bin/env python3
"""
dfs/cli_main.py
rclone ライクな dfs の CLI エントリーポイント。

コアロジックは cli_core.py に分離済み。ここでは argparse 定義と
サブコマンドの配線のみを行う。
"""

from __future__ import annotations

import argparse
import os
import socket
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from . import cli as cli_mod
from .cli_core import (
    safe_target,
    UnsafePathError,
    _ensure_remote_secret,
    _reset_workdir_pin,
    _resolve_remote,
    public_key_of,
    resolve_path,
    _resolve_self_claimed_domain_remote,
    _ensure_remote_from_service,
    _require_writable,
    cmd_libp2p_serve,
    UsageError,
    open_remote,
    refresh_cache,
    plan_changes,
    apply_writes,
    apply_deletes,
    prune_empty_dirs,
    prune_empty_parents,
    _push,
    _tree_path,
    _norm_prefix,
    _join_prefix,
    _collect_local,
    _filter_local,
    _human_size,
    _rel_entries,
    _remote_file_paths,
    _remote_dir_paths,
    _remove_from_tree,
    _validate_snapshot_id,
    _probe_registry_tcp,
    normalize_registry,
    prompt_secret,
    _normalize_path_arg,
    normalize_subtree_path,
    _read_root_pubkey_arg,
    _create_invite_token,
    _default_bootstrap_url,
    _add_create_args,
    CACHE_VERSION_FILENAME,
    FILE_CHUNK_BYTES,
    CHECKSUM_MODES,
    PathFilter,
    _path_filter,
    _local_chunk_plain_ids,
    _tar_member_path,
    _is_zstd_file,
    _extract_tar_safely,
)
from .commands.remote import (
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
from .commands.archive import _archive_registry_context, cmd_archive
from .commands.web import cmd_web
from .commands.transfer import (
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
from .crypto import KDF_DEFAULT, KDF_LEGACY_SHA256, ssh_key_fingerprint
from .dnssec import Discovery, DiscoveryError, discover_domain
from .invite import InviteError, decode_invite, encode_ro_invite, encode_rw_invite
from .l2_registry import ConflictError, ServiceUnavailableError
from .l4_log import (
    RollbackDetectedError,
    SilentDropDetectedError,
    MerkleTreeBuilder,
)
from .l5_fs import DFSNode
from .remotes import NAME_RE, Remote, RemoteError, RemoteStore, matching_ost_cert_pin, split_remote_spec

# Re-export core functions for commands/__init__.py compatibility
from .cli_core import (
    copyfile_no_follow,
    safe_target,
    UnsafePathError,
    UsageError,
    RemoteStore,
    Remote,
    RemoteError,
    _norm_prefix,
    _resolve_remote,
    open_remote,
    refresh_cache,
    plan_changes,
    apply_writes,
    apply_deletes,
    prune_empty_dirs,
    prune_empty_parents,
    _push,
    _tree_path,
    _collect_local,
    _filter_local,
    _human_size,
    _rel_entries,
    _all_entries,
    _remote_file_paths,
    _remote_dir_paths,
    _remove_from_tree,
    _validate_snapshot_id,
    _probe_registry_tcp,
    normalize_registry,
    prompt_secret,
    _normalize_path_arg,
    normalize_subtree_path,
    _read_root_pubkey_arg,
    _create_invite_token,
    _default_bootstrap_url,
    _add_create_args,
    CACHE_VERSION_FILENAME,
    FILE_CHUNK_BYTES,
    CHECKSUM_MODES,
    PathFilter,
    _path_filter,
    _local_chunk_plain_ids,
    _tar_member_path,
    _is_zstd_file,
    _extract_tar_safely,
    _require_writable,
    _resolve_self_claimed_domain_remote,
    _ensure_remote_from_service,
    DEFAULT_REGISTRY_PORT,
    DEFAULT_LOCAL_REGISTRY_PORT,
)

# Also import from other modules
from .crypto import KDF_DEFAULT, KDF_LEGACY_SHA256, ssh_key_fingerprint
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
from .l2_registry import ConflictError, ServiceUnavailableError
from .l1_delegation import DelegationError, create_delegation_envelope, verify_delegation_chain
from .l4_log import (
    FILE_CHUNK_BYTES as L4_FILE_CHUNK_BYTES,
    L4LogClient,
    MerkleTreeBuilder,
    RollbackDetectedError,
    SilentDropDetectedError,
)
from .l5_fs import DFSNode
from .fs.core import remove_tree
from .path_safety import UnsafePathError as PathUnsafePathError, copyfile_no_follow as PathCopyfileNoFollow, safe_target as PathSafeTarget
from .paths import config_dir, restrict_to_owner
from .private_io import ensure_private_dir, write_private_json
from .remotes import NAME_RE, Remote as RemotesRemote, RemoteError as RemotesRemoteError, RemoteStore as RemotesRemoteStore, matching_ost_cert_pin, split_remote_spec


# 定数
DEFAULT_REGISTRY_PORT = 9440
DEFAULT_LOCAL_REGISTRY_PORT = 19440


def _version() -> str:
    try:
        from . import __version__
        return __version__
    except Exception:
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
    val_options = {
        "--out", "--announce", "--version", "--secret", "--recovery", "--format",
        "--torrent-client", "--torrent-timeout", "--root-pubkey", "--root-fingerprint",
    }
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
        "--root-pubkey",
        help="verify 時に照合する期待 root 公開鍵（文字列または .pub ファイルパス）",
    )
    p_arch.add_argument(
        "--root-fingerprint",
        help="verify 時に照合する期待 root 公開鍵指紋 (SHA256:...)",
    )
    p_arch.add_argument(
        "--allow-embedded-root",
        action="store_true",
        help="verify 時にアーカイブ埋め込みの root 公開鍵での自己整合性検証のみを許可する",
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
        "--checksum", nargs="?", const="plain_id", default="plain_id",
        choices=CHECKSUM_MODES,
        help="変更検出: plain_id (既定) / size / crc32 / sha1",
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
        "--checksum", nargs="?", const="plain_id", default="plain_id",
        choices=CHECKSUM_MODES,
        help="変更検出: plain_id (既定) / size / crc32 / sha1",
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
    p.add_argument(
        "--root-pubkey",
        help="DFS archive bundle 展開時に照合する期待 root 公開鍵（文字列または .pub ファイル）",
    )
    p.add_argument(
        "--root-fingerprint",
        help="DFS archive bundle 展開時に照合する期待 root 公開鍵指紋 (SHA256:...)",
    )
    p.add_argument(
        "--allow-embedded-root",
        action="store_true",
        help="DFS archive bundle 展開時に埋め込み root 公開鍵での検証を許可する",
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
        "--checksum", nargs="?", const="plain_id", default="plain_id",
        choices=CHECKSUM_MODES,
        help="変更検出: plain_id (既定) / size / crc32 / sha1",
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
    p_serve.set_defaults(func=lambda args: (cli_mod.cmd_serve(args), 0)[1])

    p_promote = sub.add_parser(
        "promote", help="停止中の registry state を primary に昇格する"
    )
    p_promote.add_argument("--state-dir", default="~/.dfs_server")
    p_promote.add_argument("--role-epoch", type=int)
    p_promote.set_defaults(func=lambda args: (cli_mod.cmd_promote(args), 0)[1])

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


def main(argv: Optional[List[str]] = None) -> int:
    from .i18n import _, configure_stdio, translate_parser

    configure_stdio()
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    norm_argv = _normalize_intermixed_archive_argv(raw_argv)
    parser = translate_parser(build_parser(), _)
    args = parser.parse_args(norm_argv)
    if hasattr(args, "no_prompt") and not sys.stdin.isatty():
        args.no_prompt = True
    try:
        return int(args.func(args) or 0)
    except KeyboardInterrupt:
        print(f"\n[dfscli] {_('中断しました')}", file=sys.stderr)
        return 130
    except SystemExit:
        raise
    except BaseException as e:
        return _friendly_error(e)
    finally:
        DFSNode.close_all()
        MerkleTreeBuilder.close_all()


if __name__ == "__main__":
    raise SystemExit(main())
