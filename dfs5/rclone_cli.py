#!/usr/bin/env python3
"""
dfs5/rclone_cli.py
rclone ライクな dfs5 の CLI。

`cli.py` の部品（L2 名簿クライアント、`serve`、`delegate`、ノード構築）をそのまま使い、
「リモート名で場所を指す」操作体系を被せる。

    dfs5r listremotes
    dfs5r config create scaleway --registry http://172.16.1.60:19440 \\
        --ost 172.16.1.60:19443 --path /example.com/alice/notes \\
        --key ~/.ssh/alice --secret <共有秘密>
    dfs5r ls    scaleway:
    dfs5r ls    scaleway:docs
    dfs5r cat   scaleway:docs/readme.md
    dfs5r copy  ./local scaleway:docs
    dfs5r sync  ./local scaleway:docs      # リモートをローカルに合わせる
    dfs5r pull  scaleway:docs ./local      # リモートをローカルへ取り出す
    dfs5r check scaleway:docs ./local
    dfs5r about scaleway:

設計上の注意（dfs5 の単一書き手）:
  - リモートは「1 つの書き込み境界（サブツリー）」に対応する。
  - 書き込み系（copy / sync / copyto）は、まず作業ディレクトリの写しを先頭版に
    合わせてから、変更を載せて 1 版としてまとめて push する。
  - 読み出し系（ls / cat / size / check）は版を進めない。

環境変数:
  DFS5_CONFIG    リモート定義ファイル（既定 ~/.config/dfs5/remotes.json）
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from . import cli as cli_mod

# L2 名簿の既定ポート。ホスト名だけで済むようにする（例: --registry 172.16.1.60）。
DEFAULT_REGISTRY_PORT = 9440
# dfs5svc が立てるサーバの既定。こちらは連続した空きを選ぶので 19440 から。
DEFAULT_LOCAL_REGISTRY_PORT = 19440
from .l2_registry import ConflictError, ServiceUnavailableError
from .l4_log import (
    RollbackDetectedError,
    SilentDropDetectedError,
)
from .l5_clayfs import DFS5Node
from .crypto import normalize_path
from .remotes import Remote, RemoteError, RemoteStore, split_remote_spec

CACHE_VERSION_FILENAME = "cache_version"


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
    print(f"[dfs5r] 公開鍵を作成しました: {pub}", file=sys.stderr)


def resolve_ost(remote: Remote, registry: Optional[cli_mod.RemoteRegistryClient] = None) -> str:
    """L3 OST の ``host:port`` を決める。

    優先順: リモート定義の ``ost`` → ロケータの ``endpoints`` → サーバの広告（``/v1/ost``）。
    L2 は OST の場所を知っているので、``config create`` で ``--ost`` を省ける。
    """
    if remote.ost:
        return remote.ost
    client = registry or cli_mod.RemoteRegistryClient(remote.registry)
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
    client = registry or cli_mod.RemoteRegistryClient(remote.registry)
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


def open_remote(remote: Remote, create: bool = False) -> DFS5Node:
    """リモートの作業ディレクトリを用意し、ノードを組み立てる。

    ``create=True`` のときは未初期化なら初期化する（書き込み系で使う）。
    ``ost`` と ``path`` は、指定が無ければ L2 から解決する。
    """
    mount_root = remote.resolved_workdir().expanduser()
    cfg_path = mount_root / ".clayfs" / cli_mod.CONFIG_FILENAME

    if not cfg_path.is_file():
        if not create:
            raise UsageError(
                f"Remote {remote.name!r} is not initialized at {mount_root}.\n"
                f"Run 'dfs5r touch {remote.name}:' or a write command first."
            )
        priv_key = Path(remote.key).expanduser()
        _ensure_keypair(priv_key)
        if not remote.secret:
            # tree_secret はサーバに置かない共有秘密なので、L2 からは引けない。
            # 空のまま暗号化すると、誰でも復号できる木を作ってしまう。
            raise UsageError(
                f"Remote {remote.name!r} has no tree_secret.\n"
                f"Set it with 'dfs5r config create {remote.name} ... --secret <共有秘密>' "
                f"(or edit {RemoteStore().path})."
            )
        registry = cli_mod.RemoteRegistryClient(remote.registry)
        ost_value = resolve_ost(remote, registry)
        sub_path = resolve_path(remote, registry)
        host, _, port_str = ost_value.partition(":")
        if not port_str:
            raise UsageError(f"Cannot parse L3 OST endpoint {ost_value!r} for remote {remote.name!r}")
        mount_root.mkdir(parents=True, exist_ok=True)
        (mount_root / "tree").mkdir(exist_ok=True)
        (mount_root / ".clayfs").mkdir(exist_ok=True)
        cfg = {
            "delegation_epoch": int(remote.epoch),
            "node_name": remote.node_name or remote.name,
            "ost_host": host,
            "ost_port": int(port_str),
            "priv_key": str(priv_key),
            "registry_url": remote.registry,
            "sub_path": sub_path,
            "tree_secret": remote.secret,
        }
        cfg_path.parent.mkdir(parents=True, exist_ok=True)
        cfg_path.write_text(
            json.dumps(cfg, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8"
        )

    node, _cfg, _reg = cli_mod.load_node_from_mount(mount_root)
    return node


def _cache_marker(node: DFS5Node) -> Path:
    return node.clayfs.clayfs_meta / CACHE_VERSION_FILENAME


def _load_cached_version(node: DFS5Node) -> int:
    marker = _cache_marker(node)
    if not marker.is_file():
        return -1
    try:
        return int(marker.read_text(encoding="utf-8").strip())
    except (ValueError, OSError):
        return -1


def _save_cached_version(node: DFS5Node, version: int) -> None:
    marker = _cache_marker(node)
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text(str(int(version)) + "\n", encoding="utf-8")


def refresh_cache(node: DFS5Node, force: bool = False) -> int:
    """作業ディレクトリの写しをリモートの先頭版に合わせ、その版番号を返す。

    すでに同じ版を持っていれば何もしない（L2 の 1 往復だけ）。
    リモートが空なら、作業ツリーを空にして 0 を返す（これから最初の版を作る）。
    """
    head = node.l4.sync_head(node.registry)
    if head is None:
        # リモートは空。作業ツリーを空にして、最初の push に備える。
        work_tree = node.clayfs.work_tree
        if work_tree.exists():
            shutil.rmtree(work_tree)
        work_tree.mkdir(parents=True, exist_ok=True)
        _save_cached_version(node, 0)
        return 0

    version = int(head["payload"]["version"])
    if not force and _load_cached_version(node) == version:
        return version

    p = head["payload"]
    with tempfile.TemporaryDirectory(prefix="dfs5_stage_") as staging:
        staging_dir = Path(staging)
        with node.ost.session():
            node.builder.download_directory(p["root_plain_id"], p["root_wire_id"], staging_dir)
        node.clayfs.replace_work_tree(staging_dir)
    node.clayfs.take_snapshot(f"v{version}")
    _save_cached_version(node, version)
    return version


def _push(node: DFS5Node, remote: Remote, delegated_mounts: Optional[Dict[str, str]] = None) -> Tuple[dict, int]:
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
    return prefix


def _join_prefix(prefix: str, rel: str) -> str:
    rel = rel.replace("\\", "/").lstrip("/")
    return f"{prefix}/{rel}" if prefix else rel


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


def _tree_path(node: DFS5Node, rel: str) -> Path:
    if any(part in ("", ".", "..") for part in rel.split("/")):
        raise UsageError(f"Invalid path in tree: {rel!r}")
    return node.clayfs.work_tree / rel


def plan_changes(
    node: DFS5Node,
    prefix: str,
    local: Dict[str, Path],
    checksum: bool = False,
) -> Tuple[List[Tuple[str, Path, str]], List[str], List[str]]:
    """ローカルとリモートを比べ、(書くもの, 消すもの, 変わらないもの) を返す。

    転送の判定は rclone の既定と同じく大きさを先に見る。``checksum=True`` のときだけ
    中身の内容アドレス (``plain_id``) まで比べる。dfs5 は書き手側の索引で塊を
    重複排除するため、内容が同じなら ``push`` しても本文は送られない。それでも
    版が増えるのは無駄なので、「変わらないなら版を作らない」をここで決める。

    返り値の「書くもの」は ``(リモートのパス, ローカルの実ファイル, "add"|"update")``。
    """
    remote = {
        e["path"]: e
        for e in _all_entries(node, prefix)
        if e["type"] == "file"
    }
    wanted = {_join_prefix(prefix, rel): src for rel, src in local.items()}

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
        if checksum:
            data = src.read_bytes()
            pid = node.crypto.compute_plain_id(data).hex()
            if pid != entry.get("plain_id", ""):
                to_write.append((path, src, "update"))
                continue
        unchanged.append(path)

    to_delete = sorted(set(remote) - set(wanted))
    return to_write, to_delete, unchanged


def apply_writes(node: DFS5Node, writes: List[Tuple[str, Path, str]]) -> None:
    """``plan_changes`` の「書くもの」を、作業ツリーへ反映する。"""
    for path, src, _kind in writes:
        relative = path
        target = _tree_path(node, relative)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, target)


def apply_deletes(node: DFS5Node, paths: List[str], prune_empty: bool = True) -> None:
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


def prune_empty_dirs(node: DFS5Node, start: Optional[Path] = None) -> List[str]:
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


def _remote_file_paths(node: DFS5Node, prefix: str = "") -> set:
    return {e["path"] for e in _all_entries(node, prefix) if e["type"] == "file"}


def _remote_dir_paths(node: DFS5Node, prefix: str = "") -> set:
    return {e["path"] for e in _all_entries(node, prefix) if e["type"] == "dir"}


def _remove_from_tree(node: DFS5Node, paths: List[str]) -> None:
    """作業ツリーから、ファイルまたはディレクトリ（中身ごと）を取り除く。"""
    for rel in sorted(paths, key=lambda p: len(p.split("/")), reverse=True):
        victim = _tree_path(node, rel)
        if victim.is_dir():
            shutil.rmtree(victim, ignore_errors=True)
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


def _rel_entries(node: DFS5Node, prefix: str) -> List[Dict[str, Any]]:
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


def _all_entries(node: DFS5Node, prefix: str) -> List[Dict[str, Any]]:
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
                f"[dfs5r] 入力が一致しません。もう一度入力してください"
                f"（{attempt}/{max_tries}）",
                file=sys.stderr,
            )
            continue
        if first == "":
            print("[dfs5r] 空のまま進めます（あとで設定できます）", file=sys.stderr)
            return ""
        return first.strip()

    print("[dfs5r] 何度も一致しませんでした。--secret で渡すか、あとで設定してください", file=sys.stderr)
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
        if not args.registry:
            raise UsageError("config create には --registry が必要です")

        registry = normalize_registry(args.registry, args.registry_port)

        # --key が無ければ、その場で Ed25519 の鍵を作る。
        # 書き手の鍵は dfs5r が初めて使うものなので、利用者に用意させない。
        key_path: Path
        created_key = False
        if args.key:
            key_path = Path(args.key).expanduser()
            if not key_path.is_file():
                raise UsageError(f"指定された書き手鍵がありません: {key_path}")
        else:
            key_dir = Path(args.key_dir).expanduser() if args.key_dir else (
                Path.home() / ".config" / "dfs5" / "keys"
            )
            key_dir.mkdir(parents=True, exist_ok=True)
            key_path = key_dir / f"{args.name}_ed25519"
            if not key_path.is_file():
                res = subprocess.run(
                    ["ssh-keygen", "-t", "ed25519", "-N", "",
                     "-C", f"dfs5r-{args.name}@{socket.gethostname()}", "-f", str(key_path)],
                    capture_output=True, text=True,
                )
                if res.returncode != 0:
                    raise UsageError(f"鍵を作れませんでした: {res.stderr.strip()}")
                os.chmod(key_path, 0o600)
                created_key = True

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
            key=str(key_path),
            ost=args.ost or "",
            path=_normalize_path_arg(args.path),
            secret=secret or "",
            workdir=args.workdir or "",
            epoch=int(args.epoch),
            node_name=args.node_name or args.name,
        )
        store.set(remote)
        print(f"[dfs5r] リモート {remote.name!r} を保存しました: {store.path}")
        print(f"  registry    : {remote.registry}")
        if created_key:
            print(f"  書き手の鍵  : {key_path}（作った。OpenSSH 形式の Ed25519）")
        else:
            print(f"  書き手の鍵  : {key_path}")
        print(f"  作業ディレクトリ: {remote.resolved_workdir()}")
        if remote.ost:
            print(f"  L3 OST      : {remote.ost}")
        else:
            print("  L3 OST      : （未指定。使うときに L2 のロケータから解決します）")
        if remote.path:
            print(f"  サブツリー  : {remote.path}")
        else:
            print("  サブツリー  : （未指定。使うときに L2 で書き手鍵から探します）")
        if remote.secret:
            how = "端末から読みました" if secret_from_prompt else "指定どおり"
            print(f"  tree_secret : *** （{how}）")
        else:
            print("  tree_secret : （未指定。書く前に設定してください）")
        return 0

    if args.action == "delete":
        if store.delete(args.name):
            print(f"[dfs5r] リモート {args.name!r} を削除しました")
            return 0
        raise UsageError(f"Unknown remote {args.name!r}")

    if args.action == "show":
        r = store.get(args.name)
        for key in ("name", "registry", "ost", "path", "key", "workdir", "epoch", "node_name"):
            value = getattr(r, key)
            if key == "secret":
                value = "***"
            if key == "workdir":
                value = str(r.resolved_workdir())
            print(f"{key:{12}}: {value}")
        return 0

    if args.action == "list":
        return cmd_listremotes(args)

    raise UsageError(f"Unknown config action: {args.action}")


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
    head = "[dfs5r] " + ("(dry-run) " if dry_run else "")
    print(f"{head}{action}: {len(items)} 件", file=sys.stderr)
    if dry_run:
        for i in items[:40]:
            print(f"  {i}", file=sys.stderr)
        if len(items) > 40:
            print(f"  ... ほか {len(items) - 40} 件", file=sys.stderr)


def cmd_copy(args: argparse.Namespace) -> int:
    """ローカルのファイルをリモートへ足す（リモートにしかないものは残す）。

    変更が無ければ版を作らない（rclone と同じく冪等）。判定は大きさを先に見て、
    ``--checksum`` のときだけ内容アドレスまで比べる。
    """
    store = RemoteStore()
    name, sub = split_remote_spec(args.dest, args.remote_name)
    remote = store.get(name)
    prefix = _norm_prefix(sub)
    local = _collect_local(Path(args.src))
    if not local:
        print("[dfs5r] コピーするファイルがありません", file=sys.stderr)
        return 0

    node = open_remote(remote, create=True)
    refresh_cache(node)
    writes, _deletes, unchanged = plan_changes(node, prefix, local, checksum=args.checksum)

    plan = [
        f"{kind:6} {src} -> {remote.name}:{path}"
        for path, src, kind in writes
    ] + [f"same   {remote.name}:{path}" for path in unchanged][:0]
    _print_plan("copy", plan, args.dry_run)
    if args.dry_run:
        return 0
    if not writes:
        print(
            f"[dfs5r] copy: 変更なし（{len(unchanged)} ファイルが同じ）。新しい版は作りません",
            file=sys.stderr,
        )
        return 0

    apply_writes(node, writes)
    t0 = time.perf_counter()
    log_env, sent = _push(node, remote)
    ms = (time.perf_counter() - t0) * 1000.0
    print(
        f"[dfs5r] copy OK -> v{log_env['payload']['version']} "
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
            f"[dfs5r] copyto: 変更なし（{sub} は同じ）。新しい版は作りません",
            file=sys.stderr,
        )
        return 0
    apply_writes(node, writes)

    log_env, sent = _push(node, remote)
    print(
        f"[dfs5r] copyto OK -> v{log_env['payload']['version']} "
        f"| {sub} | sent={sent} B"
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
    local = _collect_local(Path(args.src))

    node = open_remote(remote, create=True)
    refresh_cache(node)
    writes, deletes, unchanged = plan_changes(node, prefix, local, checksum=args.checksum)
    if not args.delete:
        deletes = []

    plan = ([f"add    {remote.name}:{path}" for path, _src, kind in writes if kind == "add"]
            + [f"update {remote.name}:{path}" for path, _src, kind in writes if kind == "update"]
            + [f"delete {remote.name}:{path}" for path in deletes])
    if not plan:
        print(
            f"[dfs5r] sync: 変更なし（{len(unchanged)} ファイルが同じ）。新しい版は作りません",
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
        f"[dfs5r] sync OK -> v{log_env['payload']['version']} "
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

    src_root = node.clayfs.work_tree if not prefix else node.clayfs.work_tree / prefix
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
        target = dest / rel
        if item.is_dir():
            target.mkdir(parents=True, exist_ok=True)
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(item, target)
        count += 1

    print(f"[dfs5r] pull OK <- v{version} | {count} ファイル -> {dest}")
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
            f"[dfs5r] check: 一致しません "
            f"(remote のみ {len(only_remote)} / local のみ {len(only_local)} / 差 {len(size_diff)})"
        )
        return 1
    print(f"[dfs5r] check: 一致しました（{len(remote_files)} ファイル）")
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
        print(f"[dfs5r] mkdir: すでにあります: {name}:{sub}", file=sys.stderr)
        return 0

    target = _tree_path(node, sub)
    target.mkdir(parents=True, exist_ok=True)
    log_env, sent = _push(node, remote)
    print(f"[dfs5r] mkdir OK -> v{log_env['payload']['version']} | {sub}/ | sent={sent} B")
    return 0


def cmd_rm(args: argparse.Namespace) -> int:
    """リモートのファイル（または ``--recursive`` でディレクトリ）を消す。

    rclone の ``delete`` / ``deletefile`` に当たる。消した後に空になったディレクトリは、
    ``--rmdirs`` を付けたときだけ片付ける（既定は空ディレクトリを残す。dfs5 は空の
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
            print(f"[dfs5r] rm: 消すファイルがありません（{name}:{sub}）", file=sys.stderr)
            return 0
        # --rmdirs なら、ファイルが無くても空ディレクトリの掃除に進む
        print(
            f"[dfs5r] rm: {name}:{sub} にファイルはありません。空ディレクトリを片付けます",
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
        f"[dfs5r] rm OK -> v{log_env['payload']['version']} "
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
    print(f"[dfs5r] rmdir OK -> v{log_env['payload']['version']} | {sub}/ | sent={sent} B")
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
        print(f"[dfs5r] purge: 消すものがありません（{name}:{sub}）", file=sys.stderr)
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
        f"[dfs5r] purge OK -> v{log_env['payload']['version']} "
        f"| ファイル {len(targets)} 件・ディレクトリ {len(target_dirs)} 件 | sent={sent} B"
    )
    return 0


def cmd_touch(args: argparse.Namespace) -> int:
    """リモートの作業ディレクトリを初期化する（push/pull はしない）。"""
    store = RemoteStore()
    name, _sub = split_remote_spec(args.remote, args.remote_name)
    remote = store.get(name)
    node = open_remote(remote, create=True)
    print(f"[dfs5r] 初期化しました: {node.clayfs.mount_root}")
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    cli_mod.cmd_serve(args)
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
    p.add_argument("--ost", help="L3 OST の host:port（例: 172.16.1.60:19443）")
    p.add_argument("--path", help="サブツリーのパス（例: /example.com/alice/notes）")
    p.add_argument("--key", help="書き手の OpenSSH Ed25519 秘密鍵（省略すると作る）")
    p.add_argument(
        "--key-dir",
        help="--key を省いたときに鍵を置く場所（既定 ~/.config/dfs5/keys）",
    )
    p.add_argument(
        "--secret",
        help="tree_secret（Convergent AEAD の共有秘密）。省略すると端末からエコーなしで読む",
    )
    p.add_argument(
        "--no-prompt", action="store_true",
        help="--secret を省いても端末から読まない（パイプで使うとき）",
    )
    p.add_argument("--workdir", help="作業ディレクトリ（既定 ~/.cache/dfs5/<name>）")
    p.add_argument("--epoch", type=int, default=1, help="委譲のエポック（既定 1）")
    p.add_argument("--node-name", help="端末名（既定はリモート名）")
    if args_name_required:
        p.add_argument("name", help="リモートの名前（例: scw）")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dfs5r",
        description="dfs5r: dfs5 を rclone ライクに扱う CLI（リモート名で場所を指す）",
    )
    parser.add_argument(
        "--remote", dest="remote_name", metavar="NAME",
        help="`path` だけを書いたときに使うリモート名（rclone の :backend: 相当）",
    )
    parser.add_argument("--version", action="version", version=f"dfs5r {_version()}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("listremotes", help="定義済みのリモートを一覧する")
    p.set_defaults(func=cmd_listremotes)

    # `dfs5r create NAME ...` は `dfs5r config create NAME ...` と同じ。
    # 登録は一番よく打つので短い入口を用意する。
    p = sub.add_parser("create", help="リモートを登録する（= config create）")
    _add_create_args(p, args_name_required=True)
    p.set_defaults(func=cmd_config, action="create")

    p_conf = sub.add_parser("config", help="リモート定義の作成・表示・削除")
    p_conf.add_argument("action", choices=["create", "show", "delete", "list"])
    p_conf.add_argument("name", nargs="?", default="")
    _add_create_args(p_conf, args_name_required=False)
    p_conf.set_defaults(func=cmd_config)

    p = sub.add_parser("ls", help="リモートの直下を一覧する（内容は取らない）")
    p.add_argument("remote")
    p.set_defaults(func=cmd_ls)

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
    p.add_argument("--checksum", action="store_true",
                   help="大きさが同じでも内容アドレスまで比べる")
    p.add_argument("-n", "--dry-run", action="store_true", help="何をするかだけ表示する")
    p.set_defaults(func=cmd_copy)

    p = sub.add_parser("copyto", help="ローカルの 1 ファイルをリモートの指定パスへ置く")
    p.add_argument("src")
    p.add_argument("dest", help="remote:path/file")
    p.add_argument("--checksum", action="store_true",
                   help="大きさが同じでも内容アドレスまで比べる")
    p.add_argument("-n", "--dry-run", action="store_true")
    p.set_defaults(func=cmd_copyto)

    p = sub.add_parser("sync", help="リモートをローカルディレクトリと一致させる")
    p.add_argument("src", help="ローカルのディレクトリ")
    p.add_argument("dest", help="remote:path")
    p.add_argument("--delete", action="store_true", help="リモートにしかないものを消す")
    p.add_argument("--checksum", action="store_true", help="大きさが同じでも書き直して判定する")
    p.add_argument("-n", "--dry-run", action="store_true")
    p.set_defaults(func=cmd_sync)

    p = sub.add_parser("pull", help="リモートをローカルディレクトリへ取り出す")
    p.add_argument("src", help="remote:path")
    p.add_argument("dest", help="ローカルのディレクトリ")
    p.add_argument("--force", action="store_true", help="写しが同じ版でも取り直す")
    p.set_defaults(func=cmd_pull)

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
    p_serve.add_argument("--state-dir", default="~/.dfs5_server")
    p_serve.set_defaults(func=cmd_serve)

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
            f"[dfs5r] 単一書き手の競合: {exc}\n"
            "        他の端末が先に書きました。'dfs5r pull' の後でやり直してください。",
            file=sys.stderr,
        )
        return 7
    if isinstance(exc, RollbackDetectedError):
        print(f"[dfs5r] 巻き戻しを検出しました（B6）: {exc}", file=sys.stderr)
        return 8
    if isinstance(exc, SilentDropDetectedError):
        print(f"[dfs5r] 黙った破棄を検出しました（B7）: {exc}", file=sys.stderr)
        return 9
    if isinstance(exc, ServiceUnavailableError):
        print(f"[dfs5r] L2/L3 に到達できません: {exc}", file=sys.stderr)
        return 6
    if isinstance(exc, (UsageError, RemoteError)):
        print(f"[dfs5r] {exc}", file=sys.stderr)
        return 2
    print(f"[dfs5r] 予期しないエラー: {type(exc).__name__}: {exc}", file=sys.stderr)
    return 1


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args) or 0)
    except KeyboardInterrupt:
        print("\n[dfs5r] 中断しました", file=sys.stderr)
        return 130
    except SystemExit:
        raise
    except BaseException as e:  # noqa: BLE001 - CLI の最外殻でまとめて扱う
        return _friendly_error(e)


if __name__ == "__main__":
    raise SystemExit(main())
