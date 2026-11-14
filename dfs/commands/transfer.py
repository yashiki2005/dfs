"""File listing, transfer, sync, pull, import, mount, and filesystem subcommands."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import tarfile
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from dfs.commands import _cm


def cmd_history(args: argparse.Namespace) -> int:
    """L2 の署名済み L4 ログ履歴を表示する。"""
    store = _cm.RemoteStore()
    name, sub = _cm.split_remote_spec(args.remote, args.remote_name)
    remote = _cm._resolve_remote(store, name)
    path = ("/" + sub.lstrip("/")) if sub else remote.path
    if not path:
        raise _cm.UsageError(
            "history にはパスが必要です（例: dfscli history remote:/example.com/alice）"
        )
    client = _cm.cli_mod.RemoteRegistryClient(remote.registry_urls())
    try:
        rows = client.history(path, limit=args.limit)
    except Exception as e:  # noqa: BLE001
        raise _cm.UsageError(f"history の取得に失敗しました: {e}") from e
    for row in rows:
        print(
            f"v{row.get('version', '?'):<6} {row.get('timestamp', '?')} "
            f"{str(row.get('entry_hash', ''))[:16]}"
        )
    return 0


def cmd_ls(args: argparse.Namespace) -> int:
    store = _cm.RemoteStore()
    name, sub = _cm.split_remote_spec(args.remote, args.remote_name)
    node = _cm.open_remote(_cm._resolve_remote(store, name), create=True)
    for e in _cm._rel_entries(node, _cm._norm_prefix(sub)):
        if e["type"] == "dir":
            print(e["rel"] + "/")
        else:
            print(e["rel"])
    return 0


def cmd_lsd(args: argparse.Namespace) -> int:
    """リモートの直下にあるディレクトリだけを一覧する。"""
    store = _cm.RemoteStore()
    name, sub = _cm.split_remote_spec(args.remote, args.remote_name)
    node = _cm.open_remote(_cm._resolve_remote(store, name), create=True)
    for e in _cm._rel_entries(node, _cm._norm_prefix(sub)):
        if e["type"] == "dir":
            print(e["rel"] + "/")
    return 0


def cmd_lsl(args: argparse.Namespace) -> int:
    store = _cm.RemoteStore()
    name, sub = _cm.split_remote_spec(args.remote, args.remote_name)
    node = _cm.open_remote(_cm._resolve_remote(store, name), create=True)
    for e in _cm._rel_entries(node, _cm._norm_prefix(sub)):
        rel = e["rel"] + ("/" if e["type"] == "dir" else "")
        size = e.get("size", 0)
        print(f"{size:>12}  {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())}  {rel}")
    return 0


def cmd_lsjson(args: argparse.Namespace) -> int:
    store = _cm.RemoteStore()
    name, sub = _cm.split_remote_spec(args.remote, args.remote_name)
    node = _cm.open_remote(_cm._resolve_remote(store, name), create=True)
    rows = []
    for e in _cm._all_entries(node, _cm._norm_prefix(sub)):
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
    store = _cm.RemoteStore()
    name, sub = _cm.split_remote_spec(args.remote, args.remote_name)
    node = _cm.open_remote(_cm._resolve_remote(store, name), create=True)
    files = [e for e in _cm._all_entries(node, _cm._norm_prefix(sub)) if e["type"] == "file"]
    total = sum(int(e.get("size", 0)) for e in files)
    print(f"Total objects: {len(files)}")
    print(f"Total size: {total} ({_cm._human_size(total)})")
    unique_chunks = {
        chunk["wire_id"]
        for entry in files
        for chunk in (entry.get("chunks") or [entry])
    }
    print(f"Unique chunks (wire_id): {len(unique_chunks)}")
    return 0


def cmd_cat(args: argparse.Namespace) -> int:
    store = _cm.RemoteStore()
    name, sub = _cm.split_remote_spec(args.remote, args.remote_name)
    if not sub:
        raise _cm.UsageError("cat にはファイルのパスが必要です（例: remote:dir/file.txt）")
    node = _cm.open_remote(_cm._resolve_remote(store, name), create=True)
    try:
        data = node.read_remote(sub)
    except (FileNotFoundError, IsADirectoryError, NotADirectoryError) as e:
        raise _cm.UsageError(str(e)) from e
    _cm.sys.stdout.buffer.write(data)
    _cm.sys.stdout.buffer.flush()
    return 0


def _print_plan(action: str, items: List[str], dry_run: bool) -> None:
    head = "[dfscli] " + ("(dry-run) " if dry_run else "")
    print(f"{head}{action}: {len(items)} 件", file=_cm.sys.stderr)
    if dry_run:
        for i in items[:40]:
            print(f"  {i}", file=_cm.sys.stderr)
        if len(items) > 40:
            print(f"  ... ほか {len(items) - 40} 件", file=_cm.sys.stderr)


def cmd_copy(args: argparse.Namespace) -> int:
    """ローカルのファイルをリモートへ足す（リモートにしかないものは残す）。

    変更が無ければ版を作らない（rclone と同じく冪等）。判定は大きさを先に見て、
    ``--checksum size|crc32|sha1|plain_id`` で変更検出方法を選ぶ。
    """
    store = _cm.RemoteStore()
    name, sub = _cm.split_remote_spec(args.dest, args.remote_name)
    remote = store.get(name)
    _cm._require_writable(remote)
    prefix = _cm._norm_prefix(sub)
    path_filter = _cm._path_filter(args)
    local = _cm._filter_local(_cm._collect_local(Path(args.src)), path_filter)
    if not local:
        print("[dfscli] コピーするファイルがありません", file=_cm.sys.stderr)
        return 0

    node = _cm.open_remote(remote, create=True)
    _cm.refresh_cache(node)
    writes, _deletes, unchanged = _cm.plan_changes(
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
            file=_cm.sys.stderr,
        )
        return 0

    _cm.apply_writes(node, writes)
    t0 = time.perf_counter()
    log_env, sent = _cm._push(node, remote)
    ms = (time.perf_counter() - t0) * 1000.0
    print(
        f"[dfscli] copy OK -> v{log_env['payload']['version']} "
        f"| 追加/更新 {len(writes)} 件（同じ {len(unchanged)} 件） | sent={sent} B | {ms:.1f} ms"
    )
    return 0


def cmd_copyto(args: argparse.Namespace) -> int:
    """ローカルの 1 ファイルを、リモートの指定パスへそのまま置く。"""
    store = _cm.RemoteStore()
    name, sub = _cm.split_remote_spec(args.dest, args.remote_name)
    remote = store.get(name)
    _cm._require_writable(remote)
    if not sub:
        raise _cm.UsageError("copyto の宛先にはファイル名が必要です（例: remote:dir/name.txt）")
    src = Path(args.src).expanduser()
    if not src.is_file():
        raise _cm.UsageError(f"Local file does not exist: {src}")

    _print_plan("copyto", [f"{src} -> {remote.name}:{sub}"], args.dry_run)
    if args.dry_run:
        return 0

    node = _cm.open_remote(remote, create=True)
    _cm.refresh_cache(node)
    writes, _deletes, unchanged = _cm.plan_changes(node, "", {sub: src}, checksum=args.checksum)
    if not writes:
        print(
            f"[dfscli] copyto: 変更なし（{sub} は同じ）。新しい版は作りません",
            file=_cm.sys.stderr,
        )
        return 0
    _cm.apply_writes(node, writes)

    log_env, sent = _cm._push(node, remote)
    print(
        f"[dfscli] copyto OK -> v{log_env['payload']['version']} "
        f"| {sub} | sent={sent} B"
    )
    return 0


def _read_archive_meta_if_bundle(meta_path: Path) -> Optional[Dict[str, Any]]:
    try:
        data = json.loads(meta_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return None
    if (
        isinstance(data, dict)
        and data.get("schema") == _cm.ARCHIVE_SCHEMA
        and isinstance(data.get("chunks"), list)
    ):
        return data
    return None


def _detect_archive_bundle_in_tree(files: Dict[str, Path]) -> Optional[Path]:
    """展開済み tar 内に DFS archive bundle (`meta.json`) が含まれるか判定する。"""
    matches: List[Path] = []
    for rel, path in files.items():
        if Path(rel).name != "meta.json":
            continue
        if _read_archive_meta_if_bundle(path) is not None:
            matches.append(path.parent)
    if len(matches) > 1:
        raise _cm.UsageError(
            "アーカイブ内に複数の DFS archive bundle (meta.json) が含まれています"
        )
    return matches[0] if matches else None


def _detect_archive_bundle_dir(directory: Path) -> Path:
    """ディレクトリ内から DFS archive bundle を探す。"""
    direct = directory / "meta.json"
    if direct.is_file() and _read_archive_meta_if_bundle(direct) is not None:
        return directory
    matches: List[Path] = []
    for child in sorted(directory.iterdir()):
        if not child.is_dir():
            continue
        meta_path = child / "meta.json"
        if meta_path.is_file() and _read_archive_meta_if_bundle(meta_path) is not None:
            matches.append(child)
    if len(matches) > 1:
        raise _cm.UsageError(
            f"ディレクトリ内に複数の DFS archive bundle が含まれています: {directory}"
        )
    if not matches:
        raise _cm.UsageError(
            f"DFS archive bundle (meta.json) が見つかりません: {directory}"
        )
    return matches[0]


def _scan_extracted_tree(root: Path) -> Tuple[Dict[str, Path], set]:
    """展開済みディレクトリから通常ファイルと空ディレクトリを含む一覧を作る。"""
    files: Dict[str, Path] = {}
    dirs = set()
    if not root.exists():
        return files, dirs
    for current, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(
            d for d in dirnames if d != ".DS_Store" and not d.startswith("._")
        )
        cur_path = Path(current)
        rel_dir = cur_path.relative_to(root)
        if rel_dir != Path("."):
            dirs.add(rel_dir.as_posix())
        for fname in sorted(filenames):
            if fname == ".DS_Store" or fname.startswith("._"):
                continue
            fpath = cur_path / fname
            if fpath.is_file():
                rel = fpath.relative_to(root).as_posix()
                files[rel] = fpath
    return files, dirs


def _resolve_import_bundle_secret(args: argparse.Namespace, remote: _cm.Remote) -> str:
    secret = getattr(args, "source_secret", None) or remote.secret
    if not secret and not getattr(args, "no_prompt", False):
        secret = _cm.prompt_secret(
            "archive の tree_secret: ", "archive の tree_secret（確認）: "
        )
    if not secret:
        raise _cm.UsageError(
            "DFS archive bundle の復号には --source-secret"
            "（または宛先リモートの secret）が必要です"
        )
    return secret


def cmd_import(args: argparse.Namespace) -> int:
    """tar アーカイブまたは DFS archive bundle をリモートへインポートする。

    - 通常の tar / tar.gz / tar.xz / tar.bz2: 通常ファイルとディレクトリを 1 版として反映する。
    - `dfscli archive create` で作った bundle（フォルダまたは tar.gz 等に固めたもの）:
      署名を検証・復号して 1 版として取り込む。

    既存のリモートにしかないファイルは削除しない（copy と同じ追加・更新）。
    """
    if args.strip_components < 0:
        raise _cm.UsageError("--strip-components は 0 以上にしてください")
    store = _cm.RemoteStore()
    name, sub = _cm.split_remote_spec(args.dest, args.remote_name)
    remote = store.get(name)
    _cm._require_writable(remote)
    prefix = _cm._norm_prefix(sub)
    archive = Path(args.archive).expanduser()
    if not archive.exists():
        raise _cm.UsageError(f"インポート対象がありません: {archive}")

    with tempfile.TemporaryDirectory(prefix="dfs_import_") as tmp:
        tmp_path = Path(tmp)
        bundle_dir: Optional[Path] = None
        if archive.is_dir():
            bundle_dir = _detect_archive_bundle_dir(archive)
        elif archive.is_file():
            staging = tmp_path / "extract"
            staging.mkdir()
            try:
                files, dirs = _cm._extract_tar_safely(
                    archive, staging, args.strip_components
                )
            except (_cm.UsageError, tarfile.TarError, OSError):
                par2_index = archive.with_name(f"{archive.name}.par2")
                if not (par2_index.is_file() and _cm.find_par2_binary()):
                    raise
                try:
                    repaired = _cm.repair_with_par2(
                        archive, par2_index, tmp_path / "par2_repair"
                    )
                except _cm.ArchiveError as e:
                    raise _cm.UsageError(
                        f"tar が破損しており par2 での修復にも失敗しました: {e}"
                    ) from e
                print(
                    f"[dfscli] import: アーカイブの破損を検出し、par2 で修復しました: "
                    f"{archive.name}",
                    file=_cm.sys.stderr,
                )
                staging_repaired = tmp_path / "extract_repaired"
                staging_repaired.mkdir()
                files, dirs = _cm._extract_tar_safely(
                    repaired, staging_repaired, args.strip_components
                )
            bundle_dir = _detect_archive_bundle_in_tree(files)
        else:
            raise _cm.UsageError(f"ファイルまたはディレクトリではありません: {archive}")

        if bundle_dir is not None:
            secret = _resolve_import_bundle_secret(args, remote)
            restored = tmp_path / "restored"
            try:
                _cm.extract_bundle(bundle_dir, restored, secret)
            except Exception as e:  # noqa: BLE001
                raise _cm.UsageError(
                    f"DFS archive bundle の展開・検証に失敗しました: {e}"
                ) from e
            files, dirs = _scan_extracted_tree(restored)

        if not files and not dirs:
            print(f"[dfscli] import: インポートするものがありません: {archive}")
            return 0

        node = _cm.open_remote(remote, create=True)
        _cm.refresh_cache(node)
        remote_files = _cm._remote_file_paths(node)
        remote_dirs = _cm._remote_dir_paths(node)
        target_files = {_cm._join_prefix(prefix, rel) for rel in files}
        target_dirs = {_cm._join_prefix(prefix, rel) for rel in dirs}
        file_dir_conflicts = sorted(target_files & remote_dirs)
        dir_file_conflicts = sorted(target_dirs & remote_files)
        if file_dir_conflicts or dir_file_conflicts:
            detail = ", ".join(file_dir_conflicts + dir_file_conflicts[:5])
            raise _cm.UsageError(f"ファイルとディレクトリが衝突します: {detail}")

        # staging を再走査せず、安全展開で確定したファイルだけを使う。
        local = files
        writes, _deletes, unchanged = _cm.plan_changes(
            node, prefix, local, checksum="plain_id"
        )
        new_dirs = sorted(
            rel for rel in dirs
            if _cm._join_prefix(prefix, rel) not in remote_dirs
        )
        plan = (
            [f"{kind:6} {name}:{path}" for path, _src, kind in writes]
            + [f"mkdir  {name}:{_cm._join_prefix(prefix, rel)}/" for rel in new_dirs]
        )
        _print_plan("import", plan, args.dry_run)
        if args.dry_run:
            return 0
        if not writes and not new_dirs:
            print(
                f"[dfscli] import: 変更なし（{len(unchanged)} ファイルが同じ）。"
                "新しい版は作りません",
                file=_cm.sys.stderr,
            )
            return 0

        _cm.apply_writes(node, writes)
        for rel in new_dirs:
            target = _cm._tree_path(node, _cm._join_prefix(prefix, rel))
            try:
                target.mkdir(parents=True, exist_ok=True)
            except OSError as e:
                raise _cm.UsageError(f"ディレクトリを作成できません: {rel}: {e}") from e

        log_env, sent = _cm._push(node, remote)
        print(
            f"[dfscli] import OK -> v{log_env['payload']['version']} "
            f"| files={len(writes)} dirs={len(new_dirs)} same={len(unchanged)} "
            f"| sent={sent} B"
        )
    return 0


cmd_import_tar = cmd_import


def _configure_fuse_library(explicit: Optional[str] = None) -> None:
    """macOS では fuse-t を必須にし、fusepy の macFUSE フォールバックを防ぐ。"""
    if explicit:
        os.environ["FUSE_LIBRARY_PATH"] = str(Path(explicit).expanduser())
        return
    if _cm.sys.platform != "darwin":
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
    raise _cm.UsageError(
        "マウント機能には fuse-t が必要です。"
        "macOS では "
        "`brew install macos-fuse-t/homebrew-cask/fuse-t` "
        "でインストールしてください"
    )


def cmd_mount(args: argparse.Namespace) -> int:
    """リモートのサブツリーを fuse-t / fusepy でローカルにマウントする。

    作業ツリーを FUSE に公開し、flush / fsync / unmount 時に DFS へ push する。
    """
    store = _cm.RemoteStore()
    name, sub = _cm.split_remote_spec(args.remote, args.remote_name)
    remote = store.get(name)
    mountpoint = Path(args.mountpoint).expanduser()
    if not mountpoint.exists():
        mountpoint.mkdir(parents=True, exist_ok=True)
    if not mountpoint.is_dir():
        raise _cm.UsageError(f"マウントポイントがディレクトリではありません: {mountpoint}")

    node = _cm.open_remote(remote, create=True)
    _cm.refresh_cache(node)

    def flush_to_dfs() -> None:
        log_env, sent = _cm._push(node, remote)
        print(
            f"[dfscli] mount flush -> v{log_env['payload']['version']} "
            f"| sent={sent} B",
            file=_cm.sys.stderr,
        )

    try:
        from dfs.fuse_mount import LocalTreeFuse
    except ImportError as e:  # pragma: no cover - 依存環境
        raise _cm.UsageError(
            "mount には fusepy と fuse-t / FUSE が必要です "
            "(pip install 'dfs[fuse]')"
        ) from e

    _configure_fuse_library(args.fuse_library)
    try:
        from fuse import FUSE
    except (ImportError, OSError) as e:
        raise _cm.UsageError(
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
        print("\n[dfscli] mount を終了します", file=_cm.sys.stderr)
    finally:
        operations.destroy("/")
    return 0


def cmd_mv(args: argparse.Namespace) -> int:
    """リモート内でファイルまたはディレクトリを移動・改名する。

    移動は作業ツリー上の rename として行い、最後に 1 版だけ push する。宛先が
    既に存在する場合は既定で拒否する。ファイル同士の置換だけは ``--overwrite``
    で許可する（ディレクトリの merge は行わない）。
    """
    store = _cm.RemoteStore()
    src_name, src_sub = _cm.split_remote_spec(args.src, args.remote_name)
    dst_name, dst_sub = _cm.split_remote_spec(args.dst, args.remote_name)
    if src_name != dst_name:
        raise _cm.UsageError("mv は同じリモート内だけで使えます（別リモート間は copy + rm）")

    src = _cm._norm_prefix(src_sub)
    dst = _cm._norm_prefix(dst_sub)
    if not src or not dst:
        raise _cm.UsageError("mv には移動元と移動先のパスが必要です（例: remote:old remote:new）")
    if src == dst:
        print(f"[dfscli] mv: 移動元と移動先が同じです（{src_name}:{src}）", file=_cm.sys.stderr)
        return 0

    remote = store.get(src_name)
    _cm._require_writable(remote)
    node = _cm.open_remote(remote, create=True)
    _cm.refresh_cache(node)

    files = _cm._remote_file_paths(node)
    dirs = _cm._remote_dir_paths(node)
    if src in files:
        src_kind = "file"
    elif src in dirs:
        src_kind = "dir"
    else:
        raise _cm.UsageError(f"{src_name}:{src} は見つかりません")

    if src_kind == "dir" and dst.startswith(src + "/"):
        raise _cm.UsageError("ディレクトリを自分自身の下へ移動することはできません")

    dst_kind = "file" if dst in files else ("dir" if dst in dirs else None)
    if dst_kind is not None:
        if not (src_kind == "file" and dst_kind == "file" and args.overwrite):
            raise _cm.UsageError(
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

    src_path = _cm._tree_path(node, src)
    dst_path = _cm._tree_path(node, dst)
    try:
        dst_path.parent.mkdir(parents=True, exist_ok=True)
        if dst_kind == "file":
            os.replace(src_path, dst_path)
        else:
            src_path.rename(dst_path)
    except OSError as e:
        raise _cm.UsageError(f"移動に失敗しました: {e}") from e

    log_env, sent = _cm._push(node, remote)
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
    store = _cm.RemoteStore()
    name, sub = _cm.split_remote_spec(args.dest, args.remote_name)
    remote = store.get(name)
    _cm._require_writable(remote)
    prefix = _cm._norm_prefix(sub)
    path_filter = _cm._path_filter(args)
    local = _cm._filter_local(_cm._collect_local(Path(args.src)), path_filter)

    node = _cm.open_remote(remote, create=True)
    _cm.refresh_cache(node)
    writes, deletes, unchanged = _cm.plan_changes(
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
            file=_cm.sys.stderr,
        )
        return 0
    _print_plan("sync", plan, args.dry_run)
    if args.dry_run:
        return 0

    _cm.apply_writes(node, writes)
    if deletes:
        _cm.apply_deletes(node, deletes)

    log_env, sent = _cm._push(node, remote)
    n_add = sum(1 for _p, _s, k in writes if k == "add")
    n_upd = sum(1 for _p, _s, k in writes if k == "update")
    print(
        f"[dfscli] sync OK -> v{log_env['payload']['version']} "
        f"| add={n_add} update={n_upd} delete={len(deletes)} "
        f"| same={len(unchanged)} | sent={sent} B"
    )
    return 0


def _pull_once(
    node: _cm.DFSNode,
    remote: _cm.Remote,
    prefix: str,
    dest: Path,
    path_filter: Any,
    *,
    force: bool = False,
) -> Tuple[int, int]:
    version = _cm.refresh_cache(node, force=force)
    work_root = node.clayfs.work_tree.resolve(strict=False)
    src_root = work_root if not prefix else work_root / prefix
    try:
        src_root.resolve(strict=False).relative_to(work_root)
    except ValueError as e:
        raise _cm.UsageError(f"_cm.Remote path escapes the work tree: {prefix!r}") from e
    if not src_root.exists():
        raise _cm.UsageError(f"_cm.Remote path does not exist: {remote.name}:{prefix}")

    dest.mkdir(parents=True, exist_ok=True)
    count = 0
    for item in sorted(src_root.rglob("*")):
        rel = item.relative_to(src_root)
        if any(part in (".clayfs",) for part in rel.parts):
            continue
        if item.name in (".DS_Store",) or item.name.startswith("._"):
            continue
        if item.is_symlink():
            print(f"[dfscli] warning: skipping symlink: {item}", file=_cm.sys.stderr)
            continue
        rel_text = rel.as_posix()
        if not path_filter.allows(rel_text):
            continue
        try:
            target = _cm.safe_target(dest, rel_text, create_parents=True)
        except _cm.UnsafePathError as e:
            raise _cm.UsageError(f"Invalid pull destination: {rel_text!r} ({e})") from e
        if item.is_dir():
            target.mkdir(parents=True, exist_ok=True)
            continue
        try:
            _cm.copyfile_no_follow(item, target)
        except _cm.UnsafePathError as e:
            raise _cm.UsageError(f"Refusing symlink write: {rel_text!r} ({e})") from e
        count += 1
    return version, count


def cmd_pull(args: argparse.Namespace) -> int:
    """リモートの指定パスを、ローカルディレクトリへ取り出す。"""
    store = _cm.RemoteStore()
    name, sub = _cm.split_remote_spec(args.src, args.remote_name)
    remote = store.get(name)
    prefix = _cm._norm_prefix(sub)
    node = _cm.open_remote(remote, create=True)
    path_filter = _cm._path_filter(args)
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
                print(f"[dfscli] watch poll failed: {e}", file=_cm.sys.stderr)
                continue
            if latest > last_version:
                version, count = _pull_once(
                    node, remote, prefix, dest, path_filter, force=False
                )
                last_version = version
                print(f"[dfscli] pull OK <- v{version} | {count} ファイル -> {dest}")
    except KeyboardInterrupt:
        print("\n[dfscli] watch を終了します", file=_cm.sys.stderr)
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    """リモートの指定パスとローカルディレクトリを比べる。"""
    store = _cm.RemoteStore()
    name, sub = _cm.split_remote_spec(args.remote, args.remote_name)
    remote = store.get(name)
    prefix = _cm._norm_prefix(sub)
    node = _cm.open_remote(remote, create=True)

    remote_files = {
        e["path"][len(prefix) + 1 if prefix else 0:]: int(e.get("size", 0))
        for e in _cm._all_entries(node, prefix) if e["type"] == "file"
    }
    local_files = {}
    base = Path(args.local).expanduser()
    for rel, path in _cm._collect_local(base).items():
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
    store = _cm.RemoteStore()
    name, sub = _cm.split_remote_spec(args.remote, args.remote_name)
    remote = store.get(name)
    node = _cm.open_remote(remote, create=True)
    pin = node.l4.pin
    # 定義に書かれていない ost / path は、実際に使った値（作業ディレクトリの設定）を出す。
    cfg = json.loads((node.clayfs.clayfs_meta / _cm.cli_mod.CONFIG_FILENAME).read_text(encoding="utf-8"))
    effective_path = cfg.get("sub_path") or remote.path
    effective_ost = remote.ost or f"{cfg.get('ost_host', '')}:{cfg.get('ost_port', '')}"
    print(f"_cm.Remote      : {name}")
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
                f"_cm.Remote Head : v{hp['version']} (epoch={hp['delegation_epoch']}, "
                f"root={hp['root_plain_id'][:12]}...)"
            )
        else:
            print("_cm.Remote Head : (empty)")
    except Exception as e:  # noqa: BLE001 - 表示のためのコマンドなので落とさない
        print(f"_cm.Remote Head : [unreachable: {e}]")
    return 0


def cmd_fs(args: argparse.Namespace) -> int:
    """ローカルディレクトリの CoW 検出とスナップショット (リモート不要)。"""
    from dfs.fs import FileSystem, detect_backends

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
        snap_id = _cm._validate_snapshot_id(args.snap_id)
        result = f.take_snapshot(snap_id)
        print(f"snapshot    : {result.snapshot_id}")
        print(f"path        : {result.path}")
        print(f"backend     : {result.backend}")
        print(f"files       : {result.files}")
        print(f"bytes       : {result.bytes_copied}")
        for w in result.warnings:
            print(f"warning     : {w}", file=_cm.sys.stderr)
        return 0
    if args.action == "materialize":
        snap_id = _cm._validate_snapshot_id(args.snap_id) if args.snap_id else None
        if args.src:
            src = Path(args.src).expanduser()
        elif snap_id:
            src = root / ".clayfs" / "snapshots" / snap_id
        else:
            raise _cm.UsageError("materialize には --src か snap_id が必要")
        if not args.dst:
            raise _cm.UsageError("materialize には出力先が必要")
        f = FileSystem(root, backend=args.backend)
        out = f.materialize(src, Path(args.dst).expanduser())
        print(f"materialize : {out}")
        return 0
    raise _cm.UsageError(f"unknown fs action: {args.action}")


def cmd_mkdir(args: argparse.Namespace) -> int:
    """リモートにディレクトリを作る（空のディレクトリも版に残る）。"""
    store = _cm.RemoteStore()
    name, sub = _cm.split_remote_spec(args.remote, args.remote_name)
    remote = store.get(name)
    _cm._require_writable(remote)
    sub = _cm._norm_prefix(sub)
    if not sub:
        raise _cm.UsageError("mkdir にはディレクトリのパスが必要です（例: remote:dir/sub）")

    node = _cm.open_remote(remote, create=True)
    _cm.refresh_cache(node)
    existing = _cm._remote_dir_paths(node) | _cm._remote_file_paths(node)
    if sub in existing:
        print(f"[dfscli] mkdir: すでにあります: {name}:{sub}", file=_cm.sys.stderr)
        return 0

    target = _cm._tree_path(node, sub)
    target.mkdir(parents=True, exist_ok=True)
    log_env, sent = _cm._push(node, remote)
    print(f"[dfscli] mkdir OK -> v{log_env['payload']['version']} | {sub}/ | sent={sent} B")
    return 0


def cmd_rm(args: argparse.Namespace) -> int:
    """リモートのファイル（または ``--recursive`` でディレクトリ）を消す。

    rclone の ``delete`` / ``deletefile`` に当たる。消した後に空になったディレクトリは、
    ``--rmdirs`` を付けたときだけ片付ける（既定は空ディレクトリを残す。dfs は空の
    ディレクトリも版に残すため、消すか残すかを選べるようにしてある）。
    """
    store = _cm.RemoteStore()
    name, sub = _cm.split_remote_spec(args.remote, args.remote_name)
    remote = store.get(name)
    _cm._require_writable(remote)
    sub = _cm._norm_prefix(sub)
    if not sub:
        raise _cm.UsageError("rm にはパスが必要です（例: remote:dir/file.txt）")

    node = _cm.open_remote(remote, create=True)
    _cm.refresh_cache(node)

    files = _cm._remote_file_paths(node)
    dirs = _cm._remote_dir_paths(node)
    is_dir = sub in dirs
    targets: List[str] = []
    if sub in files:
        targets = [sub]
    elif is_dir:
        if not args.recursive:
            raise _cm.UsageError(
                f"{name}:{sub} はディレクトリです。中身ごと消すなら --recursive を付けてください"
            )
        targets = sorted(p for p in files if p == sub or p.startswith(sub + "/"))
        if not targets and not args.rmdirs:
            # 中身が無いディレクトリ。消すには --rmdirs が要る
            raise _cm.UsageError(
                f"{name}:{sub} は空のディレクトリです。消すなら --rmdirs を付けてください"
            )
    else:
        raise _cm.UsageError(f"{name}:{sub} は見つかりません")

    if not targets:
        if not args.rmdirs:
            print(f"[dfscli] rm: 消すファイルがありません（{name}:{sub}）", file=_cm.sys.stderr)
            return 0
        # --rmdirs なら、ファイルが無くても空ディレクトリの掃除に進む
        print(
            f"[dfscli] rm: {name}:{sub} にファイルはありません。空ディレクトリを片付けます",
            file=_cm.sys.stderr,
        )

    _print_plan("rm", [f"delete {name}:{p}" for p in targets], args.dry_run)
    if args.dry_run:
        return 0

    _cm._remove_from_tree(node, targets)
    removed_dirs: List[str] = []
    if args.rmdirs:
        if is_dir:
            _cm._remove_from_tree(node, [sub])
        removed_dirs.extend(_cm.prune_empty_parents(node, [sub]))

    log_env, sent = _cm._push(node, remote)
    extra = f" | 空になったディレクトリ {len(removed_dirs)} 件も削除" if removed_dirs else ""
    print(
        f"[dfscli] rm OK -> v{log_env['payload']['version']} "
        f"| 削除 {len(targets)} 件{extra} | sent={sent} B"
    )
    return 0


def cmd_rmdir(args: argparse.Namespace) -> int:
    """空のディレクトリを消す（中身があれば断る）。"""
    store = _cm.RemoteStore()
    name, sub = _cm.split_remote_spec(args.remote, args.remote_name)
    remote = store.get(name)
    _cm._require_writable(remote)
    sub = _cm._norm_prefix(sub)
    if not sub:
        raise _cm.UsageError("rmdir にはディレクトリのパスが必要です（例: remote:dir/sub）")

    node = _cm.open_remote(remote, create=True)
    _cm.refresh_cache(node)

    dirs = _cm._remote_dir_paths(node)
    files = _cm._remote_file_paths(node)
    if sub not in dirs:
        raise _cm.UsageError(f"{name}:{sub} はディレクトリではありません")
    children = [p for p in files if p.startswith(sub + "/")] + [
        d for d in dirs if d.startswith(sub + "/")
    ]
    if children:
        raise _cm.UsageError(
            f"{name}:{sub} は空ではありません（{len(children)} 件が下にあります）"
        )

    _print_plan("rmdir", [f"delete {name}:{sub}/"], args.dry_run)
    if args.dry_run:
        return 0

    _cm._remove_from_tree(node, [sub])
    _cm.prune_empty_parents(node, [sub])
    log_env, sent = _cm._push(node, remote)
    print(f"[dfscli] rmdir OK -> v{log_env['payload']['version']} | {sub}/ | sent={sent} B")
    return 0


def cmd_purge(args: argparse.Namespace) -> int:
    """指定パスの中身をすべて消す（ディレクトリ自身も消す）。"""
    store = _cm.RemoteStore()
    name, sub = _cm.split_remote_spec(args.remote, args.remote_name)
    remote = store.get(name)
    _cm._require_writable(remote)
    sub = _cm._norm_prefix(sub)

    node = _cm.open_remote(remote, create=True)
    _cm.refresh_cache(node)

    files = _cm._remote_file_paths(node)
    dirs = _cm._remote_dir_paths(node)
    if sub:
        targets = sorted(p for p in files if p == sub or p.startswith(sub + "/"))
        target_dirs = sorted((d for d in dirs if d == sub or d.startswith(sub + "/")),
                             key=lambda d: len(d.split("/")), reverse=True)
    else:
        targets = sorted(files)
        target_dirs = sorted(dirs, key=lambda d: len(d.split("/")), reverse=True)

    if not targets and not target_dirs:
        print(f"[dfscli] purge: 消すものがありません（{name}:{sub}）", file=_cm.sys.stderr)
        return 0

    _print_plan(
        "purge",
        [f"delete {name}:{p}" for p in targets] + [f"rmdir  {name}:{d}/" for d in target_dirs],
        args.dry_run,
    )
    if args.dry_run:
        return 0

    _cm._remove_from_tree(node, targets + target_dirs)
    _cm.prune_empty_dirs(node)
    log_env, sent = _cm._push(node, remote)
    print(
        f"[dfscli] purge OK -> v{log_env['payload']['version']} "
        f"| ファイル {len(targets)} 件・ディレクトリ {len(target_dirs)} 件 | sent={sent} B"
    )
    return 0


def cmd_touch(args: argparse.Namespace) -> int:
    """リモートの作業ディレクトリを初期化する（push/pull はしない）。"""
    store = _cm.RemoteStore()
    name, _sub = _cm.split_remote_spec(args.remote, args.remote_name)
    remote = store.get(name)
    node = _cm.open_remote(remote, create=True)
    print(f"[dfscli] 初期化しました: {node.clayfs.mount_root}")
    return 0
