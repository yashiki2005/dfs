#!/usr/bin/env python3
"""
dfs/fs/core.py
ファイルシステム抽象の実装。

``FileSystem`` は 1 つのルートディレクトリを扱い、
  * ``snapshot(snap_id)``  : ルート直下の作業ツリーを不変のスナップショットへ複製する
  * ``clone(src, dst)``     : 1 ファイル/ディレクトリを複製する
  * ``materialize(src)``    : スナップショットを新しい実体へ書き出す
を提供する。

CoW の有無は ``FileSystem.backend`` と ``FileSystem.info()`` で確認できる。
CoW が無い環境では ``copy`` (実コピー) に自動で落ちる。
"""

from __future__ import annotations

import errno
import os
import platform
import re
import shutil
import stat
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from dfs.fs.platform import (
    Capability,
    BackendInfo,
    Backend,
    CopyBackend,
    ReflinkBackend,
    FastCloneBackend,
    detect_cow_backend,
    is_windows,
    is_windows_junction,
    is_winerror_1314,
    clear_readonly_and_retry,
    safe_target,
    copyfile_no_follow,
    UnsafePathError,
    remove_tree,
    _recreate_symlink,
    _ignored,
    DEFAULT_IGNORE_NAMES,
    DEFAULT_IGNORE_PREFIXES,
    SNAPSHOT_ID_RE,
    _validate_snapshot_id,
)


@dataclass
class SnapshotResult:
    snapshot_id: str
    path: Path
    backend: str
    files: int
    bytes_copied: int
    skipped: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


class FileSystem:
    """1 つのルートディレクトリを CoW-aware に扱う。

    ``root``
        作業ツリー ``root/tree`` とスナップショット ``root/.clayfs/snapshots`` を
        持つディレクトリ。
    ``backend``
        ``"auto"`` (既定) で自動検出。``"copy"`` を明示すると実コピーを強制する。
    """

    def __init__(
        self,
        root: Path | str,
        backend: str = "auto",
        work_tree: Optional[Path | str] = None,
        snap_root: Optional[Path | str] = None,
        ignore: Sequence[str] = (),
    ):
        self.root = Path(root).resolve()
        self.work_tree = Path(work_tree) if work_tree is not None else self.root / "tree"
        self.snap_root = (
            Path(snap_root) if snap_root is not None else self.root / ".clayfs" / "snapshots"
        )
        self.ignore = tuple(ignore)
        self.work_tree.mkdir(parents=True, exist_ok=True)
        self.snap_root.mkdir(parents=True, exist_ok=True)
        self._backend = self._select_backend(backend)
        self._warnings: List[str] = []

    # -- 選択 ---------------------------------------------------------------
    def _select_backend(self, requested: str) -> Backend:
        if requested == "copy":
            return CopyBackend()
        if requested == "reflink":
            info = self._probe_reflink(self.root)
            if info is None:
                info = self._probe_block_clone(self.root)
            if info is None:
                raise RuntimeError("reflink backend is not available on this filesystem")
            return self._make_backend(info)
        if requested in ("fast_clone", "block_clone"):
            info = self._probe_block_clone(self.root)
            if info is None:
                raise RuntimeError("block clone backend is not available on this filesystem")
            return self._make_backend(info)
        if requested not in ("auto", ""):
            raise ValueError(f"unknown backend: {requested!r}")
        # 自動検出: platform.detect_cow_backend を使用
        backend_name = detect_cow_backend(self.root)
        if backend_name == "fast_clone":
            return FastCloneBackend()
        elif backend_name == "reflink":
            system = platform.system()
            if system == "Darwin":
                from dfs.fs.platform import macos_clonefile
                return ReflinkBackend(macos_clonefile, "macOS clonefile(2)")
            if system == "Linux":
                from dfs.fs.platform import linux_ficlone
                return ReflinkBackend(linux_ficlone, "Linux FICLONE ioctl")
        return CopyBackend()

    @staticmethod
    def _make_backend(info: BackendInfo) -> Backend:
        system = platform.system()
        if system == "Darwin":
            from dfs.fs.platform import macos_clonefile
            return ReflinkBackend(macos_clonefile, info.detail)
        if system == "Linux":
            from dfs.fs.platform import linux_ficlone
            return ReflinkBackend(linux_ficlone, info.detail)
        if info.capability is Capability.FAST_CLONE:
            return FastCloneBackend(info.detail)
        return CopyBackend()

    def _probe_reflink(self, path: Path) -> Optional[BackendInfo]:
        """path の上で 1 ファイルを実際に複製してみて CoW が使えるか確かめる。"""
        import tempfile

        system = platform.system()
        if system not in ("Darwin", "Linux"):
            return None
        with tempfile.TemporaryDirectory(prefix="dfs_fs_probe_", dir=str(path)) as probe:
            probe_dir = Path(probe)
            src = probe_dir / "probe_src"
            dst = probe_dir / "probe_dst"
            src.write_bytes(b"dfs")
            try:
                if system == "Darwin":
                    from dfs.fs.platform import macos_clonefile
                    macos_clonefile(str(src), str(dst))
                    return BackendInfo(
                        "reflink", Capability.REFLINK, "macOS clonefile(2)", True
                    )
                if system == "Linux":
                    from dfs.fs.platform import linux_ficlone
                    linux_ficlone(str(src), str(dst))
                    return BackendInfo(
                        "reflink", Capability.REFLINK, "Linux FICLONE ioctl", True
                    )
            except OSError:
                return None
            except Exception:
                return None
        return None

    def _probe_block_clone(self, path: Path) -> Optional[BackendInfo]:
        """Windows の ReFS / Dev Drive block clone を実際に試す。"""
        if not is_windows():
            return None
        import tempfile

        # block clone はクラスタ単位。1 クラスタ未満だと常に ENOTSUP になるので、
        # 1 MiB を書いて「本当に複製できたか」と「中身が一致するか」まで確かめる。
        payload = b"\x00" * (1024 * 1024)
        with tempfile.TemporaryDirectory(prefix="dfs_fs_clone_", dir=str(path)) as probe:
            probe_dir = Path(probe)
            src = probe_dir / "probe_src"
            dst = probe_dir / "probe_dst"
            src.write_bytes(payload)
            try:
                from dfs.fs.platform import _windows_block_clone
                _windows_block_clone(str(src), str(dst))
                if not dst.exists() or dst.stat().st_size != len(payload):
                    return None
                if dst.read_bytes() != payload:
                    return None
                return BackendInfo(
                    "fast_clone",
                    Capability.FAST_CLONE,
                    "Windows FSCTL_DUPLICATE_EXTENTS_TO_FILE",
                    True,
                )
            except Exception:  # noqa: BLE001 - 検出なので落とさない
                return None

    @property
    def backend(self) -> Backend:
        return self._backend

    @property
    def is_cow(self) -> bool:
        return self._backend.capability is not Capability.COPY

    def info(self) -> Dict[str, object]:
        return {
            "root": str(self.root),
            "backend": self._backend.name,
            "capability": self._backend.capability.value,
            "cow": self.is_cow,
            "detail": getattr(self._backend, "detail", ""),
            "warnings": list(self._warnings),
        }

    # -- スナップショット ---------------------------------------------------
    def take_snapshot(self, snap_id: str) -> SnapshotResult:
        snap_id = _validate_snapshot_id(snap_id)
        dest = self.snap_root / snap_id
        if dest.exists() or dest.is_symlink():
            if dest.is_symlink() or dest.is_file():
                dest.unlink()
            else:
                remove_tree(dest)
        skipped: List[str] = []
        files, total = self._copy_tree_safe(self.work_tree, dest, skipped)
        if (dest / ".clayfs").exists():
            raise RuntimeError("Invariant violation: .clayfs leaked into snapshot")
        return SnapshotResult(
            snapshot_id=snap_id,
            path=dest,
            backend=self._backend.name,
            files=files,
            bytes_copied=total,
            skipped=skipped,
            warnings=list(self._warnings),
        )

    def _copy_tree_safe(
        self, src: Path, dst: Path, skipped: List[str]
    ) -> Tuple[int, int]:
        """backend でコピーする。CoW できなかった項目は実コピーで救済し、記録する。"""
        files = 0
        total = 0
        dst.mkdir(parents=True, exist_ok=True)
        for entry in sorted(src.iterdir()):
            name = entry.name
            if name in DEFAULT_IGNORE_NAMES or name.startswith(DEFAULT_IGNORE_PREFIXES):
                continue
            if _ignored(name, self.ignore):
                continue
            target = dst / name
            if entry.is_symlink():
                try:
                    _recreate_symlink(entry, target)
                except OSError as exc:
                    # Windows で Developer Mode が無いと symlink を作れない。
                    # スナップショット全体を落とすより、記録して先へ進む。
                    if is_winerror_1314(exc):
                        skipped.append(str(entry))
                        self._warnings.append(
                            f"symlink を作れないためスナップショットから除外: {entry}"
                        )
                    else:
                        raise
            elif is_windows_junction(entry):
                # ツリー外を指し得るので辿らない。黙って落とさず記録する。
                skipped.append(str(entry))
            elif entry.is_dir():
                sub_files, sub_bytes = self._copy_tree_safe(entry, target, skipped)
                files += sub_files
                total += sub_bytes
            elif entry.is_file():
                try:
                    total += self._backend.copy_file(entry, target)
                    files += 1
                except OSError as exc:
                    if exc.errno in (
                        errno.EINVAL, errno.ENOTSUP, errno.EXDEV, errno.EOPNOTSUPP,
                    ):
                        CopyBackend().copy_file(entry, target)
                        total += target.stat().st_size
                        files += 1
                        self._warnings.append(f"copy-on-write failed, fell back to copy: {entry}")
                    else:
                        raise
            else:
                # FIFO / socket / device はスナップショットに含めない。
                skipped.append(str(entry))
        try:
            shutil.copystat(src, dst, follow_symlinks=False)
        except OSError:
            pass
        return files, total

    # -- 単体コピー ---------------------------------------------------------
    def clone(self, src: Path | str, dst: Path | str) -> int:
        """1 ファイル/ディレクトリを複製する。CoW があればそれを使う。"""
        src_p = Path(src)
        dst_p = Path(dst)
        if dst_p.exists() or dst_p.is_symlink():
            if dst_p.is_dir() and not dst_p.is_symlink():
                remove_tree(dst_p)
            else:
                dst_p.unlink()
        if src_p.is_dir() and not src_p.is_symlink():
            files, total = self._backend.copy_tree(src_p, dst_p, self.ignore)
            return total
        return self._backend.copy_file(src_p, dst_p)

    def materialize(self, src: Path | str, dst: Path | str) -> Path:
        """スナップショット ``src`` を新しい実体 ``dst`` として書き出す。"""
        dst_p = Path(dst)
        if dst_p.exists() or dst_p.is_symlink():
            if dst_p.is_dir() and not dst_p.is_symlink():
                remove_tree(dst_p)
            else:
                dst_p.unlink()
        self._backend.copy_tree(Path(src), dst_p, self.ignore)
        return dst_p

    def read_snapshot(self, snap_id: str) -> Path:
        """スナップショット ID を実ファイルツリーとして解決する。"""
        return self.snap_root / _validate_snapshot_id(snap_id)


def detect_backends(root: Path) -> List[BackendInfo]:
    """root の上で使えるバックエンドを、高性能な順に返す。"""
    from .platform import detect_cow_backend, BackendInfo, Capability
    
    infos: List[BackendInfo] = [BackendInfo("copy", Capability.COPY, "実コピー", True)]
    
    backend_name = detect_cow_backend(root)
    if backend_name == "fast_clone":
        infos.insert(0, BackendInfo("fast_clone", Capability.FAST_CLONE, "Windows FSCTL_DUPLICATE_EXTENTS_TO_FILE", True))
    elif backend_name == "reflink":
        system = platform.system()
        if system == "Darwin":
            infos.insert(0, BackendInfo("reflink", Capability.REFLINK, "macOS clonefile(2)", True))
        elif system == "Linux":
            infos.insert(0, BackendInfo("reflink", Capability.REFLINK, "Linux FICLONE ioctl", True))
    
    return infos


def default_backend_name(root: Path) -> str:
    infos = detect_backends(root)
    return infos[0].name
