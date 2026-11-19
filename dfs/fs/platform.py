#!/usr/bin/env python3
"""
dfs/platform.py
プラットフォーム固有の処理を一箇所に集約。

Windows: cluster size 取得、block clone (FSCTL_DUPLICATE_EXTENTS_TO_FILE)、
         junction 判定、read-only 属性処理、symlink 作成エラー (winerror 1314)
macOS: clonefile(2)
Linux: FICLONE ioctl
"""

from __future__ import annotations

import ctypes
import errno
import os
import platform
import re
import shutil
import stat
import sys
from pathlib import Path
from typing import Callable, Optional

# 定数
DEFAULT_IGNORE_NAMES = (".DS_Store",)
DEFAULT_IGNORE_PREFIXES = ("._",)


# ========================================================================
# Windows 固有
# ========================================================================

def is_windows() -> bool:
    """Windows で実行されているか。"""
    return sys.platform == "win32"


def _windows_cluster_size(path: str) -> int:
    """``path`` のボリュームのクラスタサイズ (バイト)。分からなければ 4096。"""
    if not is_windows():
        return 4096
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetDiskFreeSpaceW.argtypes = [
        wintypes.LPCWSTR, ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD),
    ]
    kernel32.GetDiskFreeSpaceW.restype = wintypes.BOOL
    drive = os.path.splitdrive(os.path.abspath(path))[0]
    if not drive:
        return 4096
    sectors = wintypes.DWORD()
    per_sector = wintypes.DWORD()
    free = wintypes.DWORD()
    total = wintypes.DWORD()
    ok = kernel32.GetDiskFreeSpaceW(
        drive + "\\", ctypes.byref(sectors), ctypes.byref(per_sector),
        ctypes.byref(free), ctypes.byref(total),
    )
    if not ok:
        return 4096
    return max(1, int(sectors.value) * int(per_sector.value))


def _windows_block_clone(src: str, dst: str) -> None:
    """Windows の FSCTL_DUPLICATE_EXTENTS_TO_FILE (ReFS / Dev Drive)。

    成功時は CoW の複製。NTFS など非対応 FS では OSError(ENOTSUP)。

    ReFS の block clone はクラスタ境界単位でしか複製できないため、末尾の
    半端は通常の書き込みで補う（内容は常に元ファイルと一致する）。
    1 クラスタ未満のファイルは複製する意味が無いので ENOTSUP を返し、
    呼び出し側を実コピーへ落とす。
    """
    if not is_windows():
        raise OSError(errno.ENOTSUP, "block clone is Windows-only")
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    GENERIC_READ = 0x80000000
    GENERIC_WRITE = 0x40000000
    FILE_SHARE_READ = 0x00000001
    CREATE_ALWAYS = 2
    OPEN_EXISTING = 3
    FILE_BEGIN = 0
    FSCTL_DUPLICATE_EXTENTS_TO_FILE = 0x00098344
    ERROR_INVALID_FUNCTION = 1
    ERROR_NOT_SAME_DEVICE = 17
    ERROR_NOT_SUPPORTED = 50
    ERROR_INVALID_PARAMETER = 87
    ERROR_NOT_CAPABLE = 775
    # これらは「この FS / この組み合わせでは block clone できない」の合図。
    UNSUPPORTED = {
        ERROR_INVALID_FUNCTION, ERROR_NOT_SAME_DEVICE, ERROR_NOT_SUPPORTED,
        ERROR_INVALID_PARAMETER, ERROR_NOT_CAPABLE,
    }

    class DUPLICATE_EXTENTS_DATA(ctypes.Structure):
        # 先頭はコピー元のハンドル。パス文字列ではない。
        _fields_ = [
            ("FileHandle", wintypes.HANDLE),
            ("ByteCount", ctypes.c_longlong),
            ("SourceFileOffset", ctypes.c_longlong),
            ("TargetFileOffset", ctypes.c_longlong),
        ]

    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
        wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
    ]
    kernel32.DeviceIoControl.restype = wintypes.BOOL
    kernel32.DeviceIoControl.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
        ctypes.c_void_p, wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p,
    ]
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.SetFilePointerEx.argtypes = [
        wintypes.HANDLE, ctypes.c_longlong,
        ctypes.POINTER(ctypes.c_longlong), wintypes.DWORD,
    ]
    kernel32.SetFilePointerEx.restype = wintypes.BOOL
    kernel32.SetEndOfFile.argtypes = [wintypes.HANDLE]
    kernel32.SetEndOfFile.restype = wintypes.BOOL

    INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

    def _fail(code: int, path: str) -> None:
        message = ctypes.FormatError(code).strip() or f"WinError {code}"
        if code in UNSUPPORTED:
            raise OSError(errno.ENOTSUP, message, path)
        raise OSError(code, message, path)

    def _open(path: str, access: int, disposition: int, share: int) -> int:
        handle = kernel32.CreateFileW(
            path, access, share, None, disposition, 0, None,
        )
        if handle in (0, INVALID_HANDLE_VALUE):
            _fail(ctypes.get_last_error(), path)
        return handle

    src_size = os.path.getsize(src)
    cluster = _windows_cluster_size(dst)
    aligned = src_size - (src_size % cluster)
    if aligned <= 0:
        raise OSError(
            errno.ENOTSUP,
            "file is smaller than one cluster; block clone would copy nothing",
            dst,
        )

    src_handle = -1
    dst_handle = -1
    try:
        src_handle = _open(src, GENERIC_READ, OPEN_EXISTING, FILE_SHARE_READ)
        dst_handle = _open(dst, GENERIC_READ | GENERIC_WRITE, CREATE_ALWAYS, 0)
        # DeviceIoControl はコピー先の実長 >= ByteCount を要求する。
        if not kernel32.SetFilePointerEx(dst_handle, src_size, None, FILE_BEGIN):
            _fail(ctypes.get_last_error(), dst)
        if not kernel32.SetEndOfFile(dst_handle):
            _fail(ctypes.get_last_error(), dst)

        data = DUPLICATE_EXTENTS_DATA()
        data.FileHandle = src_handle
        data.ByteCount = aligned
        data.SourceFileOffset = 0
        data.TargetFileOffset = 0
        returned = wintypes.DWORD(0)
        ok = kernel32.DeviceIoControl(
            dst_handle, FSCTL_DUPLICATE_EXTENTS_TO_FILE,
            ctypes.byref(data), ctypes.sizeof(data),
            None, 0, ctypes.byref(returned), None,
        )
        if not ok:
            _fail(ctypes.get_last_error(), dst)
    finally:
        if src_handle != -1:
            kernel32.CloseHandle(src_handle)
        if dst_handle != -1:
            kernel32.CloseHandle(dst_handle)

    # クラスタ境界からはみ出した末尾だけは素直に書き写す。
    if aligned < src_size:
        with open(src, "rb") as sf, open(dst, "r+b") as df:
            sf.seek(aligned)
            df.seek(aligned)
            df.write(sf.read(src_size - aligned))


def is_windows_junction(path: Path) -> bool:
    """Windows のジャンクション / マウントポイント（ディレクトリの再解析ポイント）か。

    OneDrive のプレースホルダのような「ファイル」の再解析ポイントは対象外。
    それらは通常の読み取りで中身が取り出せるので、コピーすべきファイルである。
    シンボリックリンクは ``is_symlink()`` 側で先に処理する。
    """
    if not is_windows():
        return False
    try:
        info = os.lstat(path)
    except OSError:
        return False
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x00000400)
    if not (getattr(info, "st_file_attributes", 0) & reparse):
        return False
    return stat.S_ISDIR(info.st_mode)


def is_winerror_1314(exc: OSError) -> bool:
    """Windows で symlink 作成権限がない場合のエラー (winerror 1314) か判定。"""
    return is_windows() and getattr(exc, "winerror", None) == 1314


def clear_readonly_and_retry(func, failed_path, _exc_info) -> None:
    """Windows の read-only 属性を外して再試行するヘルパー。"""
    try:
        os.chmod(failed_path, stat.S_IWRITE | stat.S_IREAD)
    except OSError:
        pass
    func(failed_path)


# ========================================================================
# macOS / Linux 固有
# ========================================================================

def is_macos() -> bool:
    return platform.system() == "Darwin"


def is_linux() -> bool:
    return platform.system() == "Linux"


def macos_clonefile(src: str, dst: str) -> None:
    """macOS の clonefile(2)。失敗時は OSError を送出する。"""
    libc = ctypes.CDLL(None, use_errno=True)
    rc = libc.clonefile(src.encode(), dst.encode(), 0)
    if rc != 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code), src)


def linux_ficlone(src: str, dst: str) -> None:
    """Linux の FICLONE ioctl。失敗時は OSError を送出する。"""
    import fcntl

    src_fd = os.open(src, os.O_RDONLY)
    try:
        dst_fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
        try:
            fcntl.ioctl(dst_fd, 0x40049409, src_fd)  # FICLONE
        finally:
            os.close(dst_fd)
    finally:
        os.close(src_fd)


# ========================================================================
# 共通: CoW バックエンド検出
# ========================================================================

from dataclasses import dataclass
from enum import Enum
from typing import Callable, Dict, List, Optional, Sequence, Tuple

# 既存の Capability, BackendInfo 等をインポートせず、ここで定義することで循環 import を避ける
# 実際の使用側では元の定義を使う


def detect_cow_backend(root: Path) -> Optional[str]:
    """
    利用可能な CoW バックエンド名を返す。
    優先順: fast_clone (Windows) > reflink (macOS/Linux) > copy
    """
    import tempfile
    
    # Windows block clone
    if is_windows():
        with tempfile.TemporaryDirectory(prefix="dfs_fs_clone_", dir=str(root)) as probe:
            probe_dir = Path(probe)
            src = probe_dir / "probe_src"
            dst = probe_dir / "probe_dst"
            payload = b"\x00" * (1024 * 1024)
            src.write_bytes(payload)
            try:
                _windows_block_clone(str(src), str(dst))
                if dst.exists() and dst.stat().st_size == len(payload):
                    if dst.read_bytes() == payload:
                        return "fast_clone"
            except Exception:
                pass
    
    # macOS clonefile / Linux FICLONE
    if is_macos() or is_linux():
        with tempfile.TemporaryDirectory(prefix="dfs_fs_probe_", dir=str(root)) as probe:
            probe_dir = Path(probe)
            src = probe_dir / "probe_src"
            dst = probe_dir / "probe_dst"
            src.write_bytes(b"dfs")
            try:
                if is_macos():
                    macos_clonefile(str(src), str(dst))
                    return "reflink"
                if is_linux():
                    linux_ficlone(str(src), str(dst))
                    return "reflink"
            except OSError:
                pass
            except Exception:
                pass
    
    return None


def get_fallback_copier() -> Callable[[str, str], None]:
    """実コピーを返す。"""
    import shutil
    return lambda src, dst: shutil.copy2(src, dst, follow_symlinks=False)


# ========================================================================
# パス安全性 (path_safety から移動予定)
# ========================================================================

class UnsafePathError(Exception):
    """安全でないパス操作が検出された。"""
    pass


def safe_target(root: Path, rel: str, create_parents: bool = False) -> Path:
    """root 直下の安全なパスを返す。トラバーサル攻撃を防ぐ。"""
    if not rel or rel in (".", ".."):
        raise UnsafePathError(f"Invalid relative path: {rel!r}")
    if "/" in rel or "\\" in rel or ":" in rel or "\x00" in rel:
        raise UnsafePathError(f"Invalid path entry name: {rel!r}")
    
    root = Path(root).resolve()
    target = (root / rel).resolve()
    
    try:
        target.relative_to(root)
    except ValueError:
        raise UnsafePathError(f"Path traversal attempt: {rel!r}")
    
    if create_parents:
        target.parent.mkdir(parents=True, exist_ok=True)
    
    return target


def copyfile_no_follow(src: Path, dst: Path) -> None:
    """symlink を辿らずにコピーする。"""
    import shutil
    if src.is_symlink():
        raise UnsafePathError(f"Refusing to copy symlink: {src}")
    shutil.copy2(src, dst, follow_symlinks=False)


# ========================================================================
# 削除ユーティリティ
# ========================================================================

def remove_tree(path: Path | str) -> None:
    """ディレクトリを消す。Windows の read-only 属性は外してから消す。"""
    target = Path(path)

    if is_windows():
        def _clear_and_retry(func, failed_path, _exc_info) -> None:
            try:
                os.chmod(failed_path, stat.S_IWRITE | stat.S_IREAD)
            except OSError:
                pass
            func(failed_path)

        if sys.version_info >= (3, 12):
            shutil.rmtree(target, onexc=lambda f, p, e: _clear_and_retry(f, p, e))
        else:
            shutil.rmtree(target, onerror=_clear_and_retry)
    else:
        shutil.rmtree(target)


# ========================================================================
# バックエンド基底クラス (fs.core から移動予定)
# ========================================================================

class Capability(str, Enum):
    """バックエンドが持つ能力。"""
    COPY = "copy"
    REFLINK = "reflink"
    FAST_CLONE = "fast_clone"


@dataclass(frozen=True)
class BackendInfo:
    name: str
    capability: Capability
    detail: str
    available: bool


class Backend:
    name = "backend"
    capability = Capability.COPY

    def copy_file(self, src: Path, dst: Path) -> int:
        raise NotImplementedError

    def copy_tree(self, src: Path, dst: Path, ignore: Sequence[str] = ()) -> Tuple[int, int]:
        raise NotImplementedError


class CopyBackend(Backend):
    name = "copy"
    capability = Capability.COPY

    def copy_file(self, src: Path, dst: Path) -> int:
        import shutil
        shutil.copy2(src, dst, follow_symlinks=False)
        return dst.stat().st_size

    def copy_tree(self, src: Path, dst: Path, ignore: Sequence[str] = ()) -> Tuple[int, int]:
        files = 0
        total = 0
        dst.mkdir(parents=True, exist_ok=True)
        for entry in sorted(src.iterdir()):
            rel_name = entry.name
            if rel_name in DEFAULT_IGNORE_NAMES or rel_name.startswith(DEFAULT_IGNORE_PREFIXES):
                continue
            if _ignored(rel_name, ignore):
                continue
            target = dst / rel_name
            if entry.is_symlink():
                _recreate_symlink(entry, target)
            elif is_windows_junction(entry):
                raise OSError(errno.ENOTSUP, f"unsupported reparse point: {entry}")
            elif entry.is_dir():
                sub_files, sub_bytes = self.copy_tree(entry, target, ignore)
                files += sub_files
                total += sub_bytes
            elif entry.is_file():
                total += self.copy_file(entry, target)
                files += 1
            else:
                raise OSError(errno.ENOTSUP, f"unsupported file type: {entry}")
        try:
            shutil.copystat(src, dst, follow_symlinks=False)
        except OSError:
            pass
        return files, total


class ReflinkBackend(Backend):
    name = "reflink"
    capability = Capability.REFLINK

    def __init__(self, copier: Callable[[str, str], None], detail: str):
        self._copier = copier
        self.detail = detail

    def copy_file(self, src: Path, dst: Path) -> int:
        if dst.is_symlink() or dst.exists():
            dst.unlink()
        self._copier(str(src), str(dst))
        try:
            shutil.copystat(src, dst, follow_symlinks=False)
        except OSError:
            pass
        return dst.stat().st_size

    def copy_tree(self, src: Path, dst: Path, ignore: Sequence[str] = ()) -> Tuple[int, int]:
        files = 0
        total = 0
        dst.mkdir(parents=True, exist_ok=True)
        for entry in sorted(src.iterdir()):
            rel_name = entry.name
            if rel_name in DEFAULT_IGNORE_NAMES or rel_name.startswith(DEFAULT_IGNORE_PREFIXES):
                continue
            if _ignored(rel_name, ignore):
                continue
            target = dst / rel_name
            if entry.is_symlink():
                _recreate_symlink(entry, target)
            elif is_windows_junction(entry):
                raise OSError(errno.ENOTSUP, f"unsupported reparse point: {entry}")
            elif entry.is_dir():
                sub_files, sub_bytes = self.copy_tree(entry, target, ignore)
                files += sub_files
                total += sub_bytes
            elif entry.is_file():
                try:
                    total += self.copy_file(entry, target)
                except OSError as exc:
                    if exc.errno in (errno.EINVAL, errno.ENOTSUP, errno.EXDEV, errno.EOPNOTSUPP):
                        total += CopyBackend().copy_file(entry, target)
                    else:
                        raise
                files += 1
            else:
                raise OSError(errno.ENOTSUP, f"unsupported file type: {entry}")
        try:
            shutil.copystat(src, dst, follow_symlinks=False)
        except OSError:
            pass
        return files, total


class FastCloneBackend(Backend):
    name = "fast_clone"
    capability = Capability.FAST_CLONE

    def __init__(self, detail: str = "reserved"):
        self.detail = detail
        self._inner = ReflinkBackend(_windows_block_clone, detail)

    def copy_file(self, src: Path, dst: Path) -> int:
        return self._inner.copy_file(src, dst)

    def copy_tree(self, src: Path, dst: Path, ignore: Sequence[str] = ()) -> Tuple[int, int]:
        return self._inner.copy_tree(src, dst, ignore)


def _ignored(name: str, patterns: Sequence[str]) -> bool:
    if not patterns:
        return False
    import fnmatch
    return any(fnmatch.fnmatch(name, pat) for pat in patterns)


def _recreate_symlink(src: Path, dst: Path) -> None:
    target = os.readlink(src)
    if dst.is_symlink() or dst.exists():
        dst.unlink()
    os.symlink(target, dst)


# Re-export from original fs.core
import re

SNAPSHOT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")

def _validate_snapshot_id(snap_id: str) -> str:
    """スナップショット ID を単一の安全なパス要素に限定する。"""
    if (
        not isinstance(snap_id, str) or not SNAPSHOT_ID_RE.fullmatch(snap_id)
    ):
        raise ValueError(f"Invalid snapshot ID: {snap_id!r}")
    if snap_id in (".", ".."):
        raise ValueError(f"Invalid snapshot ID: {snap_id!r}")
    return snap_id
