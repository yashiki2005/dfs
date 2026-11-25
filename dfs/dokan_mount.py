#!/usr/bin/env python3
"""Windows 用 Dokany2 (``dokan2.dll``) ネイティブマウント実装。

``ctypes`` のみで ``dokan2.dll`` の ``DokanMain`` / ``DOKAN_OPERATIONS`` を
直接呼び出し、追加の Python 依存パッケージなしで ``dfs mount`` を提供する。
非 Windows 環境でもインポート・単体テストが可能。
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wintypes
import os
import shutil
import stat
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from .path_safety import UnsafePathError, safe_target

# Dokany 2.x 定数 (dokan/dokan.h)
DOKAN_VERSION_DEFAULT = 200
VOLUME_SECURITY_DESCRIPTOR_MAX_SIZE = 16384

DOKAN_OPTION_DEBUG = 1
DOKAN_OPTION_STDERR = 1 << 1
DOKAN_OPTION_WRITE_PROTECT = 1 << 3
DOKAN_OPTION_MOUNT_MANAGER = 1 << 6
DOKAN_OPTION_CURRENT_SESSION = 1 << 7

DOKAN_SUCCESS = 0

# NTSTATUS 定数
STATUS_SUCCESS = 0x00000000
STATUS_NOT_IMPLEMENTED = 0xC0000002
STATUS_INVALID_PARAMETER = 0xC000000D
STATUS_NO_SUCH_FILE = 0xC000000F
STATUS_END_OF_FILE = 0xC0000011
STATUS_ACCESS_DENIED = 0xC0000022
STATUS_OBJECT_NAME_INVALID = 0xC0000033
STATUS_OBJECT_NAME_NOT_FOUND = 0xC0000034
STATUS_OBJECT_NAME_COLLISION = 0xC0000035
STATUS_OBJECT_PATH_INVALID = 0xC0000039
STATUS_OBJECT_PATH_NOT_FOUND = 0xC000003A
STATUS_MEDIA_WRITE_PROTECTED = 0xC00000A2
STATUS_DIRECTORY_NOT_EMPTY = 0xC0000101
STATUS_NOT_A_DIRECTORY = 0xC0000103
STATUS_FILE_IS_A_DIRECTORY = 0xC00000BA
STATUS_INTERNAL_ERROR = 0xC00000E5

# CreateDisposition
FILE_SUPERSEDE = 0
FILE_OPEN = 1
FILE_CREATE = 2
FILE_OPEN_IF = 3
FILE_OVERWRITE = 4
FILE_OVERWRITE_IF = 5

# CreateOptions
FILE_DIRECTORY_FILE = 0x00000001
FILE_NON_DIRECTORY_FILE = 0x00000040
FILE_DELETE_ON_CLOSE = 0x00001000

# FileAttributes
FILE_ATTRIBUTE_READONLY = 0x00000001
FILE_ATTRIBUTE_DIRECTORY = 0x00000010
FILE_ATTRIBUTE_NORMAL = 0x00000080

# FileSystemFlags
FILE_CASE_SENSITIVE_SEARCH = 0x00000001
FILE_CASE_PRESERVED_NAMES = 0x00000002
FILE_UNICODE_ON_DISK = 0x00000004

_WIN32_EPOCH_DIFF_SECONDS = 11644473600
_O_BINARY = getattr(os, "O_BINARY", 0)
_CALLBACK_FACTORY = getattr(ctypes, "WINFUNCTYPE", ctypes.CFUNCTYPE)
_ULONG64 = ctypes.c_uint64
_LONGLONG = ctypes.c_int64
_PULONGLONG = ctypes.POINTER(_ULONG64)
_PULONG = ctypes.POINTER(wintypes.ULONG)
_LPDWORD = ctypes.POINTER(wintypes.DWORD)
_NTSTATUS = ctypes.c_long
_UCHAR = ctypes.c_ubyte
_PVOID = ctypes.c_void_p


class DOKAN_OPTIONS(ctypes.Structure):
    _fields_ = [
        ("Version", wintypes.USHORT),
        ("SingleThread", wintypes.BOOLEAN),
        ("Options", wintypes.ULONG),
        ("GlobalContext", _ULONG64),
        ("MountPoint", wintypes.LPCWSTR),
        ("UNCName", wintypes.LPCWSTR),
        ("Timeout", wintypes.ULONG),
        ("AllocationUnitSize", wintypes.ULONG),
        ("SectorSize", wintypes.ULONG),
        ("VolumeSecurityDescriptorLength", wintypes.ULONG),
        ("VolumeSecurityDescriptor", ctypes.c_char * VOLUME_SECURITY_DESCRIPTOR_MAX_SIZE),
    ]


class DOKAN_FILE_INFO(ctypes.Structure):
    _fields_ = [
        ("Context", _ULONG64),
        ("DokanContext", _ULONG64),
        ("DokanOptions", ctypes.POINTER(DOKAN_OPTIONS)),
        ("ProcessingContext", _PVOID),
        ("ProcessId", wintypes.ULONG),
        ("IsDirectory", _UCHAR),
        ("DeleteOnClose", _UCHAR),
        ("PagingIo", _UCHAR),
        ("SynchronousIo", _UCHAR),
        ("Nocache", _UCHAR),
        ("WriteToEndOfFile", _UCHAR),
    ]


class BY_HANDLE_FILE_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("dwFileAttributes", wintypes.DWORD),
        ("ftCreationTime", wintypes.FILETIME),
        ("ftLastAccessTime", wintypes.FILETIME),
        ("ftLastWriteTime", wintypes.FILETIME),
        ("dwVolumeSerialNumber", wintypes.DWORD),
        ("nFileSizeHigh", wintypes.DWORD),
        ("nFileSizeLow", wintypes.DWORD),
        ("nNumberOfLinks", wintypes.DWORD),
        ("nFileIndexHigh", wintypes.DWORD),
        ("nFileIndexLow", wintypes.DWORD),
    ]


class WIN32_FIND_DATAW(ctypes.Structure):
    _fields_ = [
        ("dwFileAttributes", wintypes.DWORD),
        ("ftCreationTime", wintypes.FILETIME),
        ("ftLastAccessTime", wintypes.FILETIME),
        ("ftLastWriteTime", wintypes.FILETIME),
        ("nFileSizeHigh", wintypes.DWORD),
        ("nFileSizeLow", wintypes.DWORD),
        ("dwReserved0", wintypes.DWORD),
        ("dwReserved1", wintypes.DWORD),
        ("cFileName", wintypes.WCHAR * 260),
        ("cAlternateFileName", wintypes.WCHAR * 14),
    ]


_PDOKAN_FILE_INFO = ctypes.POINTER(DOKAN_FILE_INFO)
_PFILL_FIND_DATA = _CALLBACK_FACTORY(
    ctypes.c_int, ctypes.POINTER(WIN32_FIND_DATAW), _PDOKAN_FILE_INFO
)

_ZW_CREATE_FILE_CB = _CALLBACK_FACTORY(
    _NTSTATUS,
    wintypes.LPCWSTR,
    _PVOID,
    wintypes.DWORD,
    wintypes.ULONG,
    wintypes.ULONG,
    wintypes.ULONG,
    wintypes.ULONG,
    _PDOKAN_FILE_INFO,
)
_CLEANUP_CB = _CALLBACK_FACTORY(None, wintypes.LPCWSTR, _PDOKAN_FILE_INFO)
_CLOSE_FILE_CB = _CALLBACK_FACTORY(None, wintypes.LPCWSTR, _PDOKAN_FILE_INFO)
_READ_FILE_CB = _CALLBACK_FACTORY(
    _NTSTATUS,
    wintypes.LPCWSTR,
    _PVOID,
    wintypes.DWORD,
    _LPDWORD,
    _LONGLONG,
    _PDOKAN_FILE_INFO,
)
_WRITE_FILE_CB = _CALLBACK_FACTORY(
    _NTSTATUS,
    wintypes.LPCWSTR,
    _PVOID,
    wintypes.DWORD,
    _LPDWORD,
    _LONGLONG,
    _PDOKAN_FILE_INFO,
)
_FLUSH_FILE_BUFFERS_CB = _CALLBACK_FACTORY(_NTSTATUS, wintypes.LPCWSTR, _PDOKAN_FILE_INFO)
_GET_FILE_INFO_CB = _CALLBACK_FACTORY(
    _NTSTATUS,
    wintypes.LPCWSTR,
    ctypes.POINTER(BY_HANDLE_FILE_INFORMATION),
    _PDOKAN_FILE_INFO,
)
_FIND_FILES_CB = _CALLBACK_FACTORY(
    _NTSTATUS, wintypes.LPCWSTR, _PFILL_FIND_DATA, _PDOKAN_FILE_INFO
)
_FIND_FILES_WITH_PATTERN_CB = _CALLBACK_FACTORY(
    _NTSTATUS, wintypes.LPCWSTR, wintypes.LPCWSTR, _PFILL_FIND_DATA, _PDOKAN_FILE_INFO
)
_SET_FILE_ATTRS_CB = _CALLBACK_FACTORY(
    _NTSTATUS, wintypes.LPCWSTR, wintypes.DWORD, _PDOKAN_FILE_INFO
)
_SET_FILE_TIME_CB = _CALLBACK_FACTORY(
    _NTSTATUS,
    wintypes.LPCWSTR,
    ctypes.POINTER(wintypes.FILETIME),
    ctypes.POINTER(wintypes.FILETIME),
    ctypes.POINTER(wintypes.FILETIME),
    _PDOKAN_FILE_INFO,
)
_DELETE_FILE_CB = _CALLBACK_FACTORY(_NTSTATUS, wintypes.LPCWSTR, _PDOKAN_FILE_INFO)
_DELETE_DIR_CB = _CALLBACK_FACTORY(_NTSTATUS, wintypes.LPCWSTR, _PDOKAN_FILE_INFO)
_MOVE_FILE_CB = _CALLBACK_FACTORY(
    _NTSTATUS, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.BOOL, _PDOKAN_FILE_INFO
)
_SET_END_OF_FILE_CB = _CALLBACK_FACTORY(
    _NTSTATUS, wintypes.LPCWSTR, _LONGLONG, _PDOKAN_FILE_INFO
)
_SET_ALLOC_SIZE_CB = _CALLBACK_FACTORY(
    _NTSTATUS, wintypes.LPCWSTR, _LONGLONG, _PDOKAN_FILE_INFO
)
_LOCK_FILE_CB = _CALLBACK_FACTORY(
    _NTSTATUS, wintypes.LPCWSTR, _LONGLONG, _LONGLONG, _PDOKAN_FILE_INFO
)
_UNLOCK_FILE_CB = _CALLBACK_FACTORY(
    _NTSTATUS, wintypes.LPCWSTR, _LONGLONG, _LONGLONG, _PDOKAN_FILE_INFO
)
_GET_DISK_FREE_SPACE_CB = _CALLBACK_FACTORY(
    _NTSTATUS, _PULONGLONG, _PULONGLONG, _PULONGLONG, _PDOKAN_FILE_INFO
)
_GET_VOLUME_INFO_CB = _CALLBACK_FACTORY(
    _NTSTATUS,
    wintypes.LPWSTR,
    wintypes.DWORD,
    _LPDWORD,
    _LPDWORD,
    _LPDWORD,
    wintypes.LPWSTR,
    wintypes.DWORD,
    _PDOKAN_FILE_INFO,
)
_MOUNTED_CB = _CALLBACK_FACTORY(_NTSTATUS, wintypes.LPCWSTR, _PDOKAN_FILE_INFO)
_UNMOUNTED_CB = _CALLBACK_FACTORY(_NTSTATUS, _PDOKAN_FILE_INFO)
_GET_FILE_SECURITY_CB = _CALLBACK_FACTORY(
    _NTSTATUS,
    wintypes.LPCWSTR,
    _PVOID,
    _PVOID,
    wintypes.ULONG,
    _PULONG,
    _PDOKAN_FILE_INFO,
)
_SET_FILE_SECURITY_CB = _CALLBACK_FACTORY(
    _NTSTATUS,
    wintypes.LPCWSTR,
    _PVOID,
    _PVOID,
    wintypes.ULONG,
    _PDOKAN_FILE_INFO,
)
_FIND_STREAMS_CB = _CALLBACK_FACTORY(
    _NTSTATUS, wintypes.LPCWSTR, _PVOID, _PVOID, _PDOKAN_FILE_INFO
)


class DOKAN_OPERATIONS(ctypes.Structure):
    _fields_ = [
        ("ZwCreateFile", _ZW_CREATE_FILE_CB),
        ("Cleanup", _CLEANUP_CB),
        ("CloseFile", _CLOSE_FILE_CB),
        ("ReadFile", _READ_FILE_CB),
        ("WriteFile", _WRITE_FILE_CB),
        ("FlushFileBuffers", _FLUSH_FILE_BUFFERS_CB),
        ("GetFileInformation", _GET_FILE_INFO_CB),
        ("FindFiles", _FIND_FILES_CB),
        ("FindFilesWithPattern", _FIND_FILES_WITH_PATTERN_CB),
        ("SetFileAttributes", _SET_FILE_ATTRS_CB),
        ("SetFileTime", _SET_FILE_TIME_CB),
        ("DeleteFile", _DELETE_FILE_CB),
        ("DeleteDirectory", _DELETE_DIR_CB),
        ("MoveFile", _MOVE_FILE_CB),
        ("SetEndOfFile", _SET_END_OF_FILE_CB),
        ("SetAllocationSize", _SET_ALLOC_SIZE_CB),
        ("LockFile", _LOCK_FILE_CB),
        ("UnlockFile", _UNLOCK_FILE_CB),
        ("GetDiskFreeSpace", _GET_DISK_FREE_SPACE_CB),
        ("GetVolumeInformation", _GET_VOLUME_INFO_CB),
        ("Mounted", _MOUNTED_CB),
        ("Unmounted", _UNMOUNTED_CB),
        ("GetFileSecurity", _GET_FILE_SECURITY_CB),
        ("SetFileSecurity", _SET_FILE_SECURITY_CB),
        ("FindStreams", _FIND_STREAMS_CB),
    ]


def is_windows_drive_mountpoint(mountpoint: str | Path) -> bool:
    """``Z:`` または ``Z:\\`` 形式のドライブレター指定かどうかを返す。"""
    raw = str(mountpoint or "").strip()
    if len(raw) == 2 and raw[0].isalpha() and raw[1] == ":":
        return True
    if len(raw) == 3 and raw[0].isalpha() and raw[1] == ":" and raw[2] in ("\\", "/"):
        return True
    return False


def find_dokan_library(explicit: Optional[str] = None) -> Optional[Path]:
    """利用可能な Dokany2 (``dokan2.dll``) のパスを返す。"""
    import ctypes.util

    for raw in (explicit, os.environ.get("DFS_DOKAN_LIBRARY")):
        if raw:
            p = Path(raw).expanduser()
            if p.is_file():
                return p
            return None

    found = ctypes.util.find_library("dokan2")
    if found:
        return Path(found)

    candidates = []
    for env_key in ("ProgramFiles", "ProgramFiles(x86)", "SystemRoot"):
        base = os.environ.get(env_key)
        if not base:
            continue
        base_path = Path(base)
        if env_key == "SystemRoot":
            candidates.append(base_path / "System32" / "dokan2.dll")
        else:
            dokan_dir = base_path / "Dokan"
            if dokan_dir.is_dir():
                candidates.extend(sorted(dokan_dir.glob("DokanLibrary-2*/dokan2.dll"), reverse=True))
                candidates.extend(sorted(dokan_dir.glob("DokanLibrary*/dokan2.dll"), reverse=True))
    for cand in candidates:
        if cand.is_file():
            return cand
    return None


def _unix_ts_to_filetime(ts: float) -> wintypes.FILETIME:
    ticks = max(0, int((float(ts) + _WIN32_EPOCH_DIFF_SECONDS) * 10_000_000))
    return wintypes.FILETIME(ticks & 0xFFFFFFFF, (ticks >> 32) & 0xFFFFFFFF)


def _filetime_to_unix_ts(ft: wintypes.FILETIME) -> Optional[float]:
    ticks = (int(ft.dwHighDateTime) << 32) | int(ft.dwLowDateTime)
    if ticks <= 0:
        return None
    return (ticks / 10_000_000.0) - _WIN32_EPOCH_DIFF_SECONDS


def _to_signed_ntstatus(val: int) -> int:
    val = int(val) & 0xFFFFFFFF
    return val - 0x100000000 if val >= 0x80000000 else val


class LocalTreeDokan:
    """ローカル作業ツリーを Dokany2 コールバックへ公開するアダプタ。"""

    def __init__(
        self,
        root: Path | str,
        flush_callback: Callable[[], None],
        *,
        volname: str = "dfs",
        read_only: bool = False,
        sync_delay: float = 0.5,
    ) -> None:
        self.root = Path(root).resolve()
        self.flush_callback = flush_callback
        self.volname = volname or "dfs"
        self.read_only = bool(read_only)
        self.sync_delay = max(0.0, float(sync_delay))
        self._lock = threading.RLock()
        self._flush_lock = threading.Lock()
        self._dirty = False
        self._timer: Optional[threading.Timer] = None
        self._fds: Dict[int, int] = {}
        self._next_fh = 1
        self._callbacks: list[Any] = []

    def _rel_path(self, win_path: Optional[str]) -> str:
        raw = str(win_path or "\\").replace("\\", "/").lstrip("/")
        return raw

    def _resolve(self, win_path: Optional[str]) -> Path:
        rel = self._rel_path(win_path)
        if not rel:
            return self.root
        if rel == ".clayfs" or rel.startswith(".clayfs/"):
            raise OSError(os.errno.EACCES if hasattr(os, "errno") else 13, "reserved")
        return safe_target(self.root, rel)

    def _mark_dirty(self) -> None:
        self._dirty = True

    def _take_dirty_locked(self) -> bool:
        if not self._dirty or self.read_only:
            return False
        self._dirty = False
        return True

    def _run_flush_callback(self) -> None:
        with self._flush_lock:
            try:
                self.flush_callback()
            except Exception:
                with self._lock:
                    self._dirty = True
                raise

    def _timer_flush(self) -> None:
        with self._lock:
            self._timer = None
            should_flush = self._take_dirty_locked()
        if not should_flush:
            return
        try:
            self._run_flush_callback()
        except Exception as e:  # noqa: BLE001
            print(f"[dfscli] dokan flush failed: {e}", file=sys.stderr)

    def _schedule_flush(self) -> None:
        with self._lock:
            if not self._dirty or self.read_only:
                return
            if self.sync_delay <= 0:
                should_flush = self._take_dirty_locked()
            else:
                if self._timer is not None:
                    self._timer.cancel()
                self._timer = threading.Timer(self.sync_delay, self._timer_flush)
                self._timer.daemon = True
                self._timer.start()
                return
        if should_flush:
            self._run_flush_callback()

    def _alloc_fh(self, fd: int) -> int:
        fh = self._next_fh
        self._next_fh += 1
        self._fds[fh] = fd
        return fh

    def _close_fh(self, info_ptr: Any) -> None:
        if not info_ptr:
            return
        fh = int(info_ptr.contents.Context)
        if fh:
            fd = self._fds.pop(fh, None)
            info_ptr.contents.Context = 0
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass

    def close_all(self) -> None:
        with self._lock:
            if self._timer is not None:
                self._timer.cancel()
                self._timer = None
            for fd in self._fds.values():
                try:
                    os.close(fd)
                except OSError:
                    pass
            self._fds.clear()
            should_flush = self._take_dirty_locked()
        if should_flush:
            self._run_flush_callback()

    # --- コールバック本体 ---

    def zw_create_file(
        self,
        file_name: Optional[str],
        _security_ctx: Any,
        _desired_access: int,
        _file_attrs: int,
        _share_access: int,
        create_disposition: int,
        create_options: int,
        info_ptr: Any,
    ) -> int:
        try:
            target = self._resolve(file_name)
        except (UnsafePathError, OSError):
            return _to_signed_ntstatus(STATUS_OBJECT_PATH_INVALID)

        want_dir = bool(create_options & FILE_DIRECTORY_FILE)
        want_file = bool(create_options & FILE_NON_DIRECTORY_FILE)
        delete_on_close = bool(create_options & FILE_DELETE_ON_CLOSE)
        if delete_on_close and self.read_only:
            return _to_signed_ntstatus(STATUS_MEDIA_WRITE_PROTECTED)

        with self._lock:
            exists = target.exists()
            is_dir = target.is_dir() if exists else False
            if exists and target.is_symlink():
                return _to_signed_ntstatus(STATUS_ACCESS_DENIED)

            if exists:
                if want_dir and not is_dir:
                    return _to_signed_ntstatus(STATUS_NOT_A_DIRECTORY)
                if want_file and is_dir:
                    return _to_signed_ntstatus(STATUS_FILE_IS_A_DIRECTORY)
                if create_disposition == FILE_CREATE:
                    return _to_signed_ntstatus(STATUS_OBJECT_NAME_COLLISION)
                if is_dir:
                    if info_ptr:
                        info_ptr.contents.IsDirectory = 1
                        if delete_on_close:
                            info_ptr.contents.DeleteOnClose = 1
                    return _to_signed_ntstatus(STATUS_SUCCESS)

                overwrite = create_disposition in (FILE_SUPERSEDE, FILE_OVERWRITE, FILE_OVERWRITE_IF)
                if overwrite and self.read_only:
                    return _to_signed_ntstatus(STATUS_MEDIA_WRITE_PROTECTED)
                flags = (os.O_RDONLY if self.read_only else os.O_RDWR) | _O_BINARY
                if overwrite:
                    flags |= os.O_TRUNC
                try:
                    fd = os.open(target, flags)
                except OSError:
                    return _to_signed_ntstatus(STATUS_ACCESS_DENIED)
                if overwrite:
                    self._mark_dirty()
                fh = self._alloc_fh(fd)
                if info_ptr:
                    info_ptr.contents.Context = fh
                    info_ptr.contents.IsDirectory = 0
                    if delete_on_close:
                        info_ptr.contents.DeleteOnClose = 1
                if create_disposition in (FILE_OPEN_IF, FILE_OVERWRITE_IF):
                    return _to_signed_ntstatus(STATUS_OBJECT_NAME_COLLISION)
                return _to_signed_ntstatus(STATUS_SUCCESS)

            # 存在しない場合
            if create_disposition in (FILE_OPEN, FILE_OVERWRITE):
                return _to_signed_ntstatus(STATUS_OBJECT_NAME_NOT_FOUND)
            if self.read_only:
                return _to_signed_ntstatus(STATUS_MEDIA_WRITE_PROTECTED)
            if not target.parent.exists():
                return _to_signed_ntstatus(STATUS_OBJECT_PATH_NOT_FOUND)
            if want_dir:
                try:
                    target.mkdir(parents=False, exist_ok=False)
                except OSError:
                    return _to_signed_ntstatus(STATUS_ACCESS_DENIED)
                self._mark_dirty()
                if info_ptr:
                    info_ptr.contents.IsDirectory = 1
                    if delete_on_close:
                        info_ptr.contents.DeleteOnClose = 1
                return _to_signed_ntstatus(STATUS_SUCCESS)

            try:
                fd = os.open(target, os.O_CREAT | os.O_RDWR | os.O_EXCL | _O_BINARY, 0o644)
            except FileExistsError:
                return _to_signed_ntstatus(STATUS_OBJECT_NAME_COLLISION)
            except OSError:
                return _to_signed_ntstatus(STATUS_ACCESS_DENIED)
            self._mark_dirty()
            fh = self._alloc_fh(fd)
            if info_ptr:
                info_ptr.contents.Context = fh
                info_ptr.contents.IsDirectory = 0
                if delete_on_close:
                    info_ptr.contents.DeleteOnClose = 1
            return _to_signed_ntstatus(STATUS_SUCCESS)

    def cleanup(self, file_name: Optional[str], info_ptr: Any) -> None:
        deleted = False
        with self._lock:
            self._close_fh(info_ptr)
            if info_ptr and info_ptr.contents.DeleteOnClose and not self.read_only:
                try:
                    target = self._resolve(file_name)
                    if target != self.root and target.exists() and not target.is_symlink():
                        if target.is_dir():
                            target.rmdir()
                        else:
                            target.unlink()
                        self._mark_dirty()
                        deleted = True
                except OSError:
                    pass
        if deleted or self._dirty:
            self._schedule_flush()

    def close_file(self, _file_name: Optional[str], info_ptr: Any) -> None:
        with self._lock:
            self._close_fh(info_ptr)

    def read_file(
        self,
        file_name: Optional[str],
        buf_ptr: int,
        buf_len: int,
        read_len_ptr: Any,
        offset: int,
        info_ptr: Any,
    ) -> int:
        with self._lock:
            fh = int(info_ptr.contents.Context) if info_ptr else 0
            fd = self._fds.get(fh)
            temp_fd: Optional[int] = None
            if fd is None:
                try:
                    target = self._resolve(file_name)
                    temp_fd = os.open(target, os.O_RDONLY | _O_BINARY)
                    fd = temp_fd
                except (UnsafePathError, OSError):
                    return _to_signed_ntstatus(STATUS_OBJECT_NAME_NOT_FOUND)
            try:
                if hasattr(os, "pread"):
                    data = os.pread(fd, int(buf_len), max(0, int(offset)))
                else:
                    os.lseek(fd, max(0, int(offset)), os.SEEK_SET)
                    data = os.read(fd, int(buf_len))
            except OSError:
                return _to_signed_ntstatus(STATUS_INTERNAL_ERROR)
            finally:
                if temp_fd is not None:
                    try:
                        os.close(temp_fd)
                    except OSError:
                        pass
            if data and buf_ptr:
                ctypes.memmove(buf_ptr, data, len(data))
            if read_len_ptr:
                read_len_ptr[0] = len(data)
            return _to_signed_ntstatus(STATUS_SUCCESS)

    def write_file(
        self,
        file_name: Optional[str],
        buf_ptr: int,
        num_bytes: int,
        written_ptr: Any,
        offset: int,
        info_ptr: Any,
    ) -> int:
        if self.read_only:
            return _to_signed_ntstatus(STATUS_MEDIA_WRITE_PROTECTED)
        data = ctypes.string_at(buf_ptr, int(num_bytes)) if num_bytes > 0 and buf_ptr else b""
        with self._lock:
            fh = int(info_ptr.contents.Context) if info_ptr else 0
            fd = self._fds.get(fh)
            temp_fd: Optional[int] = None
            if fd is None:
                try:
                    target = self._resolve(file_name)
                    temp_fd = os.open(target, os.O_RDWR | _O_BINARY)
                    fd = temp_fd
                except (UnsafePathError, OSError):
                    return _to_signed_ntstatus(STATUS_OBJECT_NAME_NOT_FOUND)
            try:
                if info_ptr and info_ptr.contents.WriteToEndOfFile:
                    os.lseek(fd, 0, os.SEEK_END)
                    wrote = os.write(fd, data)
                elif hasattr(os, "pwrite"):
                    wrote = os.pwrite(fd, data, max(0, int(offset)))
                else:
                    os.lseek(fd, max(0, int(offset)), os.SEEK_SET)
                    wrote = os.write(fd, data)
                self._mark_dirty()
            except OSError:
                return _to_signed_ntstatus(STATUS_INTERNAL_ERROR)
            finally:
                if temp_fd is not None:
                    try:
                        os.close(temp_fd)
                    except OSError:
                        pass
            if written_ptr:
                written_ptr[0] = wrote
            return _to_signed_ntstatus(STATUS_SUCCESS)

    def flush_file_buffers(self, _file_name: Optional[str], info_ptr: Any) -> int:
        with self._lock:
            fh = int(info_ptr.contents.Context) if info_ptr else 0
            fd = self._fds.get(fh)
            if fd is not None:
                try:
                    os.fsync(fd)
                except OSError:
                    pass
        self._schedule_flush()
        return _to_signed_ntstatus(STATUS_SUCCESS)

    def get_file_information(
        self, file_name: Optional[str], buf_ptr: Any, _info_ptr: Any
    ) -> int:
        try:
            target = self._resolve(file_name)
            st = os.lstat(target)
        except (UnsafePathError, FileNotFoundError, OSError):
            return _to_signed_ntstatus(STATUS_OBJECT_NAME_NOT_FOUND)
        if stat.S_ISLNK(st.st_mode):
            return _to_signed_ntstatus(STATUS_OBJECT_NAME_NOT_FOUND)
        is_dir = stat.S_ISDIR(st.st_mode)
        attrs = FILE_ATTRIBUTE_DIRECTORY if is_dir else FILE_ATTRIBUTE_NORMAL
        if self.read_only:
            attrs |= FILE_ATTRIBUTE_READONLY
        size = 0 if is_dir else int(st.st_size)
        ctime = getattr(st, "st_birthtime", st.st_ctime)
        info = buf_ptr.contents
        info.dwFileAttributes = attrs
        info.ftCreationTime = _unix_ts_to_filetime(ctime)
        info.ftLastAccessTime = _unix_ts_to_filetime(st.st_atime)
        info.ftLastWriteTime = _unix_ts_to_filetime(st.st_mtime)
        info.dwVolumeSerialNumber = 0x44465301
        info.nFileSizeHigh = (size >> 32) & 0xFFFFFFFF
        info.nFileSizeLow = size & 0xFFFFFFFF
        info.nNumberOfLinks = max(1, int(st.st_nlink))
        ino = int(getattr(st, "st_ino", 1) or 1)
        info.nFileIndexHigh = (ino >> 32) & 0xFFFFFFFF
        info.nFileIndexLow = ino & 0xFFFFFFFF
        return _to_signed_ntstatus(STATUS_SUCCESS)

    def find_files(self, file_name: Optional[str], fill_cb: Any, info_ptr: Any) -> int:
        try:
            target = self._resolve(file_name)
        except (UnsafePathError, OSError):
            return _to_signed_ntstatus(STATUS_OBJECT_PATH_INVALID)
        if not target.is_dir():
            return _to_signed_ntstatus(STATUS_NOT_A_DIRECTORY)
        try:
            entries = sorted(target.iterdir(), key=lambda p: p.name)
        except OSError:
            return _to_signed_ntstatus(STATUS_ACCESS_DENIED)

        for entry in entries:
            if entry.name in (".clayfs", ".DS_Store") or entry.name.startswith("._"):
                continue
            try:
                st = entry.lstat()
            except OSError:
                continue
            if stat.S_ISLNK(st.st_mode):
                continue
            is_dir = stat.S_ISDIR(st.st_mode)
            attrs = FILE_ATTRIBUTE_DIRECTORY if is_dir else FILE_ATTRIBUTE_NORMAL
            if self.read_only:
                attrs |= FILE_ATTRIBUTE_READONLY
            size = 0 if is_dir else int(st.st_size)
            fd_w = WIN32_FIND_DATAW()
            fd_w.dwFileAttributes = attrs
            fd_w.ftCreationTime = _unix_ts_to_filetime(getattr(st, "st_birthtime", st.st_ctime))
            fd_w.ftLastAccessTime = _unix_ts_to_filetime(st.st_atime)
            fd_w.ftLastWriteTime = _unix_ts_to_filetime(st.st_mtime)
            fd_w.nFileSizeHigh = (size >> 32) & 0xFFFFFFFF
            fd_w.nFileSizeLow = size & 0xFFFFFFFF
            fd_w.cFileName = entry.name[:259]
            if fill_cb(ctypes.pointer(fd_w), info_ptr):
                break
        return _to_signed_ntstatus(STATUS_SUCCESS)

    def set_file_attributes(self, file_name: Optional[str], _attrs: int, _info_ptr: Any) -> int:
        if self.read_only:
            return _to_signed_ntstatus(STATUS_MEDIA_WRITE_PROTECTED)
        try:
            target = self._resolve(file_name)
            if not target.exists():
                return _to_signed_ntstatus(STATUS_OBJECT_NAME_NOT_FOUND)
        except (UnsafePathError, OSError):
            return _to_signed_ntstatus(STATUS_OBJECT_PATH_INVALID)
        return _to_signed_ntstatus(STATUS_SUCCESS)

    def set_file_time(
        self,
        file_name: Optional[str],
        _ctime: Any,
        atime_ptr: Any,
        mtime_ptr: Any,
        _info_ptr: Any,
    ) -> int:
        if self.read_only:
            return _to_signed_ntstatus(STATUS_MEDIA_WRITE_PROTECTED)
        try:
            target = self._resolve(file_name)
            st = target.lstat()
        except (UnsafePathError, OSError):
            return _to_signed_ntstatus(STATUS_OBJECT_NAME_NOT_FOUND)
        atime = _filetime_to_unix_ts(atime_ptr.contents) if atime_ptr else None
        mtime = _filetime_to_unix_ts(mtime_ptr.contents) if mtime_ptr else None
        if atime is not None or mtime is not None:
            try:
                os.utime(
                    target,
                    (atime if atime is not None else st.st_atime, mtime if mtime is not None else st.st_mtime),
                )
                with self._lock:
                    self._mark_dirty()
                self._schedule_flush()
            except OSError:
                return _to_signed_ntstatus(STATUS_ACCESS_DENIED)
        return _to_signed_ntstatus(STATUS_SUCCESS)

    def delete_file(self, file_name: Optional[str], _info_ptr: Any) -> int:
        if self.read_only:
            return _to_signed_ntstatus(STATUS_MEDIA_WRITE_PROTECTED)
        try:
            target = self._resolve(file_name)
        except (UnsafePathError, OSError):
            return _to_signed_ntstatus(STATUS_OBJECT_PATH_INVALID)
        if not target.exists():
            return _to_signed_ntstatus(STATUS_OBJECT_NAME_NOT_FOUND)
        if target.is_dir():
            return _to_signed_ntstatus(STATUS_FILE_IS_A_DIRECTORY)
        return _to_signed_ntstatus(STATUS_SUCCESS)

    def delete_directory(self, file_name: Optional[str], _info_ptr: Any) -> int:
        if self.read_only:
            return _to_signed_ntstatus(STATUS_MEDIA_WRITE_PROTECTED)
        try:
            target = self._resolve(file_name)
        except (UnsafePathError, OSError):
            return _to_signed_ntstatus(STATUS_OBJECT_PATH_INVALID)
        if not target.exists():
            return _to_signed_ntstatus(STATUS_OBJECT_NAME_NOT_FOUND)
        if not target.is_dir():
            return _to_signed_ntstatus(STATUS_NOT_A_DIRECTORY)
        try:
            if any(target.iterdir()):
                return _to_signed_ntstatus(STATUS_DIRECTORY_NOT_EMPTY)
        except OSError:
            return _to_signed_ntstatus(STATUS_ACCESS_DENIED)
        return _to_signed_ntstatus(STATUS_SUCCESS)

    def move_file(
        self,
        file_name: Optional[str],
        new_file_name: Optional[str],
        replace_if_existing: bool,
        info_ptr: Any,
    ) -> int:
        if self.read_only:
            return _to_signed_ntstatus(STATUS_MEDIA_WRITE_PROTECTED)
        try:
            src = self._resolve(file_name)
            dst = self._resolve(new_file_name)
        except (UnsafePathError, OSError):
            return _to_signed_ntstatus(STATUS_OBJECT_PATH_INVALID)
        if not src.exists():
            return _to_signed_ntstatus(STATUS_OBJECT_NAME_NOT_FOUND)
        if dst.exists() and not replace_if_existing:
            return _to_signed_ntstatus(STATUS_OBJECT_NAME_COLLISION)
        with self._lock:
            self._close_fh(info_ptr)
            try:
                dst.parent.mkdir(parents=True, exist_ok=True)
                if replace_if_existing and dst.exists():
                    if dst.is_dir():
                        shutil.rmtree(dst)
                    else:
                        os.replace(src, dst)
                        self._mark_dirty()
                        self._schedule_flush()
                        return _to_signed_ntstatus(STATUS_SUCCESS)
                src.rename(dst)
                self._mark_dirty()
            except OSError:
                return _to_signed_ntstatus(STATUS_ACCESS_DENIED)
        self._schedule_flush()
        return _to_signed_ntstatus(STATUS_SUCCESS)

    def set_end_of_file(self, file_name: Optional[str], byte_offset: int, info_ptr: Any) -> int:
        if self.read_only:
            return _to_signed_ntstatus(STATUS_MEDIA_WRITE_PROTECTED)
        with self._lock:
            fh = int(info_ptr.contents.Context) if info_ptr else 0
            fd = self._fds.get(fh)
            temp_fd: Optional[int] = None
            if fd is None:
                try:
                    target = self._resolve(file_name)
                    temp_fd = os.open(target, os.O_RDWR | _O_BINARY)
                    fd = temp_fd
                except (UnsafePathError, OSError):
                    return _to_signed_ntstatus(STATUS_OBJECT_NAME_NOT_FOUND)
            try:
                os.ftruncate(fd, max(0, int(byte_offset)))
                self._mark_dirty()
            except OSError:
                return _to_signed_ntstatus(STATUS_INTERNAL_ERROR)
            finally:
                if temp_fd is not None:
                    try:
                        os.close(temp_fd)
                    except OSError:
                        pass
        return _to_signed_ntstatus(STATUS_SUCCESS)

    def set_allocation_size(self, file_name: Optional[str], alloc_size: int, info_ptr: Any) -> int:
        if self.read_only:
            return _to_signed_ntstatus(STATUS_MEDIA_WRITE_PROTECTED)
        try:
            target = self._resolve(file_name)
            st = target.lstat()
        except (UnsafePathError, OSError):
            return _to_signed_ntstatus(STATUS_OBJECT_NAME_NOT_FOUND)
        if int(alloc_size) < int(st.st_size):
            return self.set_end_of_file(file_name, alloc_size, info_ptr)
        return _to_signed_ntstatus(STATUS_SUCCESS)

    def get_disk_free_space(
        self, free_avail_ptr: Any, total_ptr: Any, total_free_ptr: Any, _info_ptr: Any
    ) -> int:
        try:
            usage = shutil.disk_usage(self.root)
            if free_avail_ptr:
                free_avail_ptr[0] = usage.free
            if total_ptr:
                total_ptr[0] = usage.total
            if total_free_ptr:
                total_free_ptr[0] = usage.free
        except OSError:
            pass
        return _to_signed_ntstatus(STATUS_SUCCESS)

    def get_volume_information(
        self,
        vol_buf: Any,
        vol_size: int,
        serial_ptr: Any,
        max_comp_ptr: Any,
        flags_ptr: Any,
        fs_buf: Any,
        fs_size: int,
        _info_ptr: Any,
    ) -> int:
        if vol_buf and vol_size > 0:
            ctypes.wstring_at  # keep reference harmless
            vol = self.volname[: max(0, int(vol_size) - 1)]
            ctypes.memmove(vol_buf, ctypes.create_unicode_buffer(vol), (len(vol) + 1) * ctypes.sizeof(wintypes.WCHAR))
        if serial_ptr:
            serial_ptr[0] = 0x44465301
        if max_comp_ptr:
            max_comp_ptr[0] = 255
        if flags_ptr:
            flags_ptr[0] = (
                FILE_CASE_SENSITIVE_SEARCH
                | FILE_CASE_PRESERVED_NAMES
                | FILE_UNICODE_ON_DISK
            )
        if fs_buf and fs_size > 0:
            fs_name = "DFS"[: max(0, int(fs_size) - 1)]
            ctypes.memmove(fs_buf, ctypes.create_unicode_buffer(fs_name), (len(fs_name) + 1) * ctypes.sizeof(wintypes.WCHAR))
        return _to_signed_ntstatus(STATUS_SUCCESS)

    def build_operations(self) -> DOKAN_OPERATIONS:
        """``DOKAN_OPERATIONS`` 構造体を組み立て、コールバック参照をインスタンスへ保持する。"""
        ops = DOKAN_OPERATIONS()
        ops.ZwCreateFile = _ZW_CREATE_FILE_CB(self.zw_create_file)
        ops.Cleanup = _CLEANUP_CB(self.cleanup)
        ops.CloseFile = _CLOSE_FILE_CB(self.close_file)
        ops.ReadFile = _READ_FILE_CB(self.read_file)
        ops.WriteFile = _WRITE_FILE_CB(self.write_file)
        ops.FlushFileBuffers = _FLUSH_FILE_BUFFERS_CB(self.flush_file_buffers)
        ops.GetFileInformation = _GET_FILE_INFO_CB(self.get_file_information)
        ops.FindFiles = _FIND_FILES_CB(self.find_files)
        ops.FindFilesWithPattern = _FIND_FILES_WITH_PATTERN_CB()
        ops.SetFileAttributes = _SET_FILE_ATTRS_CB(self.set_file_attributes)
        ops.SetFileTime = _SET_FILE_TIME_CB(self.set_file_time)
        ops.DeleteFile = _DELETE_FILE_CB(self.delete_file)
        ops.DeleteDirectory = _DELETE_DIR_CB(self.delete_directory)
        ops.MoveFile = _MOVE_FILE_CB(self.move_file)
        ops.SetEndOfFile = _SET_END_OF_FILE_CB(self.set_end_of_file)
        ops.SetAllocationSize = _SET_ALLOC_SIZE_CB(self.set_allocation_size)
        ops.LockFile = _LOCK_FILE_CB()
        ops.UnlockFile = _UNLOCK_FILE_CB()
        ops.GetDiskFreeSpace = _GET_DISK_FREE_SPACE_CB(self.get_disk_free_space)
        ops.GetVolumeInformation = _GET_VOLUME_INFO_CB(self.get_volume_information)
        ops.Mounted = _MOUNTED_CB(lambda _mp, _fi: STATUS_SUCCESS)
        ops.Unmounted = _UNMOUNTED_CB(lambda _fi: (self.close_all(), STATUS_SUCCESS)[1])
        ops.GetFileSecurity = _GET_FILE_SECURITY_CB(
            lambda _fn, _si, _sd, _bl, _ln, _fi: _to_signed_ntstatus(STATUS_NOT_IMPLEMENTED)
        )
        ops.SetFileSecurity = _SET_FILE_SECURITY_CB(
            lambda _fn, _si, _sd, _bl, _fi: _to_signed_ntstatus(STATUS_NOT_IMPLEMENTED)
        )
        ops.FindStreams = _FIND_STREAMS_CB()
        self._callbacks = [ops]
        return ops


def mount_dokan(
    root: Path | str,
    mountpoint: str | Path,
    flush_callback: Callable[[], None],
    *,
    volname: str = "dfs",
    read_only: bool = False,
    debug: bool = False,
    sync_delay: float = 0.5,
    dokan_library: Optional[str] = None,
) -> int:
    """Dokany2 (``dokan2.dll``) を使って ``root`` を ``mountpoint`` へマウントする。"""
    if sys.platform != "win32":
        raise RuntimeError("Dokan mount is only supported on Windows")
    dll_path = find_dokan_library(dokan_library)
    if dll_path is None:
        raise FileNotFoundError(
            "dokan2.dll が見つかりません。Dokany2 (https://github.com/dokan-dev/dokany/releases) "
            "をインストールしてください。"
        )
    dll = ctypes.WinDLL(str(dll_path))  # type: ignore[attr-defined]
    dll.DokanVersion.restype = wintypes.ULONG
    dll.DokanInit.restype = None
    dll.DokanShutdown.restype = None
    dll.DokanMain.argtypes = [ctypes.POINTER(DOKAN_OPTIONS), ctypes.POINTER(DOKAN_OPERATIONS)]
    dll.DokanMain.restype = ctypes.c_int

    drv_ver = int(dll.DokanVersion() or 0)
    opts = DOKAN_OPTIONS()
    opts.Version = min(drv_ver, 230) if drv_ver >= 200 else DOKAN_VERSION_DEFAULT
    opts.SingleThread = False
    # DOKAN_OPTION_MOUNT_MANAGER requires elevated privileges in many Windows
    # environments and fails with DOKAN_START_ERROR (-4 / ERROR_NO_SYSTEM_RESOURCES)
    # when mounted by a standard user or from an SSH session.
    flags = DOKAN_OPTION_CURRENT_SESSION
    if read_only:
        flags |= DOKAN_OPTION_WRITE_PROTECT
    if debug:
        flags |= DOKAN_OPTION_DEBUG | DOKAN_OPTION_STDERR
    opts.Options = flags
    opts.MountPoint = str(mountpoint)
    opts.Timeout = 15000
    opts.AllocationUnitSize = 4096
    opts.SectorSize = 4096

    handler = LocalTreeDokan(
        root,
        flush_callback,
        volname=volname,
        read_only=read_only,
        sync_delay=sync_delay,
    )
    ops = handler.build_operations()
    dll.DokanInit()
    try:
        return int(dll.DokanMain(ctypes.byref(opts), ctypes.byref(ops)))
    finally:
        handler.close_all()
        dll.DokanShutdown()
