#!/usr/bin/env python3
"""
dfs5/fs/core.py
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

import ctypes
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

# メタデータとして保存しない名前。OS ごとに揺れるゴミをスナップショットに持ち込まない。
DEFAULT_IGNORE_NAMES: Tuple[str, ...] = (".DS_Store",)
DEFAULT_IGNORE_PREFIXES: Tuple[str, ...] = ("._",)
SNAPSHOT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def _validate_snapshot_id(snap_id: str) -> str:
    """スナップショット ID を単一の安全なパス要素に限定する。"""
    if not isinstance(snap_id, str) or not SNAPSHOT_ID_RE.fullmatch(snap_id):
        raise ValueError(f"Invalid snapshot ID: {snap_id!r}")
    if snap_id in (".", ".."):
        raise ValueError(f"Invalid snapshot ID: {snap_id!r}")
    return snap_id


class Capability(str, Enum):
    """バックエンドが持つ能力。"""

    COPY = "copy"          # 実コピー。どこでも動く。
    REFLINK = "reflink"    # ファイル単位の CoW (clonefile / FICLONE)
    FAST_CLONE = "fast_clone"  # ディレクトリ単位の CoW (btrfs send/receive, block clone)


@dataclass(frozen=True)
class BackendInfo:
    name: str
    capability: Capability
    detail: str
    available: bool


@dataclass
class SnapshotResult:
    snapshot_id: str
    path: Path
    backend: str
    files: int
    bytes_copied: int
    skipped: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


# --------------------------------------------------------------------------
# 低レベル: ファイル単位の CoW
# --------------------------------------------------------------------------

def _macos_clonefile(src: str, dst: str) -> None:
    """macOS の clonefile(2)。失敗時は OSError を送出する。"""
    libc = ctypes.CDLL(None, use_errno=True)
    rc = libc.clonefile(src.encode(), dst.encode(), 0)
    if rc != 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code), src)


def _linux_ficlone(src: str, dst: str) -> None:
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


def _windows_cluster_size(path: str) -> int:
    """``path`` のボリュームのクラスタサイズ (バイト)。分からなければ 4096。"""
    if sys.platform != "win32":
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
    if sys.platform != "win32":
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


def _is_windows_junction(path: Path) -> bool:
    """Windows のジャンクション / マウントポイント（ディレクトリの再解析ポイント）か。

    OneDrive のプレースホルダのような「ファイル」の再解析ポイントは対象外。
    それらは通常の読み取りで中身が取り出せるので、コピーすべきファイルである。
    シンボリックリンクは ``is_symlink()`` 側で先に処理する。
    """
    if sys.platform != "win32":
        return False
    try:
        info = os.lstat(path)
    except OSError:
        return False
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x00000400)
    if not (getattr(info, "st_file_attributes", 0) & reparse):
        return False
    return stat.S_ISDIR(info.st_mode)


def remove_tree(path: Path | str) -> None:
    """ディレクトリを消す。Windows の read-only 属性は外してから消す。

    ``shutil.rmtree`` は Windows では read-only 属性のファイル/ディレクトリで
    ``PermissionError`` になる。``shutil.copy2`` は属性を引き継ぐので、一度
    read-only のファイルが入ると次のスナップショットが作れなくなる。
    """
    target = Path(path)

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


def _recreate_symlink(src: Path, dst: Path) -> None:
    target = os.readlink(src)
    if dst.is_symlink() or dst.exists():
        dst.unlink()
    os.symlink(target, dst)


# --------------------------------------------------------------------------
# バックエンド
# --------------------------------------------------------------------------

class Backend:
    name = "backend"
    capability = Capability.COPY

    def copy_file(self, src: Path, dst: Path) -> int:
        raise NotImplementedError

    def copy_tree(self, src: Path, dst: Path, ignore: Sequence[str] = ()) -> Tuple[int, int]:
        raise NotImplementedError


class CopyBackend(Backend):
    """実コピー。どこでも動く。スナップショットは独立した inode になる。"""

    name = "copy"
    capability = Capability.COPY

    def copy_file(self, src: Path, dst: Path) -> int:
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
            elif _is_windows_junction(entry):
                # ジャンクションの中身は「このツリーの外」かもしれない。
                # 辿らずに断る（スナップショット側は skipped に記録して続ける）。
                raise OSError(errno.ENOTSUP, f"unsupported reparse point: {entry}")
            elif entry.is_dir():
                sub_files, sub_bytes = self.copy_tree(entry, target, ignore)
                files += sub_files
                total += sub_bytes
            elif entry.is_file():
                total += self.copy_file(entry, target)
                files += 1
            else:
                # FIFO / socket / device はコピーしない (呼び出し側が warnings で知る)
                raise OSError(errno.ENOTSUP, f"unsupported file type: {entry}")
        return files, total


class ReflinkBackend(Backend):
    """ファイル単位の CoW。macOS clonefile / Linux FICLONE。"""

    name = "reflink"
    capability = Capability.REFLINK

    def __init__(self, copier: Callable[[str, str], None], detail: str):
        self._copier = copier
        self.detail = detail

    def copy_file(self, src: Path, dst: Path) -> int:
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
            elif _is_windows_junction(entry):
                # ジャンクションの中身は「このツリーの外」かもしれない。
                # 辿らずに断る（スナップショット側は skipped に記録して続ける）。
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
                        # このファイルだけ CoW できない。実コピーへ落とす。
                        total += CopyBackend().copy_file(entry, target)
                    else:
                        raise
                files += 1
            else:
                raise OSError(errno.ENOTSUP, f"unsupported file type: {entry}")
        return files, total


class FastCloneBackend(Backend):
    """ファイル単位の CoW を内部で使う backend。

    Windows の block clone は 1 ファイル単位の API なので、``copy_file`` で
    ``FSCTL_DUPLICATE_EXTENTS_TO_FILE`` を呼び、``copy_tree`` は再帰する。
    btrfs subvolume / ``btrfs send|receive`` のような真のディレクトリ単位 CoW は
    将来の拡張 (``fast_clone`` の別実装) として予約する。
    """

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


# --------------------------------------------------------------------------
# バックエンド検出
# --------------------------------------------------------------------------

def _probe_reflink(path: Path) -> Optional[BackendInfo]:
    """path の上で 1 ファイルを実際に複製してみて CoW が使えるか確かめる。"""
    import tempfile

    system = platform.system()
    if system not in ("Darwin", "Linux"):
        return None
    with tempfile.TemporaryDirectory(prefix="dfs5_fs_probe_", dir=str(path)) as probe:
        probe_dir = Path(probe)
        src = probe_dir / "probe_src"
        dst = probe_dir / "probe_dst"
        src.write_bytes(b"dfs5")
        try:
            if system == "Darwin":
                _macos_clonefile(str(src), str(dst))
                return BackendInfo(
                    "reflink", Capability.REFLINK, "macOS clonefile(2)", True
                )
            if system == "Linux":
                _linux_ficlone(str(src), str(dst))
                return BackendInfo(
                    "reflink", Capability.REFLINK, "Linux FICLONE ioctl", True
                )
        except OSError:
            # EOPNOTSUPP / EXDEV / EINVAL / EACCES 等は「この FS では CoW 不可」。
            return None
        except Exception:
            return None
        return None


def _probe_block_clone(path: Path) -> Optional[BackendInfo]:
    """Windows の ReFS / Dev Drive block clone を実際に試す。"""
    if sys.platform != "win32":
        return None
    import tempfile

    # block clone はクラスタ単位。1 クラスタ未満だと常に ENOTSUP になるので、
    # 1 MiB を書いて「本当に複製できたか」と「中身が一致するか」まで確かめる。
    payload = b"\x00" * (1024 * 1024)
    with tempfile.TemporaryDirectory(prefix="dfs5_fs_clone_", dir=str(path)) as probe:
        probe_dir = Path(probe)
        src = probe_dir / "probe_src"
        dst = probe_dir / "probe_dst"
        src.write_bytes(payload)
        try:
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


def detect_backends(root: Path) -> List[BackendInfo]:
    """root の上で使えるバックエンドを、高性能な順に返す。"""
    infos: List[BackendInfo] = [BackendInfo("copy", Capability.COPY, "実コピー", True)]
    reflink = _probe_reflink(root)
    if reflink is not None:
        infos.insert(0, reflink)
    block = _probe_block_clone(root)
    if block is not None:
        infos.insert(0, block)
    return infos


def default_backend_name(root: Path) -> str:
    infos = detect_backends(root)
    return infos[0].name


# --------------------------------------------------------------------------
# ファイルシステム
# --------------------------------------------------------------------------

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
            info = _probe_reflink(self.root)
            if info is None:
                info = _probe_block_clone(self.root)
            if info is None:
                raise RuntimeError("reflink backend is not available on this filesystem")
            return self._make_backend(info)
        if requested in ("fast_clone", "block_clone"):
            info = _probe_block_clone(self.root)
            if info is None:
                raise RuntimeError("block clone backend is not available on this filesystem")
            return self._make_backend(info)
        if requested not in ("auto", ""):
            raise ValueError(f"unknown backend: {requested!r}")
        for info in detect_backends(self.root):
            if info.capability is Capability.FAST_CLONE:
                return self._make_backend(info)
        for info in detect_backends(self.root):
            if info.name == "reflink":
                return self._make_backend(info)
        return CopyBackend()

    @staticmethod
    def _make_backend(info: BackendInfo) -> Backend:
        system = platform.system()
        if system == "Darwin":
            return ReflinkBackend(_macos_clonefile, info.detail)
        if system == "Linux":
            return ReflinkBackend(_linux_ficlone, info.detail)
        if info.capability is Capability.FAST_CLONE:
            return FastCloneBackend(info.detail)
        return CopyBackend()

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
                    if sys.platform == "win32" and getattr(exc, "winerror", None) == 1314:
                        skipped.append(str(entry))
                        self._warnings.append(
                            f"symlink を作れないためスナップショットから除外: {entry}"
                        )
                    else:
                        raise
            elif _is_windows_junction(entry):
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
