#!/usr/bin/env python3
"""fuse-t / fusepy を使った dfs のローカルマウント。

このモジュールは FUSE の操作だけを担当し、DFS 固有の push は
``flush_callback`` として受け取る。読み書きの実体は dfs の作業ツリー。
"""

from __future__ import annotations

import errno
import os
import shutil
import stat
import threading
from pathlib import Path
from typing import Any, Callable, Optional

from .compression import get_raw_xattr, remove_raw_xattr, set_raw_xattr
from .path_safety import UnsafePathError, safe_target


class LocalTreeFuse:
    """1 つのローカルディレクトリを FUSE に公開する Operations。

    ``flush_callback`` は、書き込み後に DFS の 1 版を作る処理。
    FUSE の flush / fsync / destroy で呼ばれる。
    """

    # getattr は st_mtime などを秒単位の float で返す。fusepy の use_ns=True は
    # 値がナノ秒である前提なので、ここは秒単位の False にする。
    use_ns = False

    def __call__(self, op: str, *args: Any) -> Any:
        """fusepy の Operations と同じディスパッチ形式。"""
        method = getattr(self, op, None)
        if method is None:
            raise OSError(errno.ENOTSUP, f"unsupported FUSE operation: {op}")
        return method(*args)

    def __init__(
        self,
        root: Path | str,
        flush_callback: Callable[[], None],
        *,
        read_only: bool = False,
        sync_delay: float = 0.0,
    ):
        self.root = Path(root).resolve()
        self.flush_callback = flush_callback
        self.read_only = read_only
        self.sync_delay = max(0.0, float(sync_delay))
        self._lock = threading.RLock()
        self._flush_lock = threading.Lock()
        self._dirty = False
        self._timer: Optional[threading.Timer] = None
        self._fds: dict[int, int] = {}
        self._next_fh = 1

    def _path(self, path: str) -> Path:
        rel = (path or "/").lstrip("/")
        if not rel:
            return self.root
        try:
            return safe_target(self.root, rel)
        except UnsafePathError as e:
            raise OSError(errno.EACCES, str(e)) from e

    def _mark_dirty(self) -> None:
        if self.read_only:
            raise OSError(errno.EROFS, "read-only mount")
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
        except Exception as e:  # noqa: BLE001 - バックグラウンド flush の失敗を隠さない
            import sys

            print(f"[dfscli] mount flush failed: {e}", file=sys.stderr)

    def _schedule_flush(self) -> bool:
        with self._lock:
            if self.sync_delay <= 0:
                return self._take_dirty_locked()
            if self._timer is not None:
                self._timer.cancel()
            self._timer = threading.Timer(self.sync_delay, self._timer_flush)
            self._timer.daemon = True
            self._timer.start()
            return False

    def flush(self, path: str, fh: int | None = None) -> None:
        # FUSE は close 前に flush を複数回呼ぶことがある。デバウンスして
        # release / fsync / destroy と同じ 1 回の push に合流させる。
        if self._schedule_flush():
            self._run_flush_callback()

    def fsync(self, path: str, datasync: int, fh: int | None = None) -> None:
        # close 時の release で push する。fsync は同じデバウンスに合流させる。
        if self._schedule_flush():
            self._run_flush_callback()

    def release(self, path: str, fh: int | None = None) -> None:
        if fh is not None:
            with self._lock:
                fd = self._fds.pop(fh, None)
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
        if self._schedule_flush():
            self._run_flush_callback()

    def destroy(self, path: str) -> None:
        with self._lock:
            if self._timer is not None:
                self._timer.cancel()
                self._timer = None
            open_fds = list(self._fds.values())
            self._fds.clear()
            should_flush = self._take_dirty_locked()
        for fd in open_fds:
            try:
                os.close(fd)
            except OSError:
                pass
        if should_flush:
            self._run_flush_callback()

    def getattr(self, path: str, fh: int | None = None) -> dict[str, Any]:
        target = self._path(path)
        try:
            st = os.lstat(target)
        except FileNotFoundError:
            raise OSError(errno.ENOENT, os.strerror(errno.ENOENT))
        if stat.S_ISLNK(st.st_mode):
            raise OSError(errno.ENOENT, os.strerror(errno.ENOENT))
        return {
            "st_mode": st.st_mode,
            "st_ino": st.st_ino,
            "st_dev": st.st_dev,
            "st_nlink": st.st_nlink,
            "st_uid": st.st_uid,
            "st_gid": st.st_gid,
            "st_size": st.st_size,
            "st_atime": st.st_atime,
            "st_mtime": st.st_mtime,
            "st_ctime": st.st_ctime,
            "st_blocks": getattr(st, "st_blocks", 0),
            "st_blksize": getattr(st, "st_blksize", 4096),
        }

    def statfs(self, path: str) -> dict[str, int]:
        """マウント先の容量を、実体のあるファイルシステムから返す。"""
        target = self._path(path)
        if not target.exists():
            raise OSError(errno.ENOENT, os.strerror(errno.ENOENT))
        if hasattr(os, "statvfs"):
            try:
                st = os.statvfs(target)
            except FileNotFoundError:
                raise OSError(errno.ENOENT, os.strerror(errno.ENOENT))
            return {
                "f_bsize": int(st.f_bsize),
                "f_frsize": int(st.f_frsize or st.f_bsize),
                "f_blocks": int(st.f_blocks),
                "f_bfree": int(st.f_bfree),
                "f_bavail": int(st.f_bavail),
                "f_files": int(st.f_files),
                "f_ffree": int(st.f_ffree),
                "f_favail": int(st.f_favail),
                "f_flag": int(st.f_flag),
                "f_namemax": int(st.f_namemax),
            }
        usage = shutil.disk_usage(target)
        bsize = 4096
        return {
            "f_bsize": bsize,
            "f_frsize": bsize,
            "f_blocks": usage.total // bsize,
            "f_bfree": usage.free // bsize,
            "f_bavail": usage.free // bsize,
            "f_files": 1000000,
            "f_ffree": 500000,
            "f_favail": 500000,
            "f_flag": 0,
            "f_namemax": 255,
        }

    def readdir(self, path: str, fh: int | None = None) -> list[str]:
        target = self._path(path)
        if not target.is_dir():
            raise OSError(errno.ENOTDIR, os.strerror(errno.ENOTDIR))
        names = [".", ".."]
        for item in sorted(target.iterdir(), key=lambda p: p.name):
            if item.is_symlink():
                continue
            names.append(item.name)
        return names

    def _alloc_fh(self, fd: int) -> int:
        with self._lock:
            fh = self._next_fh
            self._next_fh += 1
            self._fds[fh] = fd
            return fh

    def _get_fd(self, fh: int | None) -> Optional[int]:
        if fh is None:
            return None
        with self._lock:
            return self._fds.get(fh)

    def open(self, path: str, flags: int) -> int:
        target = self._path(path)
        if not target.is_file() or target.is_symlink():
            raise OSError(errno.ENOENT, os.strerror(errno.ENOENT))
        if self.read_only and flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND):
            raise OSError(errno.EROFS, os.strerror(errno.EROFS))
        no_follow = getattr(os, "O_NOFOLLOW", 0)
        acc_mode = flags & os.O_ACCMODE
        open_flags = acc_mode | (flags & (os.O_APPEND | os.O_TRUNC)) | no_follow
        fd = os.open(target, open_flags)
        return self._alloc_fh(fd)

    def read(
        self,
        path: str,
        size: int,
        offset: int,
        fh: int | None = None,
    ) -> bytes:
        fd = self._get_fd(fh)
        if fd is not None:
            if hasattr(os, "pread"):
                return os.pread(fd, size, offset)
            with self._lock:
                os.lseek(fd, offset, os.SEEK_SET)
                return os.read(fd, size)
        target = self._path(path)
        no_follow = getattr(os, "O_NOFOLLOW", 0)
        try:
            temp_fd = os.open(target, os.O_RDONLY | no_follow)
        except FileNotFoundError:
            raise OSError(errno.ENOENT, os.strerror(errno.ENOENT))
        try:
            if hasattr(os, "pread"):
                return os.pread(temp_fd, size, offset)
            os.lseek(temp_fd, offset, os.SEEK_SET)
            return os.read(temp_fd, size)
        finally:
            os.close(temp_fd)

    def create(self, path: str, mode: int, flags: int = 0) -> int:
        with self._lock:
            self._mark_dirty()
            target = self._path(path)
            target.parent.mkdir(parents=True, exist_ok=True)
            no_follow = getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(
                target,
                os.O_CREAT | os.O_RDWR | os.O_TRUNC | no_follow,
                mode & 0o777,
            )
            return self._alloc_fh(fd)

    def write(
        self,
        path: str,
        data: bytes,
        offset: int,
        fh: int | None = None,
    ) -> int:
        with self._lock:
            self._mark_dirty()
            fd = self._get_fd(fh)
        if fd is not None:
            if hasattr(os, "pwrite"):
                return os.pwrite(fd, data, offset)
            with self._lock:
                os.lseek(fd, offset, os.SEEK_SET)
                return os.write(fd, data)
        with self._lock:
            target = self._path(path)
            target.parent.mkdir(parents=True, exist_ok=True)
            no_follow = getattr(os, "O_NOFOLLOW", 0)
            temp_fd = os.open(target, os.O_CREAT | os.O_RDWR | no_follow, 0o644)
            try:
                if hasattr(os, "pwrite"):
                    return os.pwrite(temp_fd, data, offset)
                os.lseek(temp_fd, offset, os.SEEK_SET)
                return os.write(temp_fd, data)
            finally:
                os.close(temp_fd)

    def truncate(self, path: str, length: int, fh: int | None = None) -> None:
        with self._lock:
            self._mark_dirty()
            fd = self._get_fd(fh)
        if fd is not None:
            os.ftruncate(fd, length)
            return
        with self._lock:
            target = self._path(path)
            target.parent.mkdir(parents=True, exist_ok=True)
            no_follow = getattr(os, "O_NOFOLLOW", 0)
            temp_fd = os.open(target, os.O_CREAT | os.O_RDWR | no_follow, 0o644)
            try:
                os.ftruncate(temp_fd, length)
            finally:
                os.close(temp_fd)

    def unlink(self, path: str) -> None:
        with self._lock:
            self._mark_dirty()
            try:
                self._path(path).unlink()
            except FileNotFoundError:
                raise OSError(errno.ENOENT, os.strerror(errno.ENOENT))

    def mkdir(self, path: str, mode: int) -> None:
        with self._lock:
            self._mark_dirty()
            self._path(path).mkdir(mode=mode)

    def rmdir(self, path: str) -> None:
        with self._lock:
            self._mark_dirty()
            self._path(path).rmdir()

    def rename(self, old: str, new: str) -> None:
        with self._lock:
            self._mark_dirty()
            src = self._path(old)
            dst = self._path(new)
            dst.parent.mkdir(parents=True, exist_ok=True)
            src.rename(dst)

    def chmod(self, path: str, mode: int) -> None:
        with self._lock:
            self._mark_dirty()
            target = self._path(path)
            if target.is_symlink():
                raise OSError(errno.ENOENT, os.strerror(errno.ENOENT))
            os.chmod(target, mode & 0o777)

    def utimens(self, path: str, times: Optional[tuple[float, float]] = None) -> None:
        with self._lock:
            self._mark_dirty()
            target = self._path(path)
            if times is None:
                os.utime(target, None)
            else:
                os.utime(target, (times[0], times[1]))

    def getxattr(self, path: str, name: str, position: int = 0) -> bytes:
        value = get_raw_xattr(self._path(path), name)
        if value is None:
            raise OSError(errno.ENODATA, os.strerror(errno.ENODATA))
        return value

    def setxattr(
        self,
        path: str,
        name: str,
        value: bytes,
        options: int = 0,
        position: int = 0,
    ) -> None:
        with self._lock:
            self._mark_dirty()
            if not set_raw_xattr(self._path(path), name, value):
                raise OSError(errno.ENOTSUP, "xattr is not supported")

    def removexattr(self, path: str, name: str) -> None:
        with self._lock:
            self._mark_dirty()
            if not remove_raw_xattr(self._path(path), name):
                raise OSError(errno.ENODATA, os.strerror(errno.ENODATA))
