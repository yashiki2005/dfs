#!/usr/bin/env python3
"""fuse-t / fusepy を使った dfs5 のローカルマウント。

このモジュールは FUSE の操作だけを担当し、DFS5 固有の push は
``flush_callback`` として受け取る。読み書きの実体は dfs5 の作業ツリー。
"""

from __future__ import annotations

import errno
import os
import stat
import threading
from pathlib import Path
from typing import Any, Callable, Optional

from .path_safety import UnsafePathError, safe_target


class LocalTreeFuse:
    """1 つのローカルディレクトリを FUSE に公開する Operations。

    ``flush_callback`` は、書き込み後に DFS5 の 1 版を作る処理。
    FUSE の flush / fsync / destroy で呼ばれる。
    """

    use_ns = True

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
        self._dirty = False
        self._timer: Optional[threading.Timer] = None

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

    def _flush_locked(self) -> None:
        if not self._dirty or self.read_only:
            return
        self.flush_callback()
        self._dirty = False

    def _timer_flush(self) -> None:
        with self._lock:
            self._timer = None
            try:
                self._flush_locked()
            except Exception as e:  # noqa: BLE001 - バックグラウンド flush の失敗を隠さない
                import sys

                print(f"[dfs5cli] mount flush failed: {e}", file=sys.stderr)

    def _schedule_flush(self) -> None:
        if self.sync_delay <= 0:
            self._flush_locked()
            return
        if self._timer is not None:
            self._timer.cancel()
        self._timer = threading.Timer(self.sync_delay, self._timer_flush)
        self._timer.daemon = True
        self._timer.start()

    def flush(self, path: str, fh: int | None = None) -> None:
        # FUSE は close 前に flush を複数回呼ぶことがある。デバウンスして
        # release / fsync / destroy と同じ 1 回の push に合流させる。
        with self._lock:
            self._schedule_flush()

    def fsync(self, path: str, datasync: int, fh: int | None = None) -> None:
        # close 時の release で push する。fsync は同じデバウンスに合流させる。
        with self._lock:
            self._schedule_flush()

    def release(self, path: str, fh: int | None = None) -> None:
        with self._lock:
            self._schedule_flush()

    def destroy(self, path: str) -> None:
        with self._lock:
            if self._timer is not None:
                self._timer.cancel()
                self._timer = None
            self._flush_locked()

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

    def open(self, path: str, flags: int) -> int:
        target = self._path(path)
        if not target.is_file():
            raise OSError(errno.ENOENT, os.strerror(errno.ENOENT))
        if self.read_only and flags & (os.O_WRONLY | os.O_RDWR):
            raise OSError(errno.EROFS, os.strerror(errno.EROFS))
        return 0

    def read(
        self,
        path: str,
        size: int,
        offset: int,
        fh: int | None = None,
    ) -> bytes:
        target = self._path(path)
        try:
            with target.open("rb") as f:
                f.seek(offset)
                return f.read(size)
        except FileNotFoundError:
            raise OSError(errno.ENOENT, os.strerror(errno.ENOENT))

    def create(self, path: str, mode: int, flags: int = 0) -> int:
        with self._lock:
            self._mark_dirty()
            target = self._path(path)
            target.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(target, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, mode)
            os.close(fd)
            return 0

    def write(
        self,
        path: str,
        data: bytes,
        offset: int,
        fh: int | None = None,
    ) -> int:
        with self._lock:
            self._mark_dirty()
            target = self._path(path)
            try:
                with target.open("r+b") as f:
                    f.seek(offset)
                    f.write(data)
            except FileNotFoundError:
                target.parent.mkdir(parents=True, exist_ok=True)
                with target.open("wb") as f:
                    f.seek(offset)
                    f.write(data)
            return len(data)

    def truncate(self, path: str, length: int, fh: int | None = None) -> None:
        with self._lock:
            self._mark_dirty()
            target = self._path(path)
            try:
                with target.open("r+b") as f:
                    f.truncate(length)
            except FileNotFoundError:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.touch()

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
            os.chmod(self._path(path), mode)

    def utimens(self, path: str, times: Optional[tuple[float, float]] = None) -> None:
        with self._lock:
            self._mark_dirty()
            target = self._path(path)
            if times is None:
                os.utime(target, None)
            else:
                os.utime(target, (times[0], times[1]))
