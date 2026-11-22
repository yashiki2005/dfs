#!/usr/bin/env python3
"""作業ツリー内への書き込みを symlink と ``..`` から守るヘルパー。"""

from __future__ import annotations

import errno
import os
import shutil
import stat
from pathlib import Path
from typing import Iterable


class UnsafePathError(ValueError):
    """作業ツリーの外へ出る、または symlink をたどるパス。"""


def _relative_parts(rel: str | os.PathLike[str]) -> tuple[str, ...]:
    raw = str(rel)
    if "\x00" in raw:
        raise UnsafePathError(f"Path contains NUL: {raw!r}")
    # リモートパスの区切りは常に '/' として扱う。Windows の '\' も同じ扱いにする。
    raw = raw.replace("\\", "/")
    if raw.startswith("/"):
        raise UnsafePathError(f"Absolute path is not allowed here: {raw!r}")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in raw):
        raise UnsafePathError(f"Path contains control character: {raw!r}")
    if ":" in raw:
        raise UnsafePathError(f"Path contains ':' (invalid/drive-relative): {raw!r}")
    parts = tuple(raw.split("/"))
    if not parts or any(part in ("", ".", "..") for part in parts):
        raise UnsafePathError(f"Invalid relative path: {raw!r}")
    return parts


def _reject_symlink_components(root: Path, parts: Iterable[str]) -> None:
    current = root
    for part in parts:
        current = current / part
        try:
            st = current.lstat()
        except FileNotFoundError:
            return
        if stat.S_ISLNK(st.st_mode):
            raise UnsafePathError(f"Refusing to follow symlink: {current}")


def _ensure_within(root: Path, target: Path) -> None:
    root_real = root.resolve(strict=False)
    target_real = target.resolve(strict=False)
    try:
        target_real.relative_to(root_real)
    except ValueError as e:
        raise UnsafePathError(
            f"Path escapes from {root_real}: {target} -> {target_real}"
        ) from e


def safe_target(
    root: Path | str,
    rel: str | os.PathLike[str],
    *,
    create_parents: bool = False,
) -> Path:
    """``root`` 配下の安全な書き込み先を返す。

    既存の親要素に symlink があれば拒否し、解決後パスが ``root`` の外なら拒否する。
    ``create_parents=True`` のときは親を作成し、作成後にもう一度 symlink を確認する。
    """
    root_p = Path(root)
    parts = _relative_parts(rel)
    target = root_p.joinpath(*parts)

    _reject_symlink_components(root_p, parts)
    _ensure_within(root_p, target)

    if create_parents:
        target.parent.mkdir(parents=True, exist_ok=True)
        _reject_symlink_components(root_p, parts[:-1])
        _ensure_within(root_p, target)

    return target


def _open_no_follow(path: Path, flags: int) -> int:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not nofollow:
        try:
            if stat.S_ISLNK(path.lstat().st_mode):
                raise UnsafePathError(f"Refusing to follow symlink: {path}")
        except FileNotFoundError:
            pass
    try:
        return os.open(path, flags | nofollow, 0o600)
    except OSError as e:
        if nofollow and e.errno == errno.ELOOP:
            raise UnsafePathError(f"Refusing to follow symlink: {path}") from e
        raise


def write_bytes_no_follow(path: Path, data: bytes) -> None:
    """最終要素が symlink でないことを確認してファイルを書く。"""
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = _open_no_follow(path, flags)
    try:
        f = os.fdopen(fd, "wb")
    except Exception:
        os.close(fd)
        raise
    with f:
        f.write(data)


def copyfile_no_follow(src: Path, dst: Path) -> None:
    """コピー元・コピー先の最終要素が symlink でないことを確認してコピーする。"""
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    src_fd = _open_no_follow(src, os.O_RDONLY)
    try:
        src_f = os.fdopen(src_fd, "rb")
    except Exception:
        os.close(src_fd)
        raise
    with src_f:
        dst_fd = _open_no_follow(dst, flags)
        try:
            dst_f = os.fdopen(dst_fd, "wb")
        except Exception:
            os.close(dst_fd)
            raise
        with dst_f:
            shutil.copyfileobj(src_f, dst_f, length=1024 * 1024)
