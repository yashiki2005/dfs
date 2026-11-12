#!/usr/bin/env python3
"""フォルダ単位の圧縮ポリシー。

``user.dfs.compression`` xattr をローカル側の設定 UI として読み、継承した
実効ポリシーを返す。xattr が失われても、push 時に署名済みマニフェストへ
実効ポリシーを記録する。
"""

from __future__ import annotations

import os
import ctypes
import sys
from pathlib import Path
from typing import Optional

XATTR_NAME = "user.dfs.compression"
VALID_POLICIES = {"none", "zstd"}


def _macos_libc():
    libc = ctypes.CDLL(None, use_errno=True)
    libc.getxattr.argtypes = [
        ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p,
        ctypes.c_size_t, ctypes.c_uint32, ctypes.c_int,
    ]
    libc.getxattr.restype = ctypes.c_ssize_t
    libc.setxattr.argtypes = [
        ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p,
        ctypes.c_size_t, ctypes.c_uint32, ctypes.c_int,
    ]
    libc.setxattr.restype = ctypes.c_int
    libc.removexattr.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]
    libc.removexattr.restype = ctypes.c_int
    return libc


def _get_xattr_bytes(path: Path | str, name: str) -> Optional[bytes]:
    if hasattr(os, "getxattr"):
        try:
            return os.getxattr(str(path), name)
        except OSError:
            return None
    if sys.platform != "darwin":
        return None
    libc = _macos_libc()
    cpath, cname = str(path).encode(), name.encode()
    size = libc.getxattr(cpath, cname, None, 0, 0, 0)
    if size < 0:
        return None
    buf = ctypes.create_string_buffer(size)
    if libc.getxattr(cpath, cname, buf, size, 0, 0) < 0:
        return None
    return buf.raw[:size]


def _set_xattr_bytes(path: Path | str, name: str, value: bytes) -> bool:
    if hasattr(os, "setxattr"):
        try:
            os.setxattr(str(path), name, value)
            return True
        except OSError:
            return False
    if sys.platform != "darwin":
        return False
    libc = _macos_libc()
    try:
        return libc.setxattr(
            str(path).encode(), name.encode(), value, len(value), 0, 0
        ) == 0
    except (OSError, TypeError):
        return False


def _remove_xattr(path: Path | str, name: str) -> bool:
    if hasattr(os, "removexattr"):
        try:
            os.removexattr(str(path), name)
            return True
        except OSError:
            return False
    if sys.platform != "darwin":
        return False
    libc = _macos_libc()
    try:
        return libc.removexattr(str(path).encode(), name.encode(), 0) == 0
    except (OSError, TypeError):
        return False


def normalize_policy(value: object, default: str = "none") -> str:
    text = str(value or "").strip().lower()
    if not text:
        return default
    if text in ("off", "false", "0"):
        return "none"
    text = {"zstandard": "zstd", "zstd:10": "zstd"}.get(text, text)
    if text not in VALID_POLICIES:
        raise ValueError(f"Invalid compression policy: {value!r}")
    return text


def get_xattr(path: Path | str) -> Optional[str]:
    """圧縮 xattr を読む。未設定・非対応環境では ``None``。"""
    raw = _get_xattr_bytes(path, XATTR_NAME)
    if raw is None:
        return None
    try:
        return normalize_policy(raw.decode("utf-8"), default="none")
    except (UnicodeDecodeError, ValueError):
        return None


def set_xattr(path: Path | str, policy: str) -> bool:
    """圧縮 xattr を best-effort で設定する。"""
    value = normalize_policy(policy, default="none")
    return _set_xattr_bytes(path, XATTR_NAME, value.encode("utf-8"))


def get_raw_xattr(path: Path | str, name: str) -> Optional[bytes]:
    return _get_xattr_bytes(path, name)


def set_raw_xattr(path: Path | str, name: str, value: bytes) -> bool:
    return _set_xattr_bytes(path, name, value)


def remove_raw_xattr(path: Path | str, name: str) -> bool:
    return _remove_xattr(path, name)


def effective_policy(
    path: Path | str,
    root: Path | str,
    default: str = "none",
) -> str:
    """path から root へ xattr をたどり、最も近い設定を返す。"""
    root_path = Path(root).resolve()
    current = Path(path).resolve()
    try:
        current.relative_to(root_path)
    except ValueError:
        return normalize_policy(default)
    while True:
        value = get_xattr(current)
        if value is not None:
            return value
        if current == root_path:
            break
        current = current.parent
    return normalize_policy(default)
