#!/usr/bin/env python3
"""フォルダ単位の圧縮ポリシー。

``user.dfs.compression`` xattr をローカル側の設定 UI として読み、継承した
実効ポリシーを返す。xattr が失われても、push 時に署名済みマニフェストへ
実効ポリシーを記録する。
"""

from __future__ import annotations

import ctypes
import functools
import os
import sys
from pathlib import Path
from typing import Dict, Optional

XATTR_NAME = "user.dfs.compression"
VALID_POLICIES = {"auto", "none", "zstd"}


@functools.lru_cache(maxsize=1)
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
    libc.listxattr.argtypes = [
        ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int,
    ]
    libc.listxattr.restype = ctypes.c_ssize_t
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


def list_raw_xattrs(path: Path | str) -> Dict[str, bytes]:
    """保存対象にできる xattr を列挙する。

    ``security.*`` など特権 xattr は、署名済みマニフェスト経由で任意に設定
    できないよう除外する。圧縮設定を含む ``user.*`` と macOS の
    ``com.apple.*`` だけを対象にする。
    """
    names: list[str] = []
    if hasattr(os, "listxattr"):
        try:
            names = [str(name) for name in os.listxattr(str(path))]
        except OSError:
            names = []
    elif sys.platform == "darwin":
        libc = _macos_libc()
        cpath = str(path).encode()
        size = libc.listxattr(cpath, None, 0, 0)
        if size > 0:
            buf = ctypes.create_string_buffer(size)
            if libc.listxattr(cpath, buf, size, 0) >= 0:
                for item in buf.raw[:size].split(b"\0"):
                    if not item:
                        continue
                    try:
                        names.append(item.decode("utf-8"))
                    except UnicodeDecodeError:
                        continue

    result: Dict[str, bytes] = {}
    for name in names:
        if not (name.startswith("user.") or name.startswith("com.apple.")):
            continue
        if "\x00" in name or len(name.encode("utf-8")) > 255:
            continue
        value = _get_xattr_bytes(path, name)
        if value is not None and len(value) <= 64 * 1024:
            result[name] = value
        if len(result) >= 64:
            break
    return result


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
