#!/usr/bin/env python3
"""
dfs.fs
OS のファイルシステム抽象 (CoW があれば CoW、無ければ OS 既定) のラッパ。

dfs の L5 (ローカル実体化・スナップショット) は、このパッケージだけに依存する。
呼び出し側は OS 固有の CoW API (clonefile / FICLONE / block clone) を意識せず、
``FileSystem`` の ``snapshot`` / ``clone`` / ``materialize`` を使う。

設計方針:
  * 既定は ``copy`` (実コピー)。どこでも動くことを最優先する。
  * OS が CoW を提供するなら自動でそちらを選ぶ (reflink / clonefile / block clone)。
  * CoW は「速さ・容量」のための最適化であり、正しさの前提にしない。
    スナップショットは常に独立した実体として読めることを保証する。
"""

from .api import default_backend, fs, snapshot, supports_cow
from .core import (
    BackendInfo,
    Capability,
    CopyBackend,
    FileSystem,
    SnapshotResult,
    detect_backends,
    default_backend_name,
)

__all__ = [
    "BackendInfo",
    "Capability",
    "CopyBackend",
    "FileSystem",
    "SnapshotResult",
    "detect_backends",
    "default_backend_name",
    "fs",
    "snapshot",
    "default_backend",
    "supports_cow",
]
