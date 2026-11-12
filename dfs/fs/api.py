#!/usr/bin/env python3
"""
dfs/fs/api.py
``FileSystem`` の薄いファサード。1 行で CoW 検出とスナップショットができる。

    from dfs.fs import fs
    f = fs("/path/to/mount")
    print(f.info())              # {'backend': 'reflink', 'cow': True, ...}
    f.take_snapshot("v1")
"""

from __future__ import annotations

from pathlib import Path
from typing import Sequence

from .core import FileSystem, SnapshotResult


def fs(
    root: Path | str,
    backend: str = "auto",
    ignore: Sequence[str] = (),
) -> FileSystem:
    """ルートディレクトリの ``FileSystem`` を作る。"""
    return FileSystem(root, backend=backend, ignore=ignore)


def snapshot(root: Path | str, snap_id: str, backend: str = "auto") -> SnapshotResult:
    """``root`` の作業ツリーを ``snap_id`` としてスナップショットする。"""
    return FileSystem(root, backend=backend).take_snapshot(snap_id)


def default_backend(root: Path | str) -> str:
    """そのディレクトリで選ばれるバックエンド名を返す (実測)。"""
    return FileSystem(root, backend="auto").backend.name


def supports_cow(root: Path | str) -> bool:
    """そのディレクトリで CoW が使えるか。"""
    return FileSystem(root, backend="auto").is_cow
