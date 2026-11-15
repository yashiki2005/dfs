"""pytest共通の後始末。

WindowsではSQLite索引を開いたまま一時ディレクトリを削除できない。
DFSの作業ツリーを含むTemporaryDirectoryを消す直前に、開いている
DFSNodeをすべてcloseしてファイルハンドルを解放する。
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from dfs.l4_log import MerkleTreeBuilder
from dfs.l5_fs import DFSNode


_ORIGINAL_CLEANUP = tempfile.TemporaryDirectory.cleanup


def _cleanup_with_dfs_nodes(directory: tempfile.TemporaryDirectory) -> None:
    root = Path(directory.name)
    try:
        has_dfs_tree = root.is_dir() and any(root.rglob(".clayfs"))
        has_index = root.is_dir() and any(root.rglob("ost_index.json"))
    except OSError:
        has_dfs_tree = False
        has_index = False
    if has_dfs_tree or has_index:
        DFSNode.close_all()
        MerkleTreeBuilder.close_all()
    _ORIGINAL_CLEANUP(directory)


tempfile.TemporaryDirectory.cleanup = _cleanup_with_dfs_nodes
