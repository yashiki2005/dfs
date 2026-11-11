#!/usr/bin/env python3
"""秘密情報を含む設定ファイルを安全に書くための小さなヘルパー。"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

from .paths import restrict_to_owner


def ensure_private_dir(path: Path, mode: int = 0o700) -> None:
    """ディレクトリを作成し、既存であっても権限を ``mode`` に補正する。"""
    path.mkdir(parents=True, exist_ok=True, mode=mode)
    try:
        os.chmod(path, mode)
    except OSError:
        # 共有ストレージ等で chmod できない場合でも、書き込み自体は続ける。
        pass


def write_private_json(path: Path, data: Any, mode: int = 0o600) -> None:
    """JSON を一時ファイル経由でアトミックに書き、所有者だけが読める権限にする。"""
    ensure_private_dir(path.parent)
    text = json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent)
    )
    tmp = Path(tmp_name)
    try:
        os.chmod(tmp, mode)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        if mode == 0o600:
            restrict_to_owner(path)
        else:
            os.chmod(path, mode)
    finally:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass
