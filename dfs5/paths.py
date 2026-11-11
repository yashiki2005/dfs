#!/usr/bin/env python3
"""
dfs5/paths.py
OS ごとの保存場所と、秘密ファイルの保護。

* ``DFS5_HOME`` があれば ``~`` の代わりにそれを使う。
  ``Path.home()`` は Windows で ``HOME`` を見ない（``USERPROFILE`` を見る）ため、
  テストや「別の場所に状態を置きたい」用途ではこの環境変数で切り替える。
* ``restrict_to_owner()`` は POSIX なら ``chmod 0600``、Windows なら ACL を
  「今のユーザー + SYSTEM + Administrators」だけに絞る。
  Windows の ``chmod`` は mode bit を変えるだけで実効的な保護にならない。
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

HOME_ENV = "DFS5_HOME"

# 絞り込み後も残す特権（バックアップ・管理用）。SID 直指定で名前解決に依存しない。
_WINDOWS_SYSTEM_SID = "*S-1-5-18"
_WINDOWS_ADMINS_SID = "*S-1-5-32-544"


def dfs5_home() -> Path:
    """dfs5 が「ホーム」として使うディレクトリ。"""
    override = os.environ.get(HOME_ENV)
    if override:
        return Path(override).expanduser()
    return Path.home()


def config_dir() -> Path:
    """``~/.config/dfs5``（Windows でも同じ場所を使う）。"""
    return dfs5_home() / ".config" / "dfs5"


def cache_dir() -> Path:
    """``~/.cache/dfs5``。"""
    return dfs5_home() / ".cache" / "dfs5"


def _windows_user_sid() -> str:
    """今のユーザーの SID。取れなければ空文字。"""
    try:
        res = subprocess.run(
            ["whoami", "/user", "/fo", "csv", "/nh"],
            capture_output=True, text=True, timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    for token in res.stdout.replace('"', " ").replace(",", " ").split():
        if token.startswith("S-1-5-") and token.count("-") >= 6:
            return token
    return ""


def restrict_to_owner(path: Path | str) -> None:
    """秘密を置くファイルを、今のユーザーだけが読めるようにする（best effort）。

    POSIX は ``chmod 0600``。Windows は継承を切って ACL を張り直す。
    失敗しても例外にしない（読めない環境で保存自体を壊さないため）。
    """
    target = Path(path)
    if sys.platform != "win32":
        try:
            os.chmod(target, 0o600)
        except OSError:
            pass
        return

    sid = _windows_user_sid()
    grants = [f"*{sid}:F"] if sid else []
    if not grants:
        user = os.environ.get("USERNAME", "")
        domain = os.environ.get("USERDOMAIN", "")
        if user:
            grants = [f"{domain}\\{user}:F" if domain else f"{user}:F"]
    if not grants:
        return

    try:
        subprocess.run(
            ["icacls", str(target), "/inheritance:r", "/grant:r", *grants,
             _WINDOWS_SYSTEM_SID + ":F", _WINDOWS_ADMINS_SID + ":F"],
            capture_output=True, timeout=15,
        )
    except (OSError, subprocess.SubprocessError):
        pass
