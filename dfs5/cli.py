#!/usr/bin/env python3
"""
dfs5/cli.py
Mac と raspi5 のターミナルから直接実行できる dfs5 CLI エントリポイント。

サブコマンド:
  - serve    : L2 名簿 (HTTP JSON RPC) と L3 OST (TLS/TCP) デーモンを起動
  - delegate : L1 権威の委譲レコードを作成・署名し、L2 名簿へ登録
  - init     : ローカルのマウントディレクトリ (.clayfs / tree / config.json) を初期化
  - push     : L5 スナップショット取得 -> L3 暗号化チャンク転送 -> L4 CAS コミット & B7 照合
  - pull     : L2/L4 先頭版同期 (B6 検証) -> L3 チャンク取得・復号 -> L5 作業ツリー更新
  - status   : ローカルの HeadPin 状態とリモートの先頭版を比較表示
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from dfs5.crypto import ChunkIntegrityError, normalize_path
    from dfs5.l1_delegation import DelegationError, create_delegation_envelope
    from dfs5.l2_registry import (
        ConflictError,
        DirectoryRegistryService,
        RegistryError,
        ServiceUnavailableError,
    )
    from dfs5.l3_ost_adapter import MiniLustreOSTServer
    from dfs5.l4_log import RollbackDetectedError, SilentDropDetectedError
    from dfs5.l5_clayfs import DFS5Node
else:
    from .crypto import ChunkIntegrityError, normalize_path
    from .l1_delegation import DelegationError, create_delegation_envelope
    from .l2_registry import (
        ConflictError,
        DirectoryRegistryService,
        RegistryError,
        ServiceUnavailableError,
    )
    from .l3_ost_adapter import MiniLustreOSTServer
    from .l4_log import RollbackDetectedError, SilentDropDetectedError
    from .l5_clayfs import DFS5Node


# ==========================================
# リモート L2 名簿 (HTTP JSON RPC) クライアント & サーバ
# ==========================================
class RemoteRegistryClient:
    """
    DirectoryRegistryService と同じメソッドシグネチャを持ち、
    HTTP 経由でリモート（またはローカル）の L2 名簿サーバと通信するクライアント。
    """

    def __init__(self, registry_url: str):
        self.registry_url = registry_url.rstrip("/")

    def _post(self, endpoint: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        url = f"{self.registry_url}{endpoint}"
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            try:
                err_body = json.loads(e.read().decode("utf-8"))
                err_type = err_body.get("error_type", "")
                err_msg = err_body.get("message", str(e))
            except Exception