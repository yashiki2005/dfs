#!/usr/bin/env python3
"""L2 名簿の読み取りキャッシュ。

registry がすべて停止しても、直前に検証済みだった delegation / locator /
head を使って読み取りを継続する。保存するのは L4 の検証を通過した応答だけで、
読み出し時にも期限と署名を再検証する。
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from .crypto import normalize_path
from .l2_registry import ServiceUnavailableError
from .private_io import write_private_json

CACHE_SCHEMA = "dfs5-l2-cache-v1"


class L2Cache:
    """``.clayfs/l2_cache.json`` に保存する小さな読み取りキャッシュ。"""

    def __init__(self, path: Path | str):
        self.path = Path(path)

    def _read(self) -> Dict[str, Any]:
        if not self.path.is_file():
            return {"schema": CACHE_SCHEMA, "paths": {}}
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError):
            return {"schema": CACHE_SCHEMA, "paths": {}}
        if not isinstance(data, dict) or data.get("schema") != CACHE_SCHEMA:
            return {"schema": CACHE_SCHEMA, "paths": {}}
        paths = data.get("paths")
        if not isinstance(paths, dict):
            paths = {}
        return {"schema": CACHE_SCHEMA, "paths": paths}

    @staticmethod
    def _delegation_is_current(envelope: Dict[str, Any], now: int) -> bool:
        if not isinstance(envelope, dict):
            return False
        chain = envelope.get("chain") or [envelope]
        if not isinstance(chain, list) or not chain:
            return False
        for item in chain:
            if not isinstance(item, dict):
                return False
            payload = item.get("payload")
            if not isinstance(payload, dict):
                return False
            try:
                issued_at = int(payload["issued_at"])
                expires_at = int(payload["expires_at"])
            except (KeyError, TypeError, ValueError):
                return False
            if not (issued_at <= now < expires_at):
                return False
        return True

    def load(
        self, path: str, now: Optional[int] = None
    ) -> Optional[Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]], Dict[str, Any]]]:
        """期限内のキャッシュを返す。壊れている・期限切れなら ``None``。"""
        current = int(time.time()) if now is None else int(now)
        try:
            norm_path = normalize_path(path)
        except ValueError:
            return None
        entry = self._read()["paths"].get(norm_path)
        if not isinstance(entry, dict):
            return None

        delegation = entry.get("delegation")
        locator = entry.get("locator")
        head = entry.get("head_log")
        if not isinstance(head, dict) or not isinstance(delegation, dict):
            return None
        if not self._delegation_is_current(delegation, current):
            return None
        if locator is not None:
            if not isinstance(locator, dict):
                return None
            payload = locator.get("payload")
            if not isinstance(payload, dict):
                return None
            try:
                expires_at = int(payload["expires_at"])
            except (KeyError, TypeError, ValueError):
                return None
            if current >= expires_at:
                return None
        return delegation, locator, head

    def store(
        self,
        path: str,
        delegation: Optional[Dict[str, Any]],
        locator: Optional[Dict[str, Any]],
        head: Optional[Dict[str, Any]],
        now: Optional[int] = None,
    ) -> None:
        """検証済みの現在 head を保存する。"""
        if not delegation or not head:
            return
        norm_path = normalize_path(path)
        data = self._read()
        data["paths"][norm_path] = {
            "delegation": delegation,
            "fetched_at": int(time.time()) if now is None else int(now),
            "head_log": head,
            "locator": locator,
        }
        write_private_json(self.path, data)


class CachedRegistryClient:
    """``RemoteRegistryClient`` の読み取りだけをキャッシュするラッパー。

    書き込み系は inner client にそのまま委譲する。``resolve(version=...)`` は
    過去版の取得なのでキャッシュを使わない。
    """

    def __init__(self, inner: Any, cache_path: Path | str):
        self.inner = inner
        self.cache = L2Cache(cache_path)
        self.last_cache_hit = False

    def __getattr__(self, name: str) -> Any:
        return getattr(self.inner, name)

    def resolve(
        self, path: str, version: Optional[int] = None
    ) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
        self.last_cache_hit = False
        try:
            return self.inner.resolve(path, version=version)
        except ServiceUnavailableError:
            if version is not None:
                raise
            cached = self.cache.load(path)
            if cached is None:
                raise
            self.last_cache_hit = True
            print(
                f"[dfs5] L2 registry unavailable; using verified cache for {path}",
                file=sys.stderr,
            )
            return cached

    def cache_verified(
        self,
        path: str,
        delegation: Optional[Dict[str, Any]],
        locator: Optional[Dict[str, Any]],
        head: Optional[Dict[str, Any]],
        now: Optional[int] = None,
    ) -> None:
        """L4 の署名検証が通った応答を保存する（呼び出し側の明示操作）。"""
        self.cache.store(path, delegation, locator, head, now=now)
