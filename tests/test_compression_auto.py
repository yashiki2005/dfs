#!/usr/bin/env python3
"""既定の圧縮ポリシー (`auto`) の試験。"""

from __future__ import annotations

import builtins
import os

from dfs.compression import VALID_POLICIES, normalize_policy
from dfs.crypto import ContentAddressedCrypto


def test_auto_policy_accepted() -> None:
    assert "auto" in VALID_POLICIES
    assert normalize_policy("auto") == "auto"


def test_pack_chunk_auto_compresses_text_and_skips_random() -> None:
    crypto = ContentAddressedCrypto("auto-test-secret")

    # 圧縮しやすい平文 -> zstd が使われる
    compressible = b'{"key":"value","msg":"hello world"}\n' * 500
    pid1, wid1, blob1 = crypto.pack_chunk(compressible, compression="auto")
    assert crypto.chunk_codec(blob1) == "zstd"
    assert len(blob1) < len(compressible)
    assert crypto.unpack_chunk(pid1, wid1, blob1) == compressible

    # ランダム（非圧縮）バイト列 -> サンプル判定で無圧縮にフォールバック
    incompressible = os.urandom(32768)
    pid2, wid2, blob2 = crypto.pack_chunk(incompressible, compression="auto")
    assert crypto.chunk_codec(blob2) == "none"
    assert crypto.unpack_chunk(pid2, wid2, blob2) == incompressible


def test_pack_chunk_auto_falls_back_when_zstandard_missing(monkeypatch) -> None:
    crypto = ContentAddressedCrypto("auto-fallback-secret")
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "zstandard":
            raise ImportError("no zstandard")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    data = b"compressible text " * 500
    pid, wid, blob = crypto.pack_chunk(data, compression="auto")
    assert crypto.chunk_codec(blob) == "none"
    assert crypto.unpack_chunk(pid, wid, blob) == data
