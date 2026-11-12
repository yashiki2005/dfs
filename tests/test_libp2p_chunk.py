#!/usr/bin/env python3
"""libp2p/QUIC chunk source の試験（サーバは別プロセス）。"""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dfs.crypto import ChunkIntegrityError
from dfs.l2_registry import ServiceUnavailableError
from dfs.libp2p_chunk import Libp2pChunkClient


class TestLibp2pChunkSource(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="dfs_libp2p_")
        self.base = Path(self._tmp.name)
        self.chunks = self.base / "chunks"
        self.chunks.mkdir()
        self.store = {}
        for blob in (b"alpha", b"bravo" * 100):
            wid = hashlib.sha256(blob).hexdigest()
            self.store[wid] = blob
            (self.chunks / f"{wid}.blk").write_bytes(blob)

        repo = str(Path(__file__).resolve().parents[1])
        env = dict(os.environ)
        env["PYTHONPATH"] = repo + (
            os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else ""
        )
        self.proc = subprocess.Popen(
            [
                sys.executable, "-m", "dfs.libp2p_chunk",
                "--chunks-dir", str(self.chunks),
                "--listen", "/ip4/127.0.0.1/udp/0/quic-v1",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        )
        self.addCleanup(self._stop)
        line = self.proc.stdout.readline().strip()
        if not line.startswith("READY "):
            err = self.proc.stderr.read()
            self.skipTest(f"libp2p QUIC unavailable: {line} {err}")
        self.addr = line[len("READY ") :]
        self.client = Libp2pChunkClient([self.addr]).start()
        self.addCleanup(self.client.close)

    def _stop(self) -> None:
        self.proc.terminate()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        self._tmp.cleanup()

    def test_quic_batch_has_and_get(self) -> None:
        ids = sorted(self.store)
        self.assertEqual(self.client.batch_has(ids), {wid: True for wid in ids})
        self.assertEqual(self.client.batch_get(ids), self.store)
        self.assertEqual(self.client.get(ids[0]), self.store[ids[0]])

    def test_missing_chunk_is_rejected(self) -> None:
        missing = hashlib.sha256(b"missing").hexdigest()
        self.assertFalse(self.client.batch_has([missing])[missing])
        with self.assertRaises(ChunkIntegrityError):
            self.client.batch_get([missing])

    def test_source_is_read_only(self) -> None:
        with self.assertRaises(ServiceUnavailableError):
            self.client.batch_put_if_absent({"x": b"y"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
