#!/usr/bin/env python3
"""暗号・署名の性能とフォールバック境界の回帰試験。"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dfs.crypto import ContentAddressedCrypto, NS_L4_LOG, ssh_sign, ssh_verify


class SshVerifyTests(unittest.TestCase):
    def test_ed25519_verify_is_in_process(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dfs_crypto_") as tmp:
            key = Path(tmp) / "key"
            subprocess.run(
                ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
                check=True,
            )
            pub = Path(f"{key}.pub").read_text(encoding="utf-8").strip()
            payload = b"in-process verify"
            signature = ssh_sign(key, NS_L4_LOG, payload)
            with patch(
                "dfs.crypto.subprocess.run",
                side_effect=AssertionError("ssh_verify must not spawn ssh-keygen"),
            ):
                self.assertTrue(
                    ssh_verify(pub, "ignored-identity", NS_L4_LOG, payload, signature)
                )

    def test_tampered_payload_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dfs_crypto_") as tmp:
            key = Path(tmp) / "key"
            subprocess.run(
                ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
                check=True,
            )
            pub = Path(f"{key}.pub").read_text(encoding="utf-8").strip()
            signature = ssh_sign(key, NS_L4_LOG, b"original")
            self.assertFalse(
                ssh_verify(pub, "ignored-identity", NS_L4_LOG, b"tampered", signature)
            )


class ChunkCompressionTests(unittest.TestCase):
    def test_zstd_roundtrip_and_codec(self) -> None:
        crypto = ContentAddressedCrypto("compression-test")
        plaintext = b"source code and log lines\n" * 20000
        pid, wid, blob = crypto.pack_chunk(plaintext, compression="zstd")
        self.assertTrue(blob.startswith(crypto.MAGIC_HEADER_V3))
        self.assertEqual(crypto.chunk_codec(blob), "zstd")
        self.assertLess(len(blob), len(plaintext))
        self.assertEqual(crypto.unpack_chunk(pid, wid, blob), plaintext)

    def test_incompressible_data_falls_back_to_plain_chunk(self) -> None:
        crypto = ContentAddressedCrypto("compression-test")
        plaintext = os.urandom(64 * 1024)
        pid, wid, blob = crypto.pack_chunk(plaintext, compression="zstd")
        self.assertTrue(blob.startswith(crypto.MAGIC_HEADER))
        self.assertEqual(crypto.chunk_codec(blob), "none")
        self.assertEqual(crypto.unpack_chunk(pid, wid, blob), plaintext)


if __name__ == "__main__":
    unittest.main(verbosity=2)
