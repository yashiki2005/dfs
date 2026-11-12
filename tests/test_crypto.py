#!/usr/bin/env python3
"""暗号・署名の性能とフォールバック境界の回帰試験。"""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dfs5.crypto import NS_L4_LOG, ssh_sign, ssh_verify


class SshVerifyTests(unittest.TestCase):
    def test_ed25519_verify_is_in_process(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dfs5_crypto_") as tmp:
            key = Path(tmp) / "key"
            subprocess.run(
                ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
                check=True,
            )
            pub = Path(f"{key}.pub").read_text(encoding="utf-8").strip()
            payload = b"in-process verify"
            signature = ssh_sign(key, NS_L4_LOG, payload)
            with patch(
                "dfs5.crypto.subprocess.run",
                side_effect=AssertionError("ssh_verify must not spawn ssh-keygen"),
            ):
                self.assertTrue(
                    ssh_verify(pub, "ignored-identity", NS_L4_LOG, payload, signature)
                )

    def test_tampered_payload_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dfs5_crypto_") as tmp:
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
