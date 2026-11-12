#!/usr/bin/env python3
"""版単位 archive bundle と torrent の試験。"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dfs5 import cli_main
from dfs5.archive import (
    ArchiveError,
    bencode,
    create_archive,
    extract_bundle,
    verify_bundle,
)
from dfs5.l1_delegation import create_delegation_envelope
from dfs5.l2_registry import DirectoryRegistryService
from dfs5.l3_store import ChunkStoreServer
from dfs5.l5_clayfs import DFS5Node


def _keypair(base: Path, name: str) -> tuple[Path, str]:
    priv = base / name
    subprocess.run(
        ["ssh-keygen", "-t", "ed25519", "-N", "", "-f", str(priv)],
        check=True,
        capture_output=True,
    )
    return priv, Path(f"{priv}.pub").read_text(encoding="utf-8").strip()


def _cert(base: Path) -> tuple[Path, Path]:
    cert, key = base / "cert.pem", base / "key.pem"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", str(key), "-out", str(cert), "-days", "1",
            "-nodes", "-subj", "/CN=localhost",
        ],
        check=True,
        capture_output=True,
    )
    return cert, key


class TestBencode(unittest.TestCase):
    def test_bencode(self) -> None:
        self.assertEqual(bencode({"a": 1, "b": b"x"}), b"d1:ai1e1:b1:xe")


class TestArchive(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="dfs5_archive_")
        self.base = Path(self._tmp.name)
        self.root_key, self.root_pub = _keypair(self.base, "root")
        self.alice_key, self.alice_pub = _keypair(self.base, "alice")
        self.cert, self.key = _cert(self.base)
        self.ost = ChunkStoreServer(self.cert, self.key)
        self.addCleanup(self.ost.close)
        self.now = int(time.time())
        self.path = "/example.com/alice"
        self.reg = DirectoryRegistryService("/example.com", self.root_pub)
        self.reg.register_delegation(
            create_delegation_envelope(
                self.root_key,
                "/example.com",
                self.path,
                self.alice_pub,
                1,
                0,
                self.now - 60,
                self.now + 10000,
            ),
            now=self.now,
        )
        self.node = DFS5Node(
            "alice",
            self.path,
            self.base / "mount",
            self.alice_key,
            self.alice_pub,
            "archive-secret",
            self.reg,
            "127.0.0.1",
            self.ost.port,
            root_pubkey=self.root_pub,
        )
        (self.node.clayfs.work_tree / "note.txt").write_text(
            "archived", encoding="utf-8"
        )
        self.node.push(delegation_epoch=1, now=self.now)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_create_verify_and_extract(self) -> None:
        bundle = self.base / "bundle"
        result = create_archive(self.node, bundle)
        self.assertEqual(result.version, 1)
        self.assertEqual(len(result.infohash), 40)
        self.assertTrue(result.torrent.is_file())
        self.assertTrue((bundle / "meta.json").is_file())
        self.assertTrue(any((bundle / "chunks").iterdir()))

        meta = verify_bundle(bundle)
        self.assertEqual(meta["version"], 1)
        out = self.base / "restored"
        extract_bundle(bundle, out, "archive-secret")
        self.assertEqual((out / "note.txt").read_text(encoding="utf-8"), "archived")

    def test_tampered_chunk_is_rejected(self) -> None:
        bundle = self.base / "bundle_tamper"
        create_archive(self.node, bundle)
        chunk = next((bundle / "chunks").iterdir())
        chunk.write_bytes(chunk.read_bytes() + b"x")
        with self.assertRaises(ArchiveError):
            verify_bundle(bundle)

    def test_meta_contains_signed_metadata(self) -> None:
        bundle = self.base / "bundle_meta"
        create_archive(self.node, bundle)
        meta = json.loads((bundle / "meta.json").read_text(encoding="utf-8"))
        self.assertIn("delegation", meta)
        self.assertIn("head_log", meta)
        self.assertEqual(meta["root_pubkey"], self.root_pub)
        self.assertEqual(meta["path"], self.path)

    def test_verify_cli(self) -> None:
        bundle = self.base / "bundle_cli"
        create_archive(self.node, bundle)
        self.assertEqual(cli_main.main(["archive", "verify", str(bundle)]), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
