#!/usr/bin/env python3
"""版単位 archive bundle と torrent の試験。"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dfs import cli as cli_mod
from dfs import cli_main
from dfs.archive import (
    ArchiveError,
    bencode,
    catalog,
    create_archive,
    download_torrent,
    extract_bundle,
    verify_bundle,
)
from dfs.l1_delegation import create_delegation_envelope
from dfs.l2_registry import DirectoryRegistryService
from dfs.l3_store import ChunkStoreServer
from dfs.l5_fs import DFSNode
from dfs.remotes import Remote, RemoteStore


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

    def test_torrent_download_uses_external_cli_dht(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dfs_bt_cli_") as tmp:
            base = Path(tmp)
            if os.name == "nt":
                executable = base / "aria2c.cmd"
                executable.write_text("@echo off\r\n", encoding="utf-8")
            else:
                executable = base / "aria2c"
                executable.write_text("#!/bin/sh\n", encoding="utf-8")
            executable.chmod(0o700)
            completed = subprocess.CompletedProcess([], 0, "", "")
            with patch("dfs.archive.subprocess.run", return_value=completed) as run:
                download_torrent(
                    "magnet:?xt=urn:btih:" + "a" * 40,
                    base / "downloads",
                    torrent_client=str(executable),
                )
            command = run.call_args.args[0]
            self.assertIn("--enable-dht=true", command)
            self.assertEqual(command[-1], "magnet:?xt=urn:btih:" + "a" * 40)


class TestArchive(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="dfs_archive_")
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
        self.node = DFSNode(
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
        self.node.close()
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
        self.assertEqual(meta["kdf"], "scrypt-v1")
        out = self.base / "restored"
        extract_bundle(bundle, out, "archive-secret")
        self.assertEqual((out / "note.txt").read_text(encoding="utf-8"), "archived")

    def test_legacy_archive_without_kdf_uses_legacy_derivation(self) -> None:
        bundle = self.base / "legacy_bundle"
        out = self.base / "legacy_restored"
        with (
            patch(
                "dfs.archive.verify_bundle",
                return_value={
                    "root_plain_id": "aa" * 32,
                    "root_wire_id": "bb" * 32,
                },
            ),
            patch("dfs.archive.MerkleTreeBuilder") as builder_cls,
        ):
            extract_bundle(bundle, out, "archive-secret")
        crypto = builder_cls.call_args.args[0]
        self.assertEqual(crypto.kdf_version, "legacy-sha256-v1")

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
        self.assertNotEqual(cli_main.main(["archive", "verify", str(bundle)]), 0)
        self.assertEqual(
            cli_main.main(["archive", "verify", str(bundle), "--root-pubkey", self.root_pub]),
            0,
        )
        self.assertEqual(
            cli_main.main(["archive", "verify", str(bundle), "--allow-embedded-root"]),
            0,
        )

    def test_history_and_specific_version_archive(self) -> None:
        (self.node.clayfs.work_tree / "note.txt").write_text(
            "version 2", encoding="utf-8"
        )
        self.node.push(delegation_epoch=1, now=self.now + 1)

        rows = self.reg.history(self.path)
        self.assertEqual([row["version"] for row in rows], [2, 1])
        _old_del, old_locator, old_head = self.reg.resolve(self.path, version=1)
        self.assertEqual(old_head["payload"]["version"], 1)
        self.assertIsNone(old_locator)
        with self.assertRaises(Exception):
            self.reg.resolve(self.path, version=99)

        bundle = self.base / "bundle_v1"
        result = create_archive(self.node, bundle, version=1)
        self.assertEqual(result.version, 1)
        meta = verify_bundle(bundle)
        self.assertEqual(meta["version"], 1)
        out = self.base / "restored_v1"
        extract_bundle(bundle, out, "archive-secret")
        self.assertEqual(
            (out / "note.txt").read_text(encoding="utf-8"), "archived"
        )
        rows = catalog(self.base)
        self.assertTrue(any(row["version"] == 1 for row in rows))

    def test_signed_descriptor_is_bound_to_l4_and_replicated(self) -> None:
        result = create_archive(self.node, self.base / "bundle_publish")
        verified = self.reg.register_archive(result.descriptor_envelope, now=self.now)
        self.assertEqual(verified["version"], 1)
        self.assertEqual(
            self.reg.list_archives(self.path)[0]["payload"]["infohash"],
            result.infohash,
        )

        replica = DirectoryRegistryService("/example.com", self.root_pub)
        self.assertTrue(
            replica.ingest_replica(
                self.reg.replication_bundle(self.path), now=self.now
            )
        )
        self.assertEqual(
            replica.list_archives(self.path)[0]["payload"]["infohash"],
            result.infohash,
        )

        tampered = json.loads(json.dumps(result.descriptor_envelope))
        tampered["payload"]["infohash"] = "f" * 40
        with self.assertRaises(ArchiveError):
            self.reg.register_archive(tampered, now=self.now)

        state_dir = self.base / "archive_state"
        pstate = cli_mod.PersistentRegistryState(
            state_dir, "/example.com", self.root_pub
        )
        pstate.service = self.reg
        pstate.save()
        loaded = cli_mod.PersistentRegistryState(
            state_dir, "/example.com", self.root_pub
        )
        self.assertEqual(
            loaded.service.list_archives(self.path)[0]["payload"]["infohash"],
            result.infohash,
        )

    def test_archive_fetch_uses_registry_config_not_dnssec(self) -> None:
        bundle = self.base / "bundle_fetch"
        result = create_archive(self.node, bundle)
        state_dir = self.base / "registry_http"
        pstate = cli_mod.PersistentRegistryState(
            state_dir, "/example.com", self.root_pub
        )
        pstate.service = self.reg
        pstate.ost_endpoint = f"tls://127.0.0.1:{self.ost.port}"
        handler = cli_mod.make_registry_http_handler(pstate, self.ost)
        httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(httpd.server_close)
        self.addCleanup(httpd.shutdown)

        config_file = self.base / "remotes.json"
        old_config = os.environ.get("DFS_CONFIG")
        os.environ["DFS_CONFIG"] = str(config_file)

        def restore_config() -> None:
            if old_config is None:
                os.environ.pop("DFS_CONFIG", None)
            else:
                os.environ["DFS_CONFIG"] = old_config

        self.addCleanup(restore_config)
        registry_url = f"http://127.0.0.1:{httpd.server_address[1]}"
        store = RemoteStore(config_file)
        store.set(
            Remote(
                name="r",
                registry=registry_url,
                key=str(self.alice_key),
                secret="archive-secret",
                path=self.path,
                root_pubkey=self.root_pub,
            )
        )
        self.assertEqual(
            cli_main.main(["--remote", "r", "archive", "publish", str(bundle)]),
            0,
        )

        download_dir = self.base / "downloads"
        restored = self.base / "restored_fetch"

        def fake_download(magnet: str, out: Path | str, **_kwargs) -> Path:
            self.assertIn(result.infohash, magnet)
            target = Path(out) / "torrent-root"
            shutil.copytree(bundle, target)
            return Path(out)

        with patch("dfs.cli_main.download_torrent", side_effect=fake_download):
            self.assertEqual(
                cli_main.main([
                    "archive", "fetch", "r:",
                    "--version", "1",
                    "--out", str(download_dir),
                    "--secret", "archive-secret",
                    str(restored),
                ]),
                0,
            )
        self.assertEqual(
            (restored / "note.txt").read_text(encoding="utf-8"),
            "archived",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
