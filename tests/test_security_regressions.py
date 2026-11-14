#!/usr/bin/env python3
"""今回塞いだ境界不備の回帰試験。"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dfs import cli as cli_mod
from dfs.cli_main import UsageError, _collect_local, _norm_prefix, apply_writes, cmd_fs
from dfs.crypto import (
    EMPTY_SHA256,
    NS_L4_LOG,
    ContentAddressedCrypto,
    ChunkIntegrityError,
    canonical_json,
    sha256_hex,
    ssh_sign,
)
from dfs.fs import FileSystem
from dfs.l1_delegation import (
    DelegationError,
    create_delegation_envelope,
    verify_delegation_chain,
)
from dfs.l2_registry import (
    ConflictError,
    DirectoryRegistryService,
    create_locator_envelope,
)
from dfs.l4_log import L4LogClient, MerkleTreeBuilder
from dfs.path_safety import UnsafePathError, copyfile_no_follow, safe_target


def _keypair(base: Path, name: str) -> tuple[Path, str]:
    priv = base / name
    subprocess.run(
        ["ssh-keygen", "-t", "ed25519", "-N", "", "-C", f"{name}@test", "-f", str(priv)],
        check=True,
        capture_output=True,
    )
    return priv, Path(f"{priv}.pub").read_text(encoding="utf-8").strip()


class _FakeOST:
    """MerkleTreeBuilder の試験用に必要なメソッドだけを持つ OST。"""

    def __init__(self) -> None:
        self.chunks: dict[str, bytes] = {}

    def batch_has(self, wire_ids):
        return {wid: wid in self.chunks for wid in wire_ids}

    def batch_put_if_absent(self, chunks, assume_absent: bool = False):
        self.chunks.update(chunks)
        return len(chunks)

    def batch_get(self, wire_ids):
        return {wid: self.chunks[wid] for wid in wire_ids if wid in self.chunks}


class TestL4PathBinding(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="dfs_pathbind_")
        self.base = Path(self._tmp.name)
        self.root_key, self.root_pub = _keypair(self.base, "root")
        self.alice_key, self.alice_pub = _keypair(self.base, "alice")
        self.now = int(time.time())
        self.reg = DirectoryRegistryService("/example.com", self.root_pub)
        self.reg.register_delegation(
            create_delegation_envelope(
                self.root_key,
                "/example.com",
                "/example.com/alice",
                self.alice_pub,
                1,
                0,
                self.now - 60,
                self.now + 10000,
            ),
            now=self.now,
        )

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _log(self, path: str, version: int = 1) -> dict:
        payload = {
            "delegation_epoch": 1,
            "parent_hash": EMPTY_SHA256,
            "parent_version": 0,
            "path": path,
            "root_plain_id": "aa" * 32,
            "root_wire_id": "bb" * 32,
            "timestamp": self.now,
            "version": version,
        }
        raw = canonical_json(payload)
        return {
            "entry_hash": sha256_hex(raw),
            "payload": payload,
            "signature": ssh_sign(self.alice_key, NS_L4_LOG, raw),
        }

    def test_registry_rejects_log_path_mismatch(self) -> None:
        log = self._log("/example.com/bob")
        loc = create_locator_envelope(
            self.alice_key,
            "/example.com/alice",
            1,
            1,
            log["entry_hash"],
            ["tls://127.0.0.1:1"],
            self.now + 1000,
        )
        with self.assertRaises(DelegationError):
            self.reg.announce_and_append("/example.com/alice", log, loc, now=self.now)
        self.assertEqual(self.reg.logs.get("/example.com/alice"), None)

    def test_client_rejects_head_path_mismatch(self) -> None:
        del_env, _, _ = self.reg.resolve("/example.com/alice")
        self.assertIsNotNone(del_env)
        log = self._log("/example.com/bob")

        class Reg:
            def resolve(self, _path):
                return del_env, None, log

        client = L4LogClient(
            "/example.com/alice",
            self.alice_key,
            self.alice_pub,
            pin_file=self.base / "pin.json",
            root_pubkey=self.root_pub,
        )
        with self.assertRaises(ChunkIntegrityError):
            client.sync_head(Reg())

    def test_chain_leaf_must_match_requested_path(self) -> None:
        d1 = create_delegation_envelope(
            self.root_key,
            "/example.com",
            "/example.com/alice",
            self.alice_pub,
            1,
            0,
            self.now - 60,
            self.now + 10000,
        )
        with self.assertRaises(DelegationError):
            verify_delegation_chain(
                "/example.com",
                self.root_pub,
                [d1],
                now=self.now,
                requested_path="/example.com/bob",
            )


class TestCasConcurrency(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="dfs_cas_")
        self.base = Path(self._tmp.name)
        self.root_key, self.root_pub = _keypair(self.base, "root")
        self.alice_key, self.alice_pub = _keypair(self.base, "alice")
        self.now = int(time.time())
        self.reg = DirectoryRegistryService("/example.com", self.root_pub)
        self.reg.register_delegation(
            create_delegation_envelope(
                self.root_key,
                "/example.com",
                "/example.com/alice",
                self.alice_pub,
                1,
                0,
                self.now - 60,
                self.now + 10000,
            ),
            now=self.now,
        )

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_same_version_announce_has_one_winner(self) -> None:
        payload = {
            "delegation_epoch": 1,
            "parent_hash": EMPTY_SHA256,
            "parent_version": 0,
            "path": "/example.com/alice",
            "root_plain_id": "aa" * 32,
            "root_wire_id": "bb" * 32,
            "timestamp": self.now,
            "version": 1,
        }
        raw = canonical_json(payload)
        log = {
            "entry_hash": sha256_hex(raw),
            "payload": payload,
            "signature": ssh_sign(self.alice_key, NS_L4_LOG, raw),
        }
        loc = create_locator_envelope(
            self.alice_key,
            "/example.com/alice",
            1,
            1,
            log["entry_hash"],
            ["tls://127.0.0.1:1"],
            self.now + 1000,
        )
        threads = 16
        barrier = threading.Barrier(threads)
        results: list[type[BaseException] | None] = []
        results_lock = threading.Lock()

        def worker() -> None:
            barrier.wait()
            try:
                self.reg.announce_and_append(
                    "/example.com/alice", log, loc, now=self.now
                )
                outcome = None
            except BaseException as e:  # 失敗型をそのまま比較する
                outcome = type(e)
            with results_lock:
                results.append(outcome)

        workers = [threading.Thread(target=worker) for _ in range(threads)]
        for t in workers:
            t.start()
        for t in workers:
            t.join(timeout=10)

        self.assertEqual(results.count(None), 1)
        self.assertEqual(results.count(ConflictError), threads - 1)
        entries = self.reg.logs["/example.com/alice"]
        self.assertEqual(len(entries), 1)
        self.assertEqual([e["payload"]["version"] for e in entries], [1])


class TestSymlinkBoundaries(unittest.TestCase):
    def test_collect_local_skips_source_symlinks(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dfs_sym_collect_") as tmp:
            base = Path(tmp)
            source = base / "source"
            source.mkdir()
            outside = base / "outside.txt"
            outside.write_text("OUTSIDE-SECRET", encoding="utf-8")
            (source / "normal.txt").write_text("normal", encoding="utf-8")
            os.symlink(outside, source / "leak.txt")

            collected = _collect_local(source)
            self.assertEqual(set(collected), {"normal.txt"})
            with self.assertRaises(UsageError):
                _collect_local(source / "leak.txt")

    def test_copyfile_no_follow_rejects_symlink_source(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dfs_sym_source_") as tmp:
            base = Path(tmp)
            outside = base / "outside.txt"
            outside.write_text("OUTSIDE-SECRET", encoding="utf-8")
            source = base / "source.txt"
            os.symlink(outside, source)
            destination = base / "destination.txt"

            with self.assertRaises(UnsafePathError):
                copyfile_no_follow(source, destination)
            self.assertFalse(destination.exists())

    def test_upload_skips_symlink(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dfs_sym_up_") as tmp:
            base = Path(tmp)
            outside = base / "outside.txt"
            outside.write_text("OUTSIDE-SECRET", encoding="utf-8")
            tree = base / "tree"
            tree.mkdir()
            (tree / "normal.txt").write_text("normal", encoding="utf-8")
            os.symlink(outside, tree / "leak.txt")

            ost = _FakeOST()
            builder = MerkleTreeBuilder(ContentAddressedCrypto("secret"), ost)
            root_pid, root_wid = builder.upload_directory(tree)
            self.assertTrue(any("leak.txt" in w for w in builder.warnings))

            out = base / "out"
            builder.download_directory(root_pid, root_wid, out)
            self.assertEqual((out / "normal.txt").read_text(encoding="utf-8"), "normal")
            self.assertFalse((out / "leak.txt").exists())

    def test_safe_target_rejects_symlink_directory(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dfs_sym_write_") as tmp:
            base = Path(tmp)
            root = base / "root"
            outside = base / "outside"
            root.mkdir()
            outside.mkdir()
            os.symlink(outside, root / "escape")
            with self.assertRaises(UnsafePathError):
                safe_target(root, "escape/pwned.txt", create_parents=True)
            self.assertFalse((outside / "pwned.txt").exists())

    def test_copyfile_no_follow_rejects_symlink_destination(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dfs_sym_copy_") as tmp:
            base = Path(tmp)
            src = base / "src.txt"
            outside = base / "outside.txt"
            root = base / "root"
            root.mkdir()
            src.write_text("new", encoding="utf-8")
            outside.write_text("old", encoding="utf-8")
            os.symlink(outside, root / "leak.txt")

            with self.assertRaises(UnsafePathError):
                copyfile_no_follow(src, root / "leak.txt")
            self.assertEqual(outside.read_text(encoding="utf-8"), "old")

    def test_apply_writes_rejects_symlink_path(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dfs_sym_apply_") as tmp:
            base = Path(tmp)
            root = base / "root"
            outside = base / "outside"
            root.mkdir()
            outside.mkdir()
            os.symlink(outside, root / "escape")
            src = base / "src.txt"
            src.write_text("payload", encoding="utf-8")

            node = SimpleNamespace(clayfs=SimpleNamespace(work_tree=root))
            with self.assertRaises(UsageError):
                apply_writes(node, [("escape/pwned.txt", src, "add")])
            self.assertFalse((outside / "pwned.txt").exists())


class TestSnapshotAndPrefixValidation(unittest.TestCase):
    def test_snapshot_id_rejects_parent_traversal(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dfs_snap_id_") as tmp:
            root = Path(tmp)
            f = FileSystem(root, backend="copy")
            with self.assertRaises(ValueError):
                f.take_snapshot("../escaped")
            with self.assertRaises(ValueError):
                f.read_snapshot("../escaped")

    def test_cli_snapshot_rejects_parent_traversal(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dfs_snap_cli_") as tmp:
            root = Path(tmp)
            args = SimpleNamespace(
                action="snapshot",
                path=str(root),
                backend="copy",
                snap_id="../escaped",
                src=None,
                dst=None,
            )
            with self.assertRaises(UsageError):
                cmd_fs(args)

    def test_norm_prefix_rejects_parent(self) -> None:
        with self.assertRaises(UsageError):
            _norm_prefix("../../outside")
        with self.assertRaises(UsageError):
            _norm_prefix("docs/../outside")


class TestServerClock(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="dfs_clock_")
        self.base = Path(self._tmp.name)
        self.root_key, self.root_pub = _keypair(self.base, "root")
        self.alice_key, self.alice_pub = _keypair(self.base, "alice")
        self.pstate = cli_mod.PersistentRegistryState(
            self.base / "state", "/example.com", self.root_pub
        )
        handler = cli_mod.make_registry_http_handler(self.pstate, None)
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self._tmp.cleanup()

    def test_client_supplied_now_cannot_extend_expired_delegation(self) -> None:
        now = int(time.time())
        env = create_delegation_envelope(
            self.root_key,
            "/example.com",
            "/example.com/alice",
            self.alice_pub,
            1,
            0,
            now - 1000,
            now - 500,
        )
        client = cli_mod.RemoteRegistryClient(f"http://127.0.0.1:{self.port}")
        with self.assertRaises(DelegationError):
            client.register_delegation(env, now=now - 700)

    def test_oversized_body_is_rejected_before_read(self) -> None:
        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as sock:
            sock.sendall(
                b"POST /v1/delegate HTTP/1.0\r\n"
                b"Content-Length: 999999999\r\n"
                b"\r\n"
            )
            response = sock.recv(4096)
        self.assertIn(b"413", response.split(b"\r\n", 1)[0])

    def test_incomplete_body_times_out(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        handler = cli_mod.make_registry_http_handler(self.pstate, None)
        handler.request_timeout = 0.2
        self.httpd = cli_mod.BoundedThreadingHTTPServer(
            ("127.0.0.1", 0), handler, max_workers=4
        )
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

        with socket.create_connection(("127.0.0.1", self.port), timeout=2) as sock:
            sock.sendall(
                b"POST /v1/resolve HTTP/1.0\r\n"
                b"Content-Length: 100\r\n"
                b"\r\n"
            )
            sock.settimeout(2)
            response = sock.recv(4096)
        self.assertIn(b"408", response.split(b"\r\n", 1)[0])

    def test_copyfile_no_follow_rejects_symlink_dst_cleanly(self) -> None:
        from dfs.path_safety import UnsafePathError, copyfile_no_follow

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src = root / "src.txt"
            target = root / "target.txt"
            dst = root / "dst_link"
            src.write_bytes(b"hello")
            target.write_bytes(b"keep")
            dst.symlink_to(target)
            with self.assertRaises(UnsafePathError):
                copyfile_no_follow(src, dst)
            self.assertEqual(target.read_bytes(), b"keep")

    def test_failover_ost_session_propagates_body_service_unavailable(self) -> None:
        from contextlib import contextmanager
        from dfs.l2_registry import ServiceUnavailableError
        from dfs.l3_ost_adapter import FailoverOSTClient

        class _DummyClient:
            host = "127.0.0.1"
            port = 1
            bytes_sent = 0
            bytes_received = 0
            blob_bytes_sent = 0
            round_trips = 0
            tls_handshakes = 0
            put_count = 0
            get_count = 0

            def reset_metrics(self) -> None:
                pass

            @contextmanager
            def session(self):
                yield self

        failover = FailoverOSTClient([_DummyClient(), _DummyClient()])  # type: ignore[list-item]
        with self.assertRaises(ServiceUnavailableError):
            with failover.session():
                raise ServiceUnavailableError("primary went offline during write")

    def test_verified_writer_rejects_missing_delegation_when_root_pinned(self) -> None:
        from dfs.l1_delegation import DelegationError
        from dfs.l4_log import L4LogClient

        client = L4LogClient(
            "/example.com/team",
            Path("/nonexistent/key"),
            "ssh-ed25519 AAAA",
            root_pubkey="ssh-ed25519 AAAAroot",
        )
        with self.assertRaises(DelegationError):
            client._verified_writer(None)


if __name__ == "__main__":
    unittest.main(verbosity=2)
