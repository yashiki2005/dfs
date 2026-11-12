#!/usr/bin/env python3
"""複数名簿フォールバックと主→複製の読み取り可用性試験。"""

from __future__ import annotations

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

from dfs5 import cli as cli_mod
from dfs5.crypto import (
    EMPTY_SHA256,
    NS_L4_LOG,
    canonical_json,
    sha256_hex,
    ssh_sign,
)
from dfs5.l1_delegation import create_delegation_envelope
from dfs5.l2_registry import (
    DirectoryRegistryService,
    create_locator_envelope,
)
from dfs5.remotes import Remote, RemoteStore


def _keypair(base: Path, name: str) -> tuple[Path, str]:
    priv = base / name
    subprocess.run(
        ["ssh-keygen", "-t", "ed25519", "-N", "", "-C", f"{name}@test", "-f", str(priv)],
        check=True,
        capture_output=True,
    )
    return priv, Path(f"{priv}.pub").read_text(encoding="utf-8").strip()


def _make_log(path: str, now: int, key: Path, version: int = 1) -> dict:
    payload = {
        "delegation_epoch": 1,
        "parent_hash": EMPTY_SHA256,
        "parent_version": 0,
        "path": path,
        "root_plain_id": "aa" * 32,
        "root_wire_id": "bb" * 32,
        "timestamp": now,
        "version": version,
    }
    raw = canonical_json(payload)
    return {
        "entry_hash": sha256_hex(raw),
        "payload": payload,
        "signature": ssh_sign(key, NS_L4_LOG, raw),
    }


def _make_locator(key: Path, path: str, log: dict, now: int) -> dict:
    return create_locator_envelope(
        key,
        path,
        1,
        int(log["payload"]["version"]),
        log["entry_hash"],
        ["tls://127.0.0.1:1"],
        now + 1000,
    )


class _DummyOST:
    def __init__(self) -> None:
        self.store: dict[str, bytes] = {}


class _RegistryHTTP:
    def __init__(self, pstate: cli_mod.PersistentRegistryState, ost=None) -> None:
        self.pstate = pstate
        self.ost = ost or _DummyOST()
        handler = cli_mod.make_registry_http_handler(pstate, self.ost)
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.port = self.httpd.server_address[1]
        self.url = f"http://127.0.0.1:{self.port}"
        self._stopped = False
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def stop_http(self) -> None:
        if self._stopped:
            return
        self._stopped = True
        self.httpd.shutdown()
        self.httpd.server_close()

    def close(self) -> None:
        try:
            self.stop_http()
        except Exception:
            pass


class AvailabilityCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="dfs5_avail_")
        self.base = Path(self._tmp.name)
        self.root_key, self.root_pub = _keypair(self.base, "root")
        self.alice_key, self.alice_pub = _keypair(self.base, "alice")
        self.now = int(time.time())
        self.path = "/example.com/alice"
        self.env = create_delegation_envelope(
            self.root_key,
            "/example.com",
            self.path,
            self.alice_pub,
            1,
            0,
            self.now - 60,
            self.now + 10000,
        )
        self.log = _make_log(self.path, self.now, self.alice_key)
        self.loc = _make_locator(self.alice_key, self.path, self.log, self.now)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _registry(self, name: str) -> DirectoryRegistryService:
        reg = DirectoryRegistryService("/example.com", self.root_pub)
        if name == "primary":
            reg.register_delegation(self.env, now=self.now)
        return reg

    def test_remote_registry_alternates_roundtrip(self) -> None:
        path = self.base / "remotes.json"
        store = RemoteStore(path)
        store.set(
            Remote(
                name="r",
                registry="http://primary:9440/",
                registry_alternates=["http://secondary:9440", "http://primary:9440"],
                key=str(self.alice_key),
            )
        )
        loaded = RemoteStore(path).get("r")
        self.assertEqual(loaded.registry_urls(), ["http://primary:9440", "http://secondary:9440"])
        self.assertEqual(loaded.registry_alternates, ["http://secondary:9440", "http://primary:9440"])

    def test_replica_bundle_is_verified_and_idempotent(self) -> None:
        primary = self._registry("primary")
        secondary = self._registry("secondary")
        primary.announce_and_append(self.path, self.log, self.loc, now=self.now)

        bundle = primary.replication_bundle(self.path)
        self.assertIsNotNone(bundle)
        self.assertTrue(secondary.ingest_replica(bundle, now=self.now))
        self.assertEqual(secondary.logs[self.path][-1]["entry_hash"], self.log["entry_hash"])
        self.assertTrue(secondary.ingest_replica(bundle, now=self.now))
        self.assertEqual(len(secondary.logs[self.path]), 1)

    def test_replica_rejects_older_bundle_instead_of_rolling_back(self) -> None:
        primary = self._registry("primary")
        secondary = self._registry("secondary")
        primary.announce_and_append(self.path, self.log, self.loc, now=self.now)
        v1 = primary.replication_bundle(self.path)
        self.assertTrue(secondary.ingest_replica(v1, now=self.now))

        v2_log = _make_log(self.path, self.now + 1, self.alice_key, version=2)
        v2_log["payload"]["parent_version"] = 1
        v2_log["payload"]["parent_hash"] = self.log["entry_hash"]
        raw = canonical_json(v2_log["payload"])
        v2_log["entry_hash"] = sha256_hex(raw)
        v2_log["signature"] = ssh_sign(self.alice_key, NS_L4_LOG, raw)
        v2_loc = _make_locator(self.alice_key, self.path, v2_log, self.now + 1)
        primary.announce_and_append(self.path, v2_log, v2_loc, now=self.now + 1)

        v2 = primary.replication_bundle(self.path)
        self.assertTrue(secondary.ingest_replica(v2, now=self.now + 1))
        self.assertEqual(secondary.logs[self.path][-1]["payload"]["version"], 2)

        # 古い v1 を再送しても、複製名簿を v1 に巻き戻さない。
        self.assertFalse(secondary.ingest_replica(v1, now=self.now + 2))
        self.assertEqual(secondary.logs[self.path][-1]["payload"]["version"], 2)

    def test_read_failover_to_secondary_after_primary_stops(self) -> None:
        primary_service = self._registry("primary")
        secondary_service = self._registry("secondary")
        primary_service.announce_and_append(self.path, self.log, self.loc, now=self.now)
        secondary_service.ingest_replica(
            primary_service.replication_bundle(self.path), now=self.now
        )

        primary = _RegistryHTTP(
            cli_mod.PersistentRegistryState(
                self.base / "primary_state", "/example.com", self.root_pub
            )
        )
        # 上の pstate は空なので、サービスを差し替えて同じ状態を持たせる。
        primary.pstate.service = primary_service
        secondary = _RegistryHTTP(
            cli_mod.PersistentRegistryState(
                self.base / "secondary_state", "/example.com", self.root_pub
            )
        )
        secondary.pstate.service = secondary_service
        self.addCleanup(primary.close)
        self.addCleanup(secondary.close)

        client = cli_mod.RemoteRegistryClient([primary.url, secondary.url])
        _del, _loc, head = client.resolve(self.path)
        self.assertIsNotNone(head)
        self.assertEqual(head["payload"]["version"], 1)

        primary.stop_http()
        _del, _loc, head = client.resolve(self.path)
        self.assertIsNotNone(head)
        self.assertEqual(head["payload"]["version"], 1)

    def test_primary_replicates_updates_to_secondary(self) -> None:
        primary = _RegistryHTTP(
            cli_mod.PersistentRegistryState(
                self.base / "primary_state", "/example.com", self.root_pub
            )
        )
        secondary = _RegistryHTTP(
            cli_mod.PersistentRegistryState(
                self.base / "secondary_state", "/example.com", self.root_pub
            )
        )
        self.addCleanup(primary.close)
        self.addCleanup(secondary.close)
        primary.pstate.replica_registries = [secondary.url]

        client = cli_mod.RemoteRegistryClient(primary.url)
        client.register_delegation(self.env, now=self.now)
        self.assertIn(self.path, secondary.pstate.service.delegations)

        client.announce_and_append(self.path, self.log, self.loc, now=self.now)
        self.assertEqual(
            secondary.pstate.service.logs[self.path][-1]["entry_hash"],
            self.log["entry_hash"],
        )

        # 主の HTTP を止めても、代替名簿から読める。
        primary.stop_http()
        failover = cli_mod.RemoteRegistryClient([primary.url, secondary.url])
        _del, _loc, head = failover.resolve(self.path)
        self.assertIsNotNone(head)
        self.assertEqual(head["payload"]["version"], 1)

    def test_write_stays_on_primary_when_secondary_is_up(self) -> None:
        primary = _RegistryHTTP(
            cli_mod.PersistentRegistryState(
                self.base / "primary_state", "/example.com", self.root_pub
            )
        )
        secondary = _RegistryHTTP(
            cli_mod.PersistentRegistryState(
                self.base / "secondary_state", "/example.com", self.root_pub
            )
        )
        self.addCleanup(primary.close)
        self.addCleanup(secondary.close)

        client = cli_mod.RemoteRegistryClient([primary.url, secondary.url])
        client.register_delegation(self.env, now=self.now)
        client.announce_and_append(self.path, self.log, self.loc, now=self.now)
        self.assertIn(self.path, primary.pstate.service.logs)
        self.assertNotIn(self.path, secondary.pstate.service.logs)


if __name__ == "__main__":
    unittest.main(verbosity=2)
