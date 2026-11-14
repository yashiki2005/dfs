#!/usr/bin/env python3
"""tests/test_discovery_candidacy.py — 小規模運用向け署名付き立候補モデルの試験。"""

from __future__ import annotations

import json
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from dfs import cli as cli_mod
from dfs import cli_main
from dfs.discovery import (
    CandidacyError,
    create_candidacy_envelope,
    fetch_candidacy,
    verify_candidacy_envelope,
)
from dfs.l3_ost_adapter import ChunkStoreServer
from dfs.remotes import RemoteStore


def _gen_ed25519(path: Path) -> tuple[Path, str]:
    res = subprocess.run(
        ["ssh-keygen", "-t", "ed25519", "-N", "", "-f", str(path)],
        capture_output=True,
        text=True,
        check=True,
    )
    assert res.returncode == 0
    pub = Path(f"{path}.pub").read_text(encoding="utf-8").strip()
    return path, pub


class CandidacyUnitTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.root_key, self.root_pub = _gen_ed25519(self.root / "root")
        _, self.other_pub = _gen_ed25519(self.root / "other")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_create_and_verify_candidacy(self) -> None:
        now = int(time.time())
        env = create_candidacy_envelope(
            self.root_key,
            "/example.com",
            self.root_pub,
            [
                {"role": "primary", "url": "http://127.0.0.1:19440"},
                {"role": "secondary", "url": "http://127.0.0.1:19442"},
            ],
            epoch=3,
            issued_at=now - 10,
            expires_at=now + 3600,
        )
        disc = verify_candidacy_envelope(env, self.root_pub, now=now)
        self.assertEqual(disc.root_anchor, "/example.com")
        self.assertEqual(disc.epoch, 3)
        self.assertEqual(disc.primary_url, "http://127.0.0.1:19440")
        self.assertEqual(disc.alternate_urls, ["http://127.0.0.1:19442"])

    def test_rejects_wrong_pubkey_tamper_expiry_and_rollback(self) -> None:
        now = int(time.time())
        env = create_candidacy_envelope(
            self.root_key,
            "/example.com",
            self.root_pub,
            [{"role": "primary", "url": "http://127.0.0.1:19440"}],
            epoch=2,
            issued_at=now - 10,
            expires_at=now + 100,
        )
        with self.assertRaises(CandidacyError):
            verify_candidacy_envelope(env, self.other_pub, now=now)
        with self.assertRaises(CandidacyError):
            verify_candidacy_envelope(env, self.root_pub, now=now + 200)
        with self.assertRaises(CandidacyError):
            verify_candidacy_envelope(env, self.root_pub, now=now, min_epoch=3)

        tampered = json.loads(json.dumps(env))
        tampered["payload"]["registries"][0]["url"] = "http://127.0.0.1:19999"
        with self.assertRaises(CandidacyError):
            verify_candidacy_envelope(tampered, self.root_pub, now=now)


class CandidacyHTTPAndCLITests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.root_key, self.root_pub = _gen_ed25519(self.root / "root")
        self.servers: list[tuple[cli_mod.BoundedThreadingHTTPServer, int]] = []
        for idx in range(2):
            state_dir = self.root / f"srv_{idx}"
            state_dir.mkdir(parents=True, exist_ok=True)
            pstate = cli_mod.PersistentRegistryState(
                state_dir, "/example.com", self.root_pub
            )
            handler = cli_mod.make_registry_http_handler(pstate, None)  # type: ignore[arg-type]
            httpd = cli_mod.BoundedThreadingHTTPServer(
                ("127.0.0.1", 0), handler, max_workers=8
            )
            port = httpd.server_address[1]
            t = threading.Thread(target=httpd.serve_forever, daemon=True)
            t.start()
            self.servers.append((httpd, port))

    def tearDown(self) -> None:
        for httpd, _ in self.servers:
            httpd.shutdown()
            httpd.server_close()
        self._tmp.cleanup()

    def test_fetch_candidacy_picks_highest_epoch_and_config_create(self) -> None:
        url_a = f"http://127.0.0.1:{self.servers[0][1]}"
        url_b = f"http://127.0.0.1:{self.servers[1][1]}"
        now = int(time.time())

        env_v1 = create_candidacy_envelope(
            self.root_key,
            "/example.com",
            self.root_pub,
            [{"role": "primary", "url": url_a}, {"role": "secondary", "url": url_b}],
            epoch=1,
            issued_at=now - 10,
            expires_at=now + 3600,
        )
        env_v2 = create_candidacy_envelope(
            self.root_key,
            "/example.com",
            self.root_pub,
            [{"role": "primary", "url": url_b}, {"role": "secondary", "url": url_a}],
            epoch=2,
            issued_at=now - 5,
            expires_at=now + 3600,
        )
        cli_mod.RemoteRegistryClient(url_a).announce_candidacy(env_v1)
        cli_mod.RemoteRegistryClient(url_b).announce_candidacy(env_v2)

        disc = fetch_candidacy([url_a, url_b], self.root_pub, now=now)
        self.assertEqual(disc.epoch, 2)
        self.assertEqual(disc.primary_url, url_b)
        self.assertEqual(disc.alternate_urls, [url_a])

        cfg_path = self.root / "remotes.json"
        writer_key, _ = _gen_ed25519(self.root / "writer")
        with patch.dict("os.environ", {"DFS_CONFIG": str(cfg_path)}):
            rc = cli_main.main([
                "config", "create", "team",
                "--candidacy-url", url_a,
                "--candidacy-url", url_b,
                "--root-pubkey", str(self.root / "root.pub"),
                "--key", str(writer_key),
                "--secret", "s3cr3t",
                "--no-prompt",
            ])
        self.assertEqual(rc, 0)
        remote = RemoteStore(cfg_path).get("team")
        self.assertEqual(remote.registry, url_b)
        self.assertEqual(remote.registry_alternates, [url_a])
        self.assertEqual(remote.role_epoch, 2)

    def test_cli_candidacy_create_and_discover(self) -> None:
        url_a = f"http://127.0.0.1:{self.servers[0][1]}"
        out_json = self.root / "cand.json"
        rc = cli_main.main([
            "candidacy", "create",
            "--root-key", str(self.root_key),
            "--root-anchor", "/example.com",
            "--root-pubkey", str(self.root / "root.pub"),
            "--primary", url_a,
            "--epoch", "4",
            "--out", str(out_json),
            "--announce", url_a,
        ])
        self.assertEqual(rc, 0)
        self.assertTrue(out_json.is_file())

        rc2 = cli_main.main([
            "candidacy", "discover",
            "--url", url_a,
            "--root-pubkey", str(self.root / "root.pub"),
        ])
        self.assertEqual(rc2, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
