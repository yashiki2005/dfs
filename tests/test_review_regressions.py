#!/usr/bin/env python3
"""Regression tests for security and correctness fixes from the e92730a review."""

from __future__ import annotations

import base64
import json
import os
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dfs import cli as cli_mod
from dfs import cli_main
from dfs import l3_ost_adapter
from dfs import l4_log
from dfs import svc as svc_mod
from dfs.crypto import (
    ChunkIntegrityError,
    ContentAddressedCrypto,
    canonical_json,
)
from dfs.invite import encode_ro_invite, encode_rw_invite
from dfs.l1_delegation import create_delegation_envelope
from dfs.l2_registry import DirectoryRegistryService
from dfs.l3_ost_adapter import ChunkStoreServer, HttpOSTClient, OSTProtocolError
from dfs.l4_log import MerkleTreeBuilder
from dfs.relay import RelayError, RelayHub
from dfs.remotes import Remote, RemoteStore


def _keypair(base: Path, name: str) -> tuple[Path, str]:
    priv = base / name
    subprocess.run(
        ["ssh-keygen", "-t", "ed25519", "-N", "", "-C", f"{name}@test", "-f", str(priv)],
        check=True,
        capture_output=True,
    )
    return priv, Path(f"{priv}.pub").read_text(encoding="utf-8").strip()


class _FakeOST:
    def __init__(self) -> None:
        self.store: dict[str, bytes] = {}

    def put_if_absent(self, wire_id: str, blob: bytes) -> bool:
        if wire_id in self.store:
            return False
        self.store[wire_id] = blob
        return True

    def batch_put_if_absent(self, blobs: dict[str, bytes], assume_absent: bool = False) -> int:
        added = 0
        for wid, blob in blobs.items():
            if wid not in self.store:
                added += 1
            self.store[wid] = blob
        return added

    def batch_has(self, wire_ids: list[str]) -> dict[str, bool]:
        return {wid: wid in self.store for wid in wire_ids}

    def get(self, wire_id: str) -> bytes:
        return self.store[wire_id]

    def batch_get(self, wire_ids: list[str]) -> dict[str, bytes]:
        return {wid: self.store[wid] for wid in wire_ids}


class TestReviewRegressions(unittest.TestCase):
    def test_invite_malicious_write_name_rejected_and_existing_key_protected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            home = root / "home"
            home.mkdir()
            priv, pub = _keypair(root, "eph")
            priv_text = priv.read_text(encoding="utf-8")

            for bad_name in ("/tmp/pwned", "../escape", "sub/dir"):
                token = encode_rw_invite(
                    name="r1",
                    registries=["http://127.0.0.1:19440"],
                    root_pubkey=pub,
                    tree_secret="secret-123",
                    path="/shared",
                    write_path="/shared/out",
                    write_priv_key=priv_text,
                    write_pub_key=pub,
                    write_name=bad_name,
                )
                with patch.dict(os.environ, {"DFS_HOME": str(home), "DFS_CONFIG": str(home / "remotes.json")}):
                    args = SimpleNamespace(
                        action="join",
                        target=token,
                        name="safe_remote",
                        workdir=None,
                        sync=False,
                        dest=None,
                        watch=False,
                        poll=30,
                        candidacy=True,
                    )
                    with self.assertRaises(cli_main.UsageError):
                        cli_main.cmd_invite(args)
                self.assertFalse(Path("/tmp/pwned_ed25519").exists())

            # Existing key file must not be overwritten
            key_dir = home / ".config" / "dfs" / "keys"
            key_dir.mkdir(parents=True, exist_ok=True)
            existing_key = key_dir / "existing_ed25519"
            existing_key.write_text("KEEP-ME", encoding="utf-8")
            token = encode_rw_invite(
                name="r2",
                registries=["http://127.0.0.1:19440"],
                root_pubkey=pub,
                tree_secret="secret-123",
                path="/shared",
                write_path="/shared/out",
                write_priv_key=priv_text,
                write_pub_key=pub,
                write_name="existing",
            )
            with patch.dict(os.environ, {"DFS_HOME": str(home), "DFS_CONFIG": str(home / "remotes.json")}):
                args = SimpleNamespace(
                    action="join",
                    target=token,
                    name="safe_remote2",
                    workdir=None,
                    sync=False,
                    dest=None,
                    watch=False,
                    poll=30,
                    candidacy=True,
                )
                with self.assertRaises(cli_main.UsageError):
                    cli_main.cmd_invite(args)
            self.assertEqual(existing_key.read_text(encoding="utf-8"), "KEEP-ME")

    def test_join_invite_uri_format_succeeds(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            home = root / "home"
            home.mkdir()
            _priv, pub = _keypair(root, "root")
            token = encode_ro_invite(
                name="ro_domain",
                registries=["http://127.0.0.1:19440"],
                root_pubkey=pub,
                tree_secret="secret-xyz",
                path="/shared",
            )
            cfg_file = home / "remotes.json"
            with patch.dict(os.environ, {"DFS_HOME": str(home), "DFS_CONFIG": str(cfg_file)}):
                rc = cli_main.main(["join", f"dfs-invite://{token}", "--name", "joined_ro"])
                self.assertEqual(rc, 0)
                store = RemoteStore(cfg_file)
                r = store.get("joined_ro")
                self.assertTrue(r.read_only)
                self.assertEqual(r.path, "/shared")

    def test_readonly_remote_rm_mv_do_not_mutate_workdir_and_archive_fetch_works(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            home = root / "home"
            workdir = root / "work"
            home.mkdir()
            workdir.mkdir()
            (workdir / "a.txt").write_text("hello", encoding="utf-8")
            _priv, pub = _keypair(root, "root")
            cfg_file = home / "remotes.json"
            store = RemoteStore(cfg_file)
            store.set(
                Remote(
                    name="ro",
                    registry="http://127.0.0.1:19440",
                    key="",
                    path="/shared",
                    secret="sec",
                    workdir=str(workdir),
                    root_pubkey=pub,
                    read_only=True,
                )
            )

            with patch.dict(os.environ, {"DFS_HOME": str(home), "DFS_CONFIG": str(cfg_file)}):
                with self.assertRaises(cli_main.UsageError):
                    cli_main.cmd_rm(SimpleNamespace(remote="ro:a.txt", remote_name="ro", message="rm"))
                self.assertTrue((workdir / "a.txt").exists())

                with self.assertRaises(cli_main.UsageError):
                    cli_main.cmd_mv(
                        SimpleNamespace(src="ro:a.txt", dst="ro:b.txt", remote_name="ro", message="mv")
                    )
                self.assertTrue((workdir / "a.txt").exists())
                self.assertFalse((workdir / "b.txt").exists())

                # _archive_registry_context must not fail when remote.key == ""
                fake_reg = SimpleNamespace(
                    archives=lambda _p, version=None: [{"payload": {"version": 1}}]
                )
                with patch.object(
                    cli_mod, "RemoteRegistryClient", return_value=fake_reg
                ), patch.object(
                    cli_main.L4LogClient,
                    "resolve_verified",
                    return_value=({"payload": {"timestamp": 1}}, {"chain": []}, {}),
                ), patch.object(
                    cli_main,
                    "verify_delegation_chain",
                    return_value={"writer": "ssh-ed25519 AAAA"},
                ), patch.object(
                    cli_main,
                    "verify_archive_descriptor",
                    return_value=None,
                ):
                    path, desc, head = cli_main._archive_registry_context(
                        store, store.get("ro"), None
                    )
                self.assertEqual(path, "/shared")
                self.assertEqual(desc["payload"]["version"], 1)
                self.assertEqual(head["payload"]["timestamp"], 1)

    def test_multichunk_upload_tracks_all_wire_ids_across_flushes(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            src = root / "src"
            dst = root / "dst"
            src.mkdir()
            (src / "big.bin").write_bytes(b"A" * 100 + b"B" * 100 + b"C" * 100)
            crypto = ContentAddressedCrypto("secret")
            ost = _FakeOST()
            builder = MerkleTreeBuilder(crypto, ost)
            with patch.object(l4_log, "FILE_CHUNK_BYTES", 100), patch.object(
                l4_log, "UPLOAD_BATCH_BYTES", 1
            ):
                root_pid, root_wid = builder.upload_directory(src)
                # Both file chunks (3) + dir chunk (1) must be recorded despite mid-walk flushes
                self.assertEqual(len(builder._last_wire_ids), 4)
                self.assertEqual(set(ost.store.keys()), builder._last_wire_ids)

                # list_tree() leaves wire_id/plain_id empty for multi-chunk files
                rows = builder.list_tree(root_pid, root_wid)
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0]["wire_id"], "")
                self.assertEqual(rows[0]["plain_id"], "")
                self.assertEqual(len(rows[0]["chunks"]), 3)

                builder.download_directory(root_pid, root_wid, dst)
                self.assertEqual(
                    (dst / "big.bin").read_bytes(),
                    b"A" * 100 + b"B" * 100 + b"C" * 100,
                )

    def test_batch_get_dedup_and_response_size_limit(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cert = root / "cert.pem"
            key = root / "key.pem"
            subprocess.run(
                [
                    "openssl",
                    "req",
                    "-x509",
                    "-newkey",
                    "rsa:2048",
                    "-keyout",
                    str(key),
                    "-out",
                    str(cert),
                    "-days",
                    "1",
                    "-nodes",
                    "-subj",
                    "/CN=test",
                ],
                check=True,
                capture_output=True,
            )
            server = ChunkStoreServer(cert, key, host="127.0.0.1", port=0)
            wid = "a" * 64
            payload = b"x" * 1024
            server.store[wid] = payload

            # Duplicate IDs are deduplicated instead of amplifying response size
            resp = server.batch_get_raw((wid * 10).encode("ascii"))
            self.assertEqual(len(resp), 1 + 4 + len(payload))

            # Exceeding MAX_OST_HTTP_BODY_BYTES raises OSTProtocolError
            wid2 = "b" * 64
            server.store[wid2] = b"y" * 1024
            with patch.object(l3_ost_adapter, "MAX_OST_HTTP_BODY_BYTES", 1500):
                with self.assertRaises(OSTProtocolError):
                    server.batch_get_raw((wid + wid2).encode("ascii"))

            # Client rejects oversized Content-Length
            fake_resp = SimpleNamespace(
                status=200,
                getheader=lambda name: str(l3_ost_adapter.MAX_OST_HTTP_BODY_BYTES + 1)
                if name == "Content-Length"
                else None,
                read=lambda _n=None: b"",
            )
            closed = []
            fake_conn = SimpleNamespace(
                sock=None,
                request=lambda *a, **kw: None,
                getresponse=lambda: fake_resp,
                close=lambda: closed.append(True),
            )
            client = HttpOSTClient("http://127.0.0.1:1")
            with self.assertRaises(ChunkIntegrityError):
                client._request_once(fake_conn, "/v1/ost/batch_get", b"")
            self.assertTrue(closed)

    def test_cli_compression_default_is_auto(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            home = root / "home"
            home.mkdir()
            priv, pub = _keypair(root, "writer")
            pub_file = root / "writer.pub"
            pub_file.write_text(pub + "\n", encoding="utf-8")
            cfg_file = home / "remotes.json"
            with patch.dict(os.environ, {"DFS_HOME": str(home), "DFS_CONFIG": str(cfg_file)}):
                rc = cli_main.main(
                    [
                        "config",
                        "create",
                        "myrem",
                        "--registry",
                        "http://127.0.0.1:19440",
                        "--key",
                        str(priv),
                        "--root-pubkey",
                        str(pub_file),
                        "--path",
                        "/data",
                        "--secret",
                        "sec",
                    ]
                )
                self.assertEqual(rc, 0)
                r = RemoteStore(cfg_file).get("myrem")
                self.assertEqual(r.compression, "auto")

                rc2 = cli_main.main(
                    [
                        "config",
                        "create",
                        "myrem2",
                        "--registry",
                        "http://127.0.0.1:19440",
                        "--key",
                        str(priv),
                        "--root-pubkey",
                        str(pub_file),
                        "--path",
                        "/data",
                        "--secret",
                        "sec",
                        "--compression",
                        "auto",
                    ]
                )
                self.assertEqual(rc2, 0)
                self.assertEqual(RemoteStore(cfg_file).get("myrem2").compression, "auto")

    def test_http_rejected_binary_request_closes_connection(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _priv, pub = _keypair(root, "root")
            cert = root / "cert.pem"
            key = root / "key.pem"
            subprocess.run(
                [
                    "openssl",
                    "req",
                    "-x509",
                    "-newkey",
                    "rsa:2048",
                    "-keyout",
                    str(key),
                    "-out",
                    str(cert),
                    "-days",
                    "1",
                    "-nodes",
                    "-subj",
                    "/CN=test",
                ],
                check=True,
                capture_output=True,
            )
            ost = ChunkStoreServer(cert, key, host="127.0.0.1", port=0)
            pstate = cli_mod.PersistentRegistryState(root / "state", "/example.com", pub)
            handler = cli_mod.make_registry_http_handler(pstate, ost)
            httpd = cli_mod.ThreadingHTTPServer(("127.0.0.1", 0), handler)
            t = threading.Thread(target=httpd.serve_forever, daemon=True)
            t.start()
            try:
                port = httpd.server_address[1]
                # Oversized Content-Length must close connection and return Connection: close
                with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
                    req = (
                        b"POST /v1/ost/batch_get HTTP/1.1\r\n"
                        b"Host: 127.0.0.1\r\n"
                        b"Content-Length: 999999999999\r\n\r\n"
                    )
                    s.sendall(req)
                    raw = b""
                    while True:
                        chunk = s.recv(4096)
                        if not chunk:
                            break
                        raw += chunk
                    self.assertIn(b"413", raw.splitlines()[0])
                    self.assertIn(b"Connection: close", raw)

                # Transfer-Encoding must also be rejected and closed
                with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
                    req = (
                        b"POST /v1/ost/batch_get HTTP/1.1\r\n"
                        b"Host: 127.0.0.1\r\n"
                        b"Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
                    )
                    s.sendall(req)
                    raw = b""
                    while True:
                        chunk = s.recv(4096)
                        if not chunk:
                            break
                        raw += chunk
                    self.assertIn(b"400", raw.splitlines()[0])
                    self.assertIn(b"Connection: close", raw)
            finally:
                httpd.shutdown()
                httpd.server_close()

    def test_relay_hub_non_loopback_requires_token_and_enforces_limits(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _priv, pub = _keypair(root, "root")
            pub_file = root / "root.pub"
            pub_file.write_text(pub + "\n", encoding="utf-8")
            args = SimpleNamespace(
                state_dir=str(root / "state"),
                ost_dir=None,
                root_pubkey=str(pub_file),
                root_anchor="/example.com",
                bind="0.0.0.0",
                ost_port=0,
                registry_port=0,
                advertise="127.0.0.1",
                role=None,
                role_epoch=None,
                enable_relay=True,
                relay_token="",
                relay=[],
                relay_node="",
                replica=[],
            )
            with patch.dict(os.environ, {}, clear=False):
                os.environ.pop("DFS_RELAY_TOKEN", None)
                os.environ.pop("DFS_RELAY_ALLOW_UNAUTH", None)
                with self.assertRaises(SystemExit):
                    cli_mod.cmd_serve(args)

        hub = RelayHub(token="secret", node_ttl=0.05, max_nodes=2, max_pending_per_node=2)
        hub._get_or_create_slot("n1")
        hub._get_or_create_slot("n2")
        with self.assertRaises(RelayError):
            hub._get_or_create_slot("n3")
        # Pending queue limit check
        hub._nodes["n1"].pending.put(object())  # type: ignore[arg-type]
        hub._nodes["n1"].pending.put(object())  # type: ignore[arg-type]
        with self.assertRaises(RelayError):
            hub.forward("n1", "GET", "/v1/status", "application/json", b"")

    def test_dfssvc_hub_writes_0600_config_and_passes_token_via_env(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            home = root / "home"
            home.mkdir()
            root_key, _ = _keypair(root, "root_k")
            writer_key, _ = _keypair(root, "writer_k")
            captured: dict[str, object] = {}

            def fake_popen(cmd, env=None, **kwargs):
                captured["cmd"] = list(cmd)
                captured["env"] = dict(env or {})
                raise RuntimeError("stop-before-spawn")

            with patch.dict(os.environ, {"DFS_HOME": str(home)}), patch.object(
                svc_mod.subprocess, "Popen", side_effect=fake_popen
            ):
                args = SimpleNamespace(
                    name="hubsvc",
                    host="127.0.0.1",
                    port=19500,
                    hub=True,
                    join=None,
                    relay_token=None,
                    relay_node=None,
                    advertise=None,
                    state_dir=None,
                    ost_dir=None,
                    root_key=str(root_key),
                    writer_key=str(writer_key),
                    root_anchor="/example.com",
                    role=None,
                    role_epoch=None,
                    replica=[],
                    foreground=False,
                    wait=1.0,
                )
                with self.assertRaises(RuntimeError):
                    svc_mod.cmd_start(args)

                cfg_file = svc_mod._base_dir("hubsvc") / "dfssvc.json"
                self.assertTrue(cfg_file.is_file())
            mode = stat.S_IMODE(cfg_file.stat().st_mode)
            self.assertEqual(mode, 0o600)
            cfg = json.loads(cfg_file.read_text(encoding="utf-8"))
            self.assertTrue(cfg["relay_token"])
            self.assertNotIn("--relay-token", captured["cmd"])  # type: ignore[arg-type]
            self.assertEqual(
                captured["env"]["DFS_RELAY_TOKEN"],  # type: ignore[index]
                cfg["relay_token"],
            )

    def test_pyinstaller_entrypoints_run_without_relative_import_error(self) -> None:
        repo = Path(__file__).resolve().parents[1]
        for script in ("scripts/pyinstaller_cli.py", "scripts/pyinstaller_svc.py"):
            res = subprocess.run(
                [sys.executable, str(repo / script), "--help"],
                cwd=str(repo),
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(res.returncode, 0, msg=res.stderr)

    def test_top_level_remote_flag_works_with_ls_and_subtree_hint(self) -> None:
        from dfs.remotes import RemoteError, split_remote_spec

        self.assertEqual(split_remote_spec("dfs://local"), ("local", ""))
        self.assertEqual(split_remote_spec("dfs://local/"), ("local", ""))
        self.assertEqual(split_remote_spec("dfs://local:"), ("local", ""))
        self.assertEqual(split_remote_spec("dfs://local:test/a.txt"), ("local", "test/a.txt"))
        self.assertEqual(split_remote_spec("dfs://local/test/a.txt"), ("local", "test/a.txt"))
        self.assertEqual(split_remote_spec("dfs:///test/a.txt", "local"), ("local", "test/a.txt"))

        parser = cli_main.build_parser()
        for subcmd in ("ls", "lsd", "lsl", "lsjson", "size", "about", "touch", "history"):
            args = parser.parse_args(["--remote", "local", subcmd])
            self.assertEqual(args.remote_name, "local")
            self.assertEqual(args.remote, "")
            self.assertEqual(split_remote_spec(args.remote, args.remote_name), ("local", ""))

        with tempfile.TemporaryDirectory() as td:
            store = RemoteStore(Path(td) / "remotes.json")
            with self.assertRaises(RemoteError) as ctx:
                store.get("/example.com/local")
            self.assertIn("hint:", str(ctx.exception))

    def test_listremotes_shows_reachability_and_usage_hint(self) -> None:
        import io
        from contextlib import redirect_stdout

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            home = root / "home"
            home.mkdir()
            priv, _pub = _keypair(root, "w")
            cfg_file = home / "remotes.json"
            store = RemoteStore(cfg_file)
            store.set(
                Remote(
                    name="local",
                    registry="http://127.0.0.1:1",
                    key=str(priv),
                    path="/example.com/local",
                    secret="s",
                )
            )
            with patch.dict(os.environ, {"DFS_HOME": str(home), "DFS_CONFIG": str(cfg_file)}), patch.object(
                cli_main, "_probe_registry_tcp", return_value=True
            ):
                buf = io.StringIO()
                with redirect_stdout(buf):
                    rc = cli_main.main(["listremotes"])
                self.assertEqual(rc, 0)
                out = buf.getvalue()
                self.assertIn("dfs://local/ -> http://127.0.0.1:1 /example.com/local [online, rw]", out)
                self.assertIn("Scheme: dfs://", out)
                self.assertIn("dfscli ls dfs://local/", out)

                buf_json = io.StringIO()
                with redirect_stdout(buf_json):
                    rc2 = cli_main.main(["listremotes", "--json", "--no-check"])
                self.assertEqual(rc2, 0)
                rows = json.loads(buf_json.getvalue())
                self.assertEqual(rows[0]["name"], "local")
                self.assertIsNone(rows[0]["online"])

    def test_listremotes_prune_and_self_claimed_domain_resolution(self) -> None:
        from dfs.svc import Service, ServiceStore

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            home = root / "home"
            home.mkdir()
            priv, pub = _keypair(root, "w")
            cfg_file = home / "remotes.json"
            store = RemoteStore(cfg_file)
            store.set(
                Remote(
                    name="local",
                    registry="http://127.0.0.1:1",
                    key=str(priv),
                    path="/example.com/local",
                    secret="s",
                )
            )
            store.set(
                Remote(
                    name="stale",
                    registry="http://127.0.0.1:2",
                    key=str(priv),
                    path="/old",
                    secret="s",
                )
            )
            with patch.dict(os.environ, {"DFS_HOME": str(home), "DFS_CONFIG": str(cfg_file)}):
                svc_store = ServiceStore()
                svc_store.services["local"] = Service(
                    name="local",
                    state_dir=str(root / "st"),
                    root_key=str(priv),
                    root_pub=str(root / "w.pub"),
                    registry_port=1,
                    ost_port=2,
                    bind="127.0.0.1",
                    advertise="127.0.0.1",
                    root_anchor="/example.com",
                    pid=999999,
                    started_at="2026-01-01T00:00:00Z",
                )
                svc_store.save()

                with patch.object(cli_main, "_probe_registry_tcp", return_value=False):
                    rc = cli_main.main(["listremotes", "--prune", "-y"])
                self.assertEqual(rc, 0)
                reloaded = RemoteStore(cfg_file)
                self.assertIn("local", reloaded.remotes)
                self.assertNotIn("stale", reloaded.remotes)

                fake_reg = SimpleNamespace(
                    root_anchor_info=lambda: {"root_pubkey": pub, "root_anchor": "/yashiki.top"}
                )
                with patch("dfs.dnssec.has_txt_record", return_value=False), patch.object(
                    cli_main, "_probe_registry_tcp", return_value=True
                ), patch.object(
                    cli_mod, "RemoteRegistryClient", return_value=fake_reg
                ):
                    resolved = cli_main._resolve_remote(reloaded, "yashiki.top")
                self.assertEqual(resolved.name, "yashiki.top")
                self.assertEqual(resolved.path, "/yashiki.top")
                self.assertTrue(resolved.read_only)

                # When _dfs.<domain> TXT exists, self-claimed TOFU fallback must NOT be allowed
                with patch("dfs.dnssec.has_txt_record", return_value=True), patch.object(
                    cli_main,
                    "discover_domain",
                    side_effect=cli_main.DiscoveryError("bad dnssec"),
                ):
                    with self.assertRaises(cli_main.UsageError):
                        cli_main._resolve_remote(reloaded, "yashiki.top")

    def test_join_dfs_domain_uses_dnssec_discovery(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            home = root / "home"
            home.mkdir()
            _, pub = _keypair(root, "w")
            cfg_file = home / "remotes.json"
            discovered = SimpleNamespace(
                domain="yashiki.top",
                primary_url="https://l2.yashiki.top",
                alternate_urls=[],
                root_pubkey=pub,
                root_fingerprint="fp-yashiki",
                epoch=1,
                root_anchor="/yashiki.top",
                dnssec_validated=True,
            )
            with patch.dict(
                os.environ,
                {"HOME": str(home), "DFS_HOME": str(home), "DFS_CONFIG": str(cfg_file)},
            ):
                with patch("dfs.dnssec.has_txt_record", return_value=True), patch.object(
                    cli_main, "discover_domain", return_value=discovered
                ) as mock_discover, patch(
                    "dfs.relay.discover_ice_candidates", return_value=[]
                ):
                    rc = cli_main.main(["join", "dfs://yashiki.top"])
                self.assertEqual(rc, 0)
                mock_discover.assert_called_once()
                reloaded = RemoteStore(cfg_file)
                remote = reloaded.get("yashiki.top")
                self.assertIsNotNone(remote)
                self.assertEqual(remote.registry, "https://l2.yashiki.top")
                self.assertEqual(remote.path, "/yashiki.top")
                self.assertEqual(remote.root_pubkey, pub)
                self.assertTrue(remote.read_only)


if __name__ == "__main__":
    unittest.main()
