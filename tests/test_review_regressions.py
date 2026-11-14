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


def _self_signed_cert(base: Path, cn: str = "localhost") -> tuple[Path, Path]:
    cert = base / "cert.pem"
    key = base / "key.pem"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", str(key), "-out", str(cert),
            "-days", "1", "-nodes", "-subj", f"/CN={cn}",
        ],
        check=True,
        capture_output=True,
    )
    return cert, key


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
            class FailReg:
                def __init__(self, urls):
                    pass

                def list_paths(self):
                    raise RuntimeError("HTTP 502: Bad Gateway")

            class OkReg:
                def __init__(self, urls):
                    pass

                def list_paths(self):
                    return {"root_anchor": "/yashiki.top", "root_pubkey": pub, "paths": {}}

            with patch.dict(
                os.environ,
                {"HOME": str(home), "DFS_HOME": str(home), "DFS_CONFIG": str(cfg_file)},
            ):
                with patch("dfs.dnssec.has_txt_record", return_value=True), patch.object(
                    cli_main, "discover_domain", return_value=discovered
                ), patch.object(
                    cli_mod, "RemoteRegistryClient", FailReg
                ), patch(
                    "dfs.relay.discover_ice_candidates", return_value=[]
                ):
                    rc_fail = cli_main.main(["join", "dfs://yashiki.top"])
                self.assertNotEqual(rc_fail, 0)
                self.assertNotIn("yashiki.top", RemoteStore(cfg_file).remotes)

                with patch("dfs.dnssec.has_txt_record", return_value=True), patch.object(
                    cli_main, "discover_domain", return_value=discovered
                ) as mock_discover, patch.object(
                    cli_mod, "RemoteRegistryClient", OkReg
                ), patch(
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

    def test_ensure_remote_secret_prompts_and_persists(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            home = root / "home"
            home.mkdir()
            cfg_file = home / "remotes.json"
            store = RemoteStore(cfg_file)
            remote = Remote(
                name="yashiki.top",
                registry="https://l2.yashiki.top",
                key="",
                path="/yashiki.top",
                secret="",
                read_only=True,
            )
            store.set(remote)
            with patch.dict(os.environ, {"DFS_HOME": str(home), "DFS_CONFIG": str(cfg_file)}):
                with patch.object(cli_main, "prompt_secret", return_value="") as mock_empty:
                    with self.assertRaises(cli_main.UsageError):
                        cli_main._ensure_remote_secret(RemoteStore(cfg_file).get("yashiki.top"))
                mock_empty.assert_called_once()

                with patch.object(
                    cli_main, "prompt_secret", return_value="my-shared-secret"
                ) as mock_prompt:
                    updated = cli_main._ensure_remote_secret(
                        RemoteStore(cfg_file).get("yashiki.top")
                    )
                mock_prompt.assert_called_once()
                self.assertEqual(updated.secret, "my-shared-secret")
                self.assertEqual(RemoteStore(cfg_file).get("yashiki.top").secret, "my-shared-secret")

    def test_listremotes_queries_l2_and_dnssec_status(self) -> None:
        import io
        from contextlib import redirect_stdout

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            home = root / "home"
            home.mkdir()
            _, pub = _keypair(root, "w")
            cfg_file = home / "remotes.json"
            store = RemoteStore(cfg_file)
            store.set(
                Remote(
                    name="root",
                    registry="https://root.example.net",
                    key="",
                    path="/root",
                    root_pubkey=pub,
                    read_only=True,
                )
            )
            store.set(
                Remote(
                    name="yashiki.top",
                    registry="https://l2.yashiki.top",
                    key="",
                    path="/yashiki.top",
                    root_pubkey=pub,
                    read_only=True,
                )
            )

            class FakeReg:
                def __init__(self, urls):
                    self.url = urls[0] if isinstance(urls, list) else urls

                def list_paths(self):
                    if "root.example.net" in self.url:
                        return {"root_anchor": "/", "root_pubkey": pub, "paths": {"/a": {}}}
                    return {
                        "root_anchor": "/yashiki.top",
                        "root_pubkey": pub,
                        "paths": {"/yashiki.top/d1": {}, "/yashiki.top/d2": {}},
                    }

            discovered = SimpleNamespace(
                domain="yashiki.top",
                primary_url="https://l2.yashiki.top",
                alternate_urls=[],
                root_pubkey=pub,
                epoch=1,
                root_anchor="/yashiki.top",
                dnssec_validated=True,
            )

            with patch.dict(os.environ, {"DFS_HOME": str(home), "DFS_CONFIG": str(cfg_file)}), patch.object(
                cli_main, "_probe_registry_tcp", return_value=True
            ), patch.object(
                cli_mod, "RemoteRegistryClient", FakeReg
            ), patch(
                "dfs.dnssec.has_txt_record",
                side_effect=lambda rec: rec == "_dfs.yashiki.top",
            ), patch.object(
                cli_main, "discover_domain", return_value=discovered
            ):
                buf = io.StringIO()
                with redirect_stdout(buf):
                    rc = cli_main.main(["listremotes"])
                self.assertEqual(rc, 0)
                out = buf.getvalue()
                self.assertIn("root dfs (anchor=/, paths=1)", out)
                self.assertIn("root dfs (anchor=/yashiki.top, paths=2), DNSSEC: verified (_dfs.yashiki.top)", out)

                buf_json = io.StringIO()
                with redirect_stdout(buf_json):
                    rc2 = cli_main.main(["listremotes", "--json"])
                self.assertEqual(rc2, 0)
                rows = {r["name"]: r for r in json.loads(buf_json.getvalue())}
                self.assertEqual(rows["root"]["role"], "root")
                self.assertEqual(rows["root"]["paths_count"], 1)
                self.assertIsNone(rows["root"]["dnssec"])
                self.assertEqual(rows["yashiki.top"]["role"], "root")
                self.assertEqual(rows["yashiki.top"]["paths_count"], 2)
                self.assertEqual(rows["yashiki.top"]["dnssec"], "verified")
                self.assertEqual(rows["yashiki.top"]["dnssec_record"], "_dfs.yashiki.top")

    def test_listremotes_empty_probes_builtin_root_yashiki_top(self) -> None:
        import io
        from contextlib import redirect_stdout

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            home = root / "home"
            home.mkdir()
            _, pub = _keypair(root, "w")
            cfg_file = home / "remotes.json"

            class FakeReg:
                def __init__(self, urls):
                    self.urls = urls

                def list_paths(self):
                    return {"root_anchor": "/yashiki.top", "root_pubkey": pub, "paths": {"/yashiki.top/a": {}}}

            discovered = SimpleNamespace(
                domain="yashiki.top",
                primary_url="https://l2.yashiki.top",
                alternate_urls=[],
                root_pubkey=pub,
                epoch=1,
                root_anchor="/yashiki.top",
                dnssec_validated=True,
            )

            with patch.dict(os.environ, {"DFS_HOME": str(home), "DFS_CONFIG": str(cfg_file)}), patch.object(
                cli_main, "_probe_registry_tcp", return_value=True
            ), patch.object(
                cli_mod, "RemoteRegistryClient", FakeReg
            ), patch(
                "dfs.dnssec.has_txt_record",
                side_effect=lambda rec: rec == "_dfs.yashiki.top",
            ), patch.object(
                cli_main, "discover_domain", return_value=discovered
            ):
                buf = io.StringIO()
                with redirect_stdout(buf):
                    rc = cli_main.main(["listremotes"])
                self.assertEqual(rc, 0)
                out = buf.getvalue()
                self.assertIn("既定の root dfs:", out)
                self.assertIn("dfs://yashiki.top/ -> https://l2.yashiki.top /yashiki.top [online, unregistered]", out)
                self.assertIn("root dfs (anchor=/yashiki.top, paths=1), DNSSEC: verified (_dfs.yashiki.top)", out)

    def test_serve_accepts_relay_hub_flag(self) -> None:
        args = cli_mod.build_parser().parse_args(["serve", "--root-pubkey", "dummy.pub", "--relay-hub"])
        self.assertTrue(args.enable_relay)

    def test_join_auto_restarts_running_dfssvc(self) -> None:
        from dfs import svc as svc_mod

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            home = root / "home"
            svc_dir = home / "dfssvc" / "local"
            svc_dir.mkdir(parents=True)
            priv, pub = _keypair(root, "w")
            cfg_file = home / "remotes.json"

            class OkReg:
                def __init__(self, urls):
                    pass

                def list_paths(self):
                    return {"root_anchor": "/yashiki.top", "root_pubkey": pub, "paths": {}}

            discovered = SimpleNamespace(
                domain="yashiki.top",
                primary_url="https://l2.yashiki.top",
                alternate_urls=[],
                root_pubkey=pub,
                epoch=1,
                root_anchor="/yashiki.top",
                dnssec_validated=True,
            )

            with patch.dict(
                os.environ,
                {"HOME": str(home), "DFS_HOME": str(home), "DFS_CONFIG": str(cfg_file)},
            ):
                svc_store = svc_mod.ServiceStore()
                svc_store.services["local"] = svc_mod.Service(
                    name="local",
                    state_dir=str(root / "st"),
                    root_key=str(priv),
                    root_pub=str(root / "w.pub"),
                    registry_port=19440,
                    ost_port=19443,
                    bind="127.0.0.1",
                    advertise="127.0.0.1",
                    root_anchor="/example.com",
                    pid=999999,
                    started_at="2026-01-01T00:00:00Z",
                )
                svc_store.save()

                with patch("dfs.dnssec.has_txt_record", return_value=True), patch.object(
                    cli_main, "discover_domain", return_value=discovered
                ), patch.object(
                    cli_mod, "RemoteRegistryClient", OkReg
                ), patch(
                    "dfs.relay.discover_ice_candidates", return_value=[]
                ), patch.object(
                    svc_mod.Service, "is_running", return_value=True
                ), patch.object(
                    svc_mod, "main", return_value=0
                ) as mock_svc_main:
                    rc = cli_main.main(["join", "--name", "local", "dfs://yashiki.top"])
                self.assertEqual(rc, 0)
                mock_svc_main.assert_called_once_with(["start", "--name", "local", "--force"])

    def test_join_preserves_dfssvc_writer_key_as_rw(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            home = root / "home"
            keys_dir = home / "dfssvc" / "local" / "keys"
            keys_dir.mkdir(parents=True)
            writer_priv = keys_dir / "writer"
            writer_priv.write_text("dummy-priv", encoding="utf-8")
            _, pub = _keypair(root, "w")
            cfg_file = home / "remotes.json"

            class OkReg:
                def __init__(self, urls):
                    pass

                def list_paths(self):
                    return {"root_anchor": "/yashiki.top", "root_pubkey": pub, "paths": {}}

            discovered = SimpleNamespace(
                domain="yashiki.top",
                primary_url="https://l2.yashiki.top",
                alternate_urls=[],
                root_pubkey=pub,
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
                ), patch.object(
                    cli_mod, "RemoteRegistryClient", OkReg
                ), patch(
                    "dfs.relay.discover_ice_candidates", return_value=[]
                ), patch.object(
                    cli_main, "_detect_external_ip", return_value="203.0.113.10"
                ), patch(
                    "socket.gethostname", return_value="mac-test"
                ):
                    rc = cli_main.main(["join", "--name", "local", "dfs://yashiki.top"])
                self.assertEqual(rc, 0)
                expected_id = cli_main.default_subtree_name("203.0.113.10", "mac-test")
                self.assertEqual(
                    expected_id,
                    cli_main.default_subtree_name("203.0.113.10", "mac-test"),
                )
                self.assertNotEqual(
                    expected_id,
                    cli_main.default_subtree_name("203.0.113.11", "mac-test"),
                )
                remote = RemoteStore(cfg_file).get("local")
                self.assertEqual(remote.key, str(writer_priv))
                self.assertEqual(remote.path, f"/yashiki.top/{expected_id}")
                self.assertFalse(remote.read_only)

    def test_open_remote_resets_pin_when_subtree_changes(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            workdir = root / "wd"
            meta = workdir / ".clayfs"
            meta.mkdir(parents=True)
            (workdir / "tree").mkdir()
            priv, pub = _keypair(root, "w")
            pin_file = meta / "local_head.json"
            pin_file.write_text('{"version": 2, "entry_hash": "abc", "delegation_epoch": 1}', encoding="utf-8")
            cfg_file = meta / cli_mod.CONFIG_FILENAME
            cfg_file.write_text(
                json.dumps(
                    {
                        "node_name": "local",
                        "registry_url": "http://127.0.0.1:19440",
                        "ost_endpoint": "127.0.0.1:19441",
                        "ost_host": "127.0.0.1",
                        "ost_port": 19441,
                        "sub_path": "/example.com/local",
                        "priv_key": str(priv),
                        "root_pubkey": pub,
                        "tree_secret": "s",
                        "read_only": False,
                    }
                ),
                encoding="utf-8",
            )
            remote = Remote(
                name="local",
                registry="https://l2.yashiki.top",
                key=str(priv),
                ost="127.0.0.1:19441",
                path="/yashiki.top/new_node",
                secret="s",
                workdir=str(workdir),
                root_pubkey=pub,
                read_only=False,
            )
            node = cli_main.open_remote(remote)
            self.assertFalse(pin_file.exists())
            self.assertEqual(node.l4.pin.version, 0)

    def test_auto_delegate_registers_new_leaf_and_blocks_hijack(self) -> None:
        from http.server import ThreadingHTTPServer

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            root_priv, root_pub = _keypair(root, "root")
            _, pub_a = _keypair(root, "writer_a")
            _, pub_b = _keypair(root, "writer_b")
            state_dir = root / "state"
            state_dir.mkdir()
            ost_dir = root / "ost"
            ost_dir.mkdir()
            pstate = cli_mod.PersistentRegistryState(
                state_dir, "/yashiki.top", root_pub, chunks_dir=ost_dir
            )
            pstate.auto_delegate_key = root_priv
            handler = cli_mod.make_registry_http_handler(pstate, None)  # type: ignore[arg-type]
            httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
            t = threading.Thread(target=httpd.serve_forever, daemon=True)
            t.start()
            try:
                client = cli_mod.RemoteRegistryClient(f"http://127.0.0.1:{httpd.server_port}")
                res_a = client.auto_delegate("/yashiki.top/nodeA", pub_a)
                self.assertTrue(res_a["ok"])

                # 同一書き手なら冪等に成功
                res_a2 = client.auto_delegate("/yashiki.top/nodeA", pub_a)
                self.assertTrue(res_a2.get("already_registered"))

                # 別の書き手による既存パスの乗っ取りは拒否
                with self.assertRaises(cli_mod.ConflictError):
                    client.auto_delegate("/yashiki.top/nodeA", pub_b)

                # 多段パスは拒否
                with self.assertRaises(cli_mod.RegistryError):
                    client.auto_delegate("/yashiki.top/nodeA/sub", pub_b)

                # 未使用の直下パスなら別の書き手も参加可能
                res_b = client.auto_delegate("/yashiki.top/nodeB", pub_b)
                self.assertTrue(res_b["ok"])
            finally:
                httpd.shutdown()
                httpd.server_close()

    def test_remote_domain_candidate_prefers_registry_over_dotted_alias(self) -> None:
        from dfs.remotes import Remote

        self.assertEqual(
            cli_main._remote_domain_candidate(
                Remote(name="backup.v1", registry="https://dfs.example.com", key="")
            ),
            "dfs.example.com",
        )
        self.assertEqual(
            cli_main._remote_domain_candidate(
                Remote(name="yashiki.top", registry="https://l2.yashiki.top", key="")
            ),
            "yashiki.top",
        )
        self.assertEqual(
            cli_main._remote_domain_candidate(
                Remote(name="backup.v1", registry="http://127.0.0.1:9440", key="")
            ),
            "",
        )

    def test_ensure_remote_secret_accepts_explicit_store_and_probe_timeout(self) -> None:
        from unittest.mock import patch
        from dfs.remotes import Remote, RemoteStore

        with tempfile.TemporaryDirectory() as td:
            cfg = Path(td) / "custom_remotes.json"
            store = RemoteStore(cfg)
            remote = Remote(name="r1", registry="https://dfs.example.com", key="")
            store.set(remote)
            with patch.object(cli_main, "prompt_secret", return_value="explicit-sec"):
                updated = cli_main._ensure_remote_secret(remote, store=store)
            self.assertEqual(updated.secret, "explicit-sec")
            self.assertEqual(store.get("r1").secret, "explicit-sec")

        seen_timeouts = []

        class SpyClient(cli_mod.RemoteRegistryClient):
            def list_paths(self):
                seen_timeouts.append(self.default_timeout)
                return {"root_anchor": "/", "root_pubkey": "", "paths": {}}

        with patch.object(cli_main, "_probe_registry_tcp", return_value=True), patch.object(
            cli_mod, "RemoteRegistryClient", SpyClient
        ), patch("dfs.dnssec.has_txt_record", return_value=False):
            st = cli_main._probe_remote_status(
                Remote(name="local", registry="http://127.0.0.1:9440", key="")
            )
        self.assertTrue(st["l2_ok"])
        self.assertEqual(seen_timeouts, [1.5])

    def test_l3_batch_get_enforces_total_byte_cap(self) -> None:
        import ssl
        import socket
        import struct
        from dfs.crypto import sha256_hex
        from dfs.l3_ost_adapter import ChunkStoreServer, MAX_OST_HTTP_BODY_BYTES

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cert, key = root / "cert.pem", root / "key.pem"
            subprocess.run(
                [
                    "openssl", "req", "-x509", "-newkey", "rsa:2048",
                    "-keyout", str(key), "-out", str(cert),
                    "-days", "1", "-nodes", "-subj", "/CN=localhost",
                ],
                check=True,
                capture_output=True,
            )
            srv = ChunkStoreServer(cert, key)
            try:
                blob = b"A" * 65536
                wid = sha256_hex(blob)
                srv.store[wid] = blob
                # Total frame size exceeds MAX_OST_HTTP_BODY_BYTES when requested enough times
                count = (MAX_OST_HTTP_BODY_BYTES // (4 + len(blob))) + 10
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with socket.create_connection(("127.0.0.1", srv.port), timeout=5) as raw:
                    with ctx.wrap_socket(raw, server_hostname="localhost") as s:
                        s.sendall(
                            b"F"
                            + (b"0" * 64)
                            + struct.pack(">I", count)
                            + (wid.encode("ascii") * count)
                        )
                        resp = s.recv(16)
                self.assertEqual(resp[:1], b"E")
            finally:
                srv.close()

    def test_windows_path_traversal_ads_and_setuid_mode_mitigations(self) -> None:
        from dfs.crypto import normalize_name
        from dfs.l4_log import MerkleTreeBuilder

        for bad in ("..\\evil", "a:stream", "CON", "nul.txt", "trail ", "trail.", "bad\x07name"):
            with self.assertRaises(ValueError, msg=f"Should reject {bad!r}"):
                normalize_name(bad)

        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "script.sh"
            f.write_text("#!/bin/sh\n", encoding="utf-8")
            os.chmod(f, 0o644)
            MerkleTreeBuilder._apply_metadata(f, {"mode": 0o4755})
            self.assertEqual(f.stat().st_mode & 0o7777, 0o755)

    def test_save_ost_chunks_writes_only_dirty_wire_ids(self) -> None:
        from dfs.crypto import sha256_hex
        from dfs.l3_ost_adapter import ChunkStoreServer

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cert, key = root / "cert.pem", root / "key.pem"
            subprocess.run(
                [
                    "openssl", "req", "-x509", "-newkey", "rsa:2048",
                    "-keyout", str(key), "-out", str(cert),
                    "-days", "1", "-nodes", "-subj", "/CN=localhost",
                ],
                check=True,
                capture_output=True,
            )
            srv = ChunkStoreServer(cert, key)
            try:
                pstate = cli_mod.PersistentRegistryState(
                    root / "state", "/example.com", "ssh-ed25519 AAAA", chunks_dir=root / "chunks"
                )
                b1 = b"chunk-one"
                w1 = sha256_hex(b1)
                with srv._store_lock:
                    srv.store[w1] = b1
                    srv._dirty_wire_ids.add(w1)
                pstate.save_ost_chunks(srv)
                self.assertTrue((root / "chunks" / f"{w1}.blk").is_file())
                self.assertEqual(srv._dirty_wire_ids, set())
            finally:
                srv.close()

    def test_ost_client_verifies_cert_sha256_pin(self) -> None:
        from dfs.l3_ost_adapter import ChunkStoreServer, OSTClient, ServiceUnavailableError

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cert1, key1 = root / "cert1.pem", root / "key1.pem"
            cert2, key2 = root / "cert2.pem", root / "key2.pem"
            for cert, key, cn in ((cert1, key1, "ost1"), (cert2, key2, "ost2")):
                subprocess.run(
                    [
                        "openssl", "req", "-x509", "-newkey", "rsa:2048",
                        "-keyout", str(key), "-out", str(cert),
                        "-days", "1", "-nodes", "-subj", f"/CN={cn}",
                    ],
                    check=True,
                    capture_output=True,
                )
            srv = ChunkStoreServer(cert1, key1)
            srv_wrong = ChunkStoreServer(cert2, key2)
            try:
                self.assertEqual(len(srv.cert_sha256), 64)
                ok_client = OSTClient("127.0.0.1", srv.port, expected_cert_sha256=srv.cert_sha256)
                self.assertGreaterEqual(ok_client.probe(), 0.0)

                bad_client = OSTClient(
                    "127.0.0.1", srv.port, expected_cert_sha256=srv_wrong.cert_sha256
                )
                with self.assertRaises(ServiceUnavailableError):
                    bad_client.probe()
            finally:
                srv.close()
                srv_wrong.close()

    def test_l4_rejects_unpinned_tofu_writer_unless_explicit(self) -> None:
        from dfs.crypto import canonical_json, sha256_hex
        from dfs.l1_delegation import DelegationError
        from dfs.l4_log import L4LogClient

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            priv, pub = _keypair(root, "writer")
            _, fake_pub = _keypair(root, "attacker")

            class FakeReg:
                def resolve(self, path):
                    payload = {"path": path, "version": 1, "timestamp": 1000, "writer": fake_pub}
                    return (
                        {"payload": {"writer": fake_pub, "path": path}},
                        None,
                        {"payload": payload, "entry_hash": sha256_hex(canonical_json(payload)), "signature": "bad"},
                    )

            strict = L4LogClient("/example.com/test", priv, pub, root_pubkey=None)
            with self.assertRaises(DelegationError):
                strict.sync_head(FakeReg())  # type: ignore[arg-type]

            tofu = L4LogClient("/example.com/test", priv, pub, root_pubkey=None, allow_tofu=True)
            self.assertEqual(
                tofu._verified_writer({"payload": {"writer": fake_pub}}),
                fake_pub,
            )

    def test_ost_disk_backed_lru_and_quota(self) -> None:
        from dfs.crypto import ChunkIntegrityError, sha256_hex
        from dfs.l3_ost_adapter import ChunkStoreServer, OSTClient

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cert = root / "cert.pem"
            key = root / "key.pem"
            chunks_dir = root / "chunks"
            subprocess.run(
                [
                    "openssl", "req", "-x509", "-newkey", "rsa:2048",
                    "-keyout", str(key), "-out", str(cert),
                    "-days", "1", "-nodes", "-subj", "/CN=127.0.0.1",
                ],
                check=True,
                capture_output=True,
            )
            srv = ChunkStoreServer(
                cert,
                key,
                chunks_dir=chunks_dir,
                max_store_bytes=120,
                max_ram_bytes=60,
            )
            try:
                cli = OSTClient("127.0.0.1", srv.port, expected_cert_sha256=srv.cert_sha256)
                b1 = b"a" * 50
                b2 = b"b" * 50
                b3 = b"c" * 50
                w1 = sha256_hex(b1)
                w2 = sha256_hex(b2)
                w3 = sha256_hex(b3)

                cli.put_if_absent(w1, b1)
                cli.put_if_absent(w2, b2)

                # w1 was evicted from bounded RAM cache (max_ram_bytes=60), but served from disk.
                with srv._store_lock:
                    self.assertNotIn(w1, srv.store)
                    self.assertIn(w2, srv.store)
                self.assertEqual(cli.get(w1), b1)

                # Third chunk pushes total over max_store_bytes=120.
                with self.assertRaises(ChunkIntegrityError):
                    cli.put_if_absent(w3, b3)
                self.assertEqual(cli.batch_has([w3]), {w3: False})
            finally:
                srv.close()

    def test_download_directory_rejects_case_colliding_entries(self) -> None:
        from dfs.crypto import ChunkIntegrityError, ContentAddressedCrypto, canonical_json
        from dfs.l4_log import MerkleTreeBuilder

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            crypto = ContentAddressedCrypto("test-secret")
            f1_plain, f1_wire, f1_blob = crypto.pack_chunk(b"first")
            f2_plain, f2_wire, f2_blob = crypto.pack_chunk(b"second")
            dir_obj = {
                "format": "dfs-dir-v2",
                "entries": [
                    {"name": "Readme.md", "type": "file", "plain_id": f1_plain, "wire_id": f1_wire, "size": 5},
                    {"name": "readme.md", "type": "file", "plain_id": f2_plain, "wire_id": f2_wire, "size": 6},
                ],
            }
            d_plain, d_wire, d_blob = crypto.pack_chunk(canonical_json(dir_obj))
            blobs = {d_wire: d_blob, f1_wire: f1_blob, f2_wire: f2_blob}

            class FakeOST:
                def batch_get(self, wids):
                    return {wid: blobs[wid] for wid in wids if wid in blobs}

            builder = MerkleTreeBuilder(crypto, FakeOST())  # type: ignore[arg-type]
            with self.assertRaises(ChunkIntegrityError):
                builder.download_directory(d_plain, d_wire, root / "out")

    def test_ssh_verify_rejects_whitespace_and_control_identity(self) -> None:
        from dfs.crypto import ssh_sign, ssh_verify

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            priv, pub = _keypair(root, "signer")
            payload = b"hello"
            sig = ssh_sign(priv, "dfs", payload)
            self.assertTrue(ssh_verify(pub, "alice@example.com", "dfs", payload, sig))
            for bad_id in ("", "alice bob", "alice\nbob", "alice\x00bob"):
                self.assertFalse(ssh_verify(pub, bad_id, "dfs", payload, sig))

    def test_web_login_rate_limits_repeated_failures(self) -> None:
        import json
        import threading
        import urllib.error
        import urllib.request
        from http.server import ThreadingHTTPServer
        from dfs.web import WebConfig, make_web_handler

        class DummyBackend:
            pass

        cfg = WebConfig(remote_name="test", token="correct-token")
        srv = ThreadingHTTPServer(("127.0.0.1", 0), make_web_handler(DummyBackend(), cfg))  # type: ignore[arg-type]
        th = threading.Thread(target=srv.serve_forever, daemon=True)
        th.start()
        try:
            url = f"http://127.0.0.1:{srv.server_address[1]}/api/login"
            body = json.dumps({"token": "wrong-token"}).encode("utf-8")
            for _ in range(5):
                req = urllib.request.Request(
                    url,
                    data=body,
                    method="POST",
                    headers={"Content-Type": "application/json", "Sec-Fetch-Site": "same-origin"},
                )
                with self.assertRaises(urllib.error.HTTPError) as ctx:
                    urllib.request.urlopen(req, timeout=2.0)
                self.assertEqual(ctx.exception.code, 401)

            req6 = urllib.request.Request(
                url,
                data=body,
                method="POST",
                headers={"Content-Type": "application/json", "Sec-Fetch-Site": "same-origin"},
            )
            with self.assertRaises(urllib.error.HTTPError) as ctx6:
                urllib.request.urlopen(req6, timeout=2.0)
            self.assertEqual(ctx6.exception.code, 429)
            self.assertIsNotNone(ctx6.exception.headers.get("Retry-After"))
        finally:
            srv.shutdown()
            srv.server_close()

    def test_http_ost_disk_persistence_quota_and_restart(self) -> None:
        import struct
        from dfs.crypto import sha256_hex
        from dfs.l3_ost_adapter import ChunkStoreServer, OSTProtocolError

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cert, key = _self_signed_cert(root)
            chunks_dir = root / "chunks"

            # 1) ディスクに既存の .blk がある場合、RAM が空でも batch_has_raw / batch_get_raw が見つけられる
            pre_blob = b"preexisting-disk-chunk"
            pre_wid = sha256_hex(pre_blob)
            chunks_dir.mkdir(parents=True, exist_ok=True)
            (chunks_dir / f"{pre_wid}.blk").write_bytes(pre_blob)

            srv1 = ChunkStoreServer(
                cert, key, chunks_dir=chunks_dir, max_store_bytes=100, max_ram_bytes=64
            )
            try:
                self.assertEqual(srv1.batch_has_raw(pre_wid.encode("ascii")), b"O1")
                got = srv1.batch_get_raw(pre_wid.encode("ascii"))
                self.assertEqual(got, b"O" + struct.pack(">I", len(pre_blob)) + pre_blob)

                # 2) batch_put_raw で入れたチャンクは .blk 永続化され、max_store_bytes も効く
                new_blob = b"http-put-chunk-1"
                new_wid = sha256_hex(new_blob)
                payload = (
                    struct.pack(">I", 1)
                    + new_wid.encode("ascii")
                    + struct.pack(">I", len(new_blob))
                    + new_blob
                )
                srv1.batch_put_raw(payload)
                self.assertTrue((chunks_dir / f"{new_wid}.blk").is_file())

                big_blob = b"X" * 90
                big_wid = sha256_hex(big_blob)
                big_payload = (
                    struct.pack(">I", 1)
                    + big_wid.encode("ascii")
                    + struct.pack(">I", len(big_blob))
                    + big_blob
                )
                with self.assertRaises(OSTProtocolError):
                    srv1.batch_put_raw(big_payload)
            finally:
                srv1.close()

            # 3) 再起動後（別インスタンス）でも HTTP 経由で入れたチャンクを取得できる
            srv2 = ChunkStoreServer(cert, key, chunks_dir=chunks_dir)
            try:
                self.assertEqual(srv2.batch_has_raw(new_wid.encode("ascii")), b"O1")
                got2 = srv2.batch_get_raw(new_wid.encode("ascii"))
                self.assertEqual(got2, b"O" + struct.pack(">I", len(new_blob)) + new_blob)
            finally:
                srv2.close()

    def test_batch_get_checks_size_before_reading_chunks(self) -> None:
        from unittest import mock
        from dfs.crypto import sha256_hex
        from dfs.l3_ost_adapter import ChunkStoreServer, OSTProtocolError, MAX_OST_HTTP_BODY_BYTES

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cert, key = _self_signed_cert(root)
            chunks_dir = root / "chunks"
            chunks_dir.mkdir(parents=True, exist_ok=True)
            srv = ChunkStoreServer(cert, key, chunks_dir=chunks_dir)
            try:
                # 擬似的に上限超えサイズを返す _chunk_size で、_get_chunk が呼ばれないことを検証
                wid1 = sha256_hex(b"a")
                wid2 = sha256_hex(b"b")
                raw_ids = (wid1 + wid2).encode("ascii")
                with mock.patch.object(
                    srv, "_chunk_size", return_value=MAX_OST_HTTP_BODY_BYTES
                ), mock.patch.object(srv, "_get_chunk") as mock_get:
                    with self.assertRaises(OSTProtocolError):
                        srv.batch_get_raw(raw_ids)
                    mock_get.assert_not_called()
            finally:
                srv.close()

    def test_ost_cert_pin_propagation_and_explicit_tofu(self) -> None:
        import time
        from dfs.invite import decode_invite, encode_ro_invite
        from dfs.l1_delegation import DelegationError, create_delegation_envelope
        from dfs.l2_registry import DirectoryRegistryService
        from dfs.l3_ost_adapter import ChunkStoreServer, HttpOSTClient, ServiceUnavailableError
        from dfs.l5_fs import DFSNode

        with self.assertRaises(ValueError):
            HttpOSTClient("http://127.0.0.1:19440/relay/a", expected_cert_sha256="aa" * 32)

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cert, key = _self_signed_cert(root)
            root_priv, root_pub = _keypair(root, "root")
            alice_priv, alice_pub = _keypair(root, "alice")
            srv = ChunkStoreServer(cert, key)
            try:
                reg = DirectoryRegistryService("/example.com", root_pub)
                now = int(time.time())
                env = create_delegation_envelope(
                    root_priv, "/example.com", "/example.com/alice", alice_pub,
                    1, 0, now - 60, now + 3600,
                )
                reg.register_delegation(env, now=now)

                # DFSNode -> make_ost_client へ誤ったピンが伝播し、拒否されること
                bad_node = DFSNode(
                    "alice", "/example.com/alice", root / "wd_bad",
                    alice_priv, alice_pub, "secret", reg, "127.0.0.1", srv.port,
                    root_pubkey=root_pub, ost_cert_sha256="00" * 32,
                )
                (bad_node.clayfs.work_tree / "f.txt").write_text("hi", encoding="utf-8")
                with self.assertRaises(ServiceUnavailableError):
                    bad_node.push(1, now=now)

                # 正しいピンでは成功すること
                good_node = DFSNode(
                    "alice", "/example.com/alice", root / "wd_good",
                    alice_priv, alice_pub, "secret", reg, "127.0.0.1", srv.port,
                    root_pubkey=root_pub, ost_cert_sha256=srv.cert_sha256,
                )
                (good_node.clayfs.work_tree / "f.txt").write_text("hi", encoding="utf-8")
                good_node.push(1, now=now)

                # root_pubkey="" では既定 (allow_tofu=False) で拒否、allow_tofu=True なら許可
                no_tofu = DFSNode(
                    "alice", "/example.com/alice", root / "wd_notofu",
                    alice_priv, alice_pub, "secret", reg, "127.0.0.1", srv.port,
                    root_pubkey="", ost_cert_sha256=srv.cert_sha256,
                )
                with self.assertRaises(DelegationError):
                    no_tofu.pull()

                yes_tofu = DFSNode(
                    "alice", "/example.com/alice", root / "wd_yestofu",
                    alice_priv, alice_pub, "secret", reg, "127.0.0.1", srv.port,
                    root_pubkey="", ost_cert_sha256=srv.cert_sha256, allow_tofu=True,
                )
                yes_tofu.pull()
                self.assertEqual((yes_tofu.clayfs.work_tree / "f.txt").read_text(encoding="utf-8"), "hi")

                # 招待トークンにも ost_cert_sha256 が含まれ往復できること
                tok = encode_ro_invite(
                    name="ro",
                    registries=["http://127.0.0.1:19440"],
                    root_pubkey=root_pub,
                    tree_secret="secret",
                    ost=f"127.0.0.1:{srv.port}",
                    ost_cert_sha256=srv.cert_sha256,
                )
                decoded = decode_invite(tok)
                self.assertEqual(decoded["ost_cert_sha256"], srv.cert_sha256)
            finally:
                srv.close()

    def test_web_query_token_bearer_and_trusted_proxy_rate_limit(self) -> None:
        import threading
        import urllib.error
        import urllib.request
        from http.server import ThreadingHTTPServer
        from dfs.web import WebConfig, make_web_handler

        class DummyBackend:
            pass

        # 1) クエリトークン & Bearer のレート制限（trusted_proxies なし）
        cfg = WebConfig(remote_name="test", token="correct-token")
        srv = ThreadingHTTPServer(("127.0.0.1", 0), make_web_handler(DummyBackend(), cfg))  # type: ignore[arg-type]
        th = threading.Thread(target=srv.serve_forever, daemon=True)
        th.start()
        try:
            base = f"http://127.0.0.1:{srv.server_address[1]}"
            for _ in range(5):
                req = urllib.request.Request(
                    f"{base}/?token=wrong",
                    headers={"X-Forwarded-For": "203.0.113.99"},
                )
                with self.assertRaises(urllib.error.HTTPError) as ctx:
                    urllib.request.urlopen(req, timeout=2.0)
                self.assertEqual(ctx.exception.code, 401)

            # XFF を偽装しても trusted_proxies が空なので 429 になる
            req6 = urllib.request.Request(
                f"{base}/?token=wrong",
                headers={"X-Forwarded-For": "203.0.113.100"},
            )
            with self.assertRaises(urllib.error.HTTPError) as ctx6:
                urllib.request.urlopen(req6, timeout=2.0)
            self.assertEqual(ctx6.exception.code, 429)

            # Bearer ヘッダー認証も同じ IP バケットで 429 になる
            req_bearer = urllib.request.Request(
                f"{base}/api/info",
                headers={"Authorization": "Bearer wrong"},
            )
            with self.assertRaises(urllib.error.HTTPError) as ctx_b:
                urllib.request.urlopen(req_bearer, timeout=2.0)
            self.assertEqual(ctx_b.exception.code, 429)
        finally:
            srv.shutdown()
            srv.server_close()

        # 2) trusted_proxies 指定時は X-Forwarded-For のクライアント IP 単位で分離される
        cfg2 = WebConfig(
            remote_name="test",
            token="correct-token",
            trusted_proxies=("127.0.0.1",),
        )
        srv2 = ThreadingHTTPServer(("127.0.0.1", 0), make_web_handler(DummyBackend(), cfg2))  # type: ignore[arg-type]
        th2 = threading.Thread(target=srv2.serve_forever, daemon=True)
        th2.start()
        try:
            base2 = f"http://127.0.0.1:{srv2.server_address[1]}"
            for _ in range(5):
                req = urllib.request.Request(
                    f"{base2}/api/info",
                    headers={
                        "Authorization": "Bearer wrong",
                        "X-Forwarded-For": "203.0.113.10",
                    },
                )
                with self.assertRaises(urllib.error.HTTPError) as ctx:
                    urllib.request.urlopen(req, timeout=2.0)
                self.assertEqual(ctx.exception.code, 401)
            # 203.0.113.10 はロック
            with self.assertRaises(urllib.error.HTTPError) as ctx_lock:
                urllib.request.urlopen(
                    urllib.request.Request(
                        f"{base2}/api/info",
                        headers={
                            "Authorization": "Bearer wrong",
                            "X-Forwarded-For": "203.0.113.10",
                        },
                    ),
                    timeout=2.0,
                )
            self.assertEqual(ctx_lock.exception.code, 429)
            # 別クライアント 203.0.113.11 はまだ 401（ロックされていない）
            with self.assertRaises(urllib.error.HTTPError) as ctx_other:
                urllib.request.urlopen(
                    urllib.request.Request(
                        f"{base2}/api/info",
                        headers={
                            "Authorization": "Bearer wrong",
                            "X-Forwarded-For": "203.0.113.11",
                        },
                    ),
                    timeout=2.0,
                )
            self.assertEqual(ctx_other.exception.code, 401)
        finally:
            srv2.shutdown()
            srv2.server_close()


if __name__ == "__main__":
    unittest.main()
