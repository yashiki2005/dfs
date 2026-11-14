#!/usr/bin/env python3
"""Tests for dfs.web mobile file sharing and Web CLI server."""

from __future__ import annotations

import http.client
import json
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dfs import cli_main
from dfs.web import DFSWebBackend, WebConfig, start_web_server


class TestWebCLI(unittest.TestCase):
    def _make_server(
        self,
        work_tree: Path,
        *,
        token: str = "tok-secret-123",
        read_only: bool = False,
        ttl_seconds: int = 0,
        base_path: str = "",
        started_at: float = 0.0,
    ):
        state = {"ver": 1, "syncs": 0, "pushes": 0}

        def _sync(_force: bool) -> int:
            state["syncs"] += 1
            return state["ver"]

        def _push() -> int:
            state["pushes"] += 1
            state["ver"] += 1
            return state["ver"]

        backend = DFSWebBackend(
            work_tree=work_tree,
            remote_name="phone",
            read_only=read_only,
            sync_fn=_sync,
            push_fn=_push,
            status_fn=lambda: {"workdir": str(work_tree)},
        )
        cfg = WebConfig(
            remote_name="phone",
            token=token,
            read_only=read_only,
            ttl_seconds=ttl_seconds,
            base_path=base_path,
            started_at=started_at,
        )
        httpd = start_web_server(backend, cfg, bind="127.0.0.1", port=0)
        t = threading.Thread(target=httpd.serve_forever, daemon=True)
        t.start()
        return httpd, state

    def test_auth_cookie_base_path_upload_download_and_cli(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            wt = Path(td)
            (wt / "hello.txt").write_text("world\n", encoding="utf-8")
            (wt / "evil.html").write_text("<script>alert(1)</script>", encoding="utf-8")
            httpd, state = self._make_server(wt, base_path="/dfs")
            try:
                port = httpd.server_address[1]
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)

                # Unauthenticated API call returns 401
                conn.request("GET", "/dfs/api/ls")
                r = conn.getresponse()
                r.read()
                self.assertEqual(r.status, 401)

                # Token query login sets HttpOnly cookie and Secure when X-Forwarded-Proto=https
                conn.request(
                    "GET",
                    "/dfs/?token=tok-secret-123",
                    headers={"X-Forwarded-Proto": "https"},
                )
                r = conn.getresponse()
                r.read()
                self.assertEqual(r.status, 302)
                set_cookie = r.getheader("Set-Cookie") or ""
                self.assertIn("HttpOnly", set_cookie)
                self.assertIn("SameSite=Lax", set_cookie)
                self.assertIn("Secure", set_cookie)
                cookie_pair = set_cookie.split(";", 1)[0]

                # Fetch HTML page and check CSP nonce + security headers
                conn.request("GET", "/dfs/", headers={"Cookie": cookie_pair})
                r = conn.getresponse()
                html = r.read().decode("utf-8")
                self.assertEqual(r.status, 200)
                self.assertIn("script-src 'nonce-", r.getheader("Content-Security-Policy") or "")
                self.assertEqual(r.getheader("X-Content-Type-Options"), "nosniff")
                self.assertEqual(r.getheader("X-Frame-Options"), "DENY")
                self.assertIn("dfs web", html)

                # List files
                conn.request("GET", "/dfs/api/ls", headers={"Cookie": cookie_pair})
                r = conn.getresponse()
                listing = json.loads(r.read().decode("utf-8"))
                self.assertEqual(r.status, 200)
                names = {e["name"] for e in listing["entries"]}
                self.assertEqual(names, {"hello.txt", "evil.html"})

                # HTML inline download must be forced to attachment + octet-stream
                conn.request(
                    "GET",
                    "/dfs/api/download?inline=1&path=evil.html",
                    headers={"Cookie": cookie_pair},
                )
                r = conn.getresponse()
                r.read()
                self.assertEqual(r.status, 200)
                self.assertIn("attachment", r.getheader("Content-Disposition") or "")
                self.assertEqual(r.getheader("Content-Type"), "application/octet-stream")

                # Upload binary file
                conn.request(
                    "POST",
                    "/dfs/api/upload?path=sub/photo.jpg",
                    body=b"\xff\xd8\xff\xe0test",
                    headers={
                        "Cookie": cookie_pair,
                        "Content-Type": "application/octet-stream",
                    },
                )
                r = conn.getresponse()
                up = json.loads(r.read().decode("utf-8"))
                self.assertEqual(r.status, 200)
                self.assertEqual(up["path"], "sub/photo.jpg")
                self.assertEqual((wt / "sub" / "photo.jpg").read_bytes(), b"\xff\xd8\xff\xe0test")
                self.assertEqual(state["pushes"], 1)

                # Traversal blocked
                conn.request(
                    "GET",
                    "/dfs/api/ls?path=../outside",
                    headers={"Cookie": cookie_pair},
                )
                r = conn.getresponse()
                r.read()
                self.assertEqual(r.status, 400)

                # Web CLI commands
                conn.request(
                    "POST",
                    "/dfs/api/cli",
                    body=json.dumps({"command": "cd sub", "cwd": ""}).encode("utf-8"),
                    headers={"Cookie": cookie_pair, "Content-Type": "application/json"},
                )
                r = conn.getresponse()
                res = json.loads(r.read().decode("utf-8"))
                self.assertTrue(res["ok"])
                self.assertEqual(res["cwd"], "sub")

                conn.request(
                    "POST",
                    "/dfs/api/cli",
                    body=json.dumps({"command": "cat /hello.txt", "cwd": "sub"}).encode("utf-8"),
                    headers={"Cookie": cookie_pair, "Content-Type": "application/json"},
                )
                r = conn.getresponse()
                res = json.loads(r.read().decode("utf-8"))
                self.assertTrue(res["ok"])
                self.assertIn("world", res["output"])

                # Cross-site fetch metadata blocked
                conn.request(
                    "GET",
                    "/dfs/api/ls",
                    headers={"Cookie": cookie_pair, "Sec-Fetch-Site": "cross-site"},
                )
                r = conn.getresponse()
                r.read()
                self.assertEqual(r.status, 403)

                # Logout clears cookie & sends Clear-Site-Data
                conn.request("POST", "/dfs/api/logout", headers={"Cookie": cookie_pair})
                r = conn.getresponse()
                r.read()
                self.assertEqual(r.status, 200)
                self.assertIn("cookies", r.getheader("Clear-Site-Data") or "")
                conn.close()
            finally:
                httpd.shutdown()
                httpd.server_close()

    def test_readonly_and_ttl_enforcement(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            wt = Path(td)
            (wt / "note.txt").write_text("ro", encoding="utf-8")
            httpd, _ = self._make_server(wt, read_only=True)
            try:
                port = httpd.server_address[1]
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                headers = {
                    "Authorization": "Bearer tok-secret-123",
                    "Content-Type": "application/json",
                }
                conn.request(
                    "POST",
                    "/api/mkdir",
                    body=b'{"path":"newdir"}',
                    headers=headers,
                )
                r = conn.getresponse()
                r.read()
                self.assertEqual(r.status, 403)

                conn.request(
                    "POST",
                    "/api/cli",
                    body=b'{"command":"rm note.txt","cwd":""}',
                    headers=headers,
                )
                r = conn.getresponse()
                res = json.loads(r.read().decode("utf-8"))
                self.assertFalse(res["ok"])
                self.assertTrue((wt / "note.txt").exists())
                conn.close()
            finally:
                httpd.shutdown()
                httpd.server_close()

            # Expired TTL returns 403
            httpd2, _ = self._make_server(
                wt, ttl_seconds=10, started_at=time.time() - 100
            )
            try:
                port2 = httpd2.server_address[1]
                conn2 = http.client.HTTPConnection("127.0.0.1", port2, timeout=5)
                conn2.request(
                    "GET",
                    "/api/ls",
                    headers={"Authorization": "Bearer tok-secret-123"},
                )
                r = conn2.getresponse()
                r.read()
                self.assertEqual(r.status, 403)
                conn2.close()
            finally:
                httpd2.shutdown()
                httpd2.server_close()

    def test_cli_web_help(self) -> None:
        parser = cli_main.build_parser()
        args_default = parser.parse_args(["web"])
        self.assertIsNone(args_default.remote)
        self.assertIsNone(args_default.bind)
        self.assertIsNone(args_default.port)

        args = parser.parse_args(["web", "myremote", "--bind", "0.0.0.0", "--port", "8080", "--read-only"])
        self.assertEqual(args.remote, "myremote")
        self.assertEqual(args.bind, "0.0.0.0")
        self.assertEqual(args.port, 8080)
        self.assertTrue(args.read_only)

    def test_auto_register_from_dfssvc_service(self) -> None:
        from unittest.mock import patch
        from dfs.remotes import RemoteStore
        from dfs.svc import Service, ServiceStore

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            home = root / "home"
            home.mkdir()
            pub_file = root / "root.pub"
            pub_file.write_text("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest\n", encoding="utf-8")
            with patch.dict("os.environ", {"DFS_HOME": str(home), "DFS_CONFIG": str(home / "remotes.json")}):
                svc_store = ServiceStore()
                svc_store.services["local"] = Service(
                    name="local",
                    state_dir=str(root / "state"),
                    root_key=str(root / "root"),
                    root_pub=str(pub_file),
                    registry_port=19440,
                    ost_port=19441,
                    bind="127.0.0.1",
                    advertise="127.0.0.1",
                    root_anchor="/example.com",
                    pid=999999,
                    started_at="2026-01-01T00:00:00Z",
                    writer_key=str(root / "writer"),
                    sub_path="/example.com/local",
                )
                svc_store.save()
                r_store = RemoteStore()
                with self.assertRaises(cli_main.UsageError) as ctx:
                    cli_main._ensure_remote_from_service(r_store, "local")
                self.assertIn("dfscli config create local", str(ctx.exception))
                self.assertIn("dfssvc env local", str(ctx.exception))
                self.assertNotIn("local", r_store.remotes)


if __name__ == "__main__":
    unittest.main()
