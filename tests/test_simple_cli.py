#!/usr/bin/env python3
"""Tests for the unified simplified CLI (dfs.simple_cli / ./cli)."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from dfs import simple_cli, svc as svc_mod
from dfs.remotes import RemoteStore


class SimpleCliTests(unittest.TestCase):
    def test_start_push_ls_pull_stop_roundtrip(self) -> None:
        start_port, _ = svc_mod.find_consecutive_free_ports(25000, 2, "127.0.0.1")
        with tempfile.TemporaryDirectory(prefix="dfs_simple_cli_") as td:
            root = Path(td)
            home = root / "home"
            home.mkdir()
            cfg = root / "remotes.json"
            src = root / "src"
            src.mkdir()
            (src / "hello.txt").write_text("simple cli works\n", encoding="utf-8")
            dst = root / "dst"

            env_patch = {
                "HOME": str(home),
                "XDG_CONFIG_HOME": str(home / ".config"),
                "DFS_HOME": str(home),
                "DFS_CONFIG": str(cfg),
            }
            old = {k: os.environ.get(k) for k in env_patch}
            os.environ.update(env_patch)
            try:
                rc = simple_cli.main(
                    ["start", "--no-hub", "--port", str(start_port), "--secret", "test-sec"]
                )
                self.assertEqual(rc, 0)
                self.assertIn("local", RemoteStore(cfg).remotes)

                self.assertEqual(simple_cli.main(["push", str(src)]), 0)
                self.assertEqual(simple_cli.main(["ls"]), 0)
                self.assertEqual(simple_cli.main(["pull", str(dst)]), 0)
                self.assertEqual(
                    (dst / "hello.txt").read_text(encoding="utf-8"),
                    "simple cli works\n",
                )
            finally:
                try:
                    simple_cli.main(["stop", "--forget"])
                finally:
                    for k, v in old.items():
                        if v is None:
                            os.environ.pop(k, None)
                        else:
                            os.environ[k] = v

    def test_auto_joins_yashiki_top_with_localized_notice(self) -> None:
        import io
        from contextlib import redirect_stderr
        from types import SimpleNamespace
        from unittest.mock import patch

        for lang, expected_sub in (
            ("en", "Using yashiki.top for NAT traversal"),
            ("ja", "NAT を突破するために yashiki.top を利用します"),
            ("fr", "Utilisation de yashiki.top pour la traversée NAT"),
        ):
            with tempfile.TemporaryDirectory(prefix="dfs_simple_i18n_") as td:
                root = Path(td)
                cfg = root / "remotes.json"
                seen_argv: list[list[str]] = []
                fake_svc = SimpleNamespace(
                    is_running=lambda: True,
                    registry_url="http://127.0.0.1:19440",
                    writer_key=str(root / "writer"),
                    root_key=str(root / "root"),
                )

                class FakeStore:
                    services = {}

                    def __init__(self) -> None:
                        if seen_argv:
                            self.services = {"local": fake_svc}

                def fake_svc_main(argv: list[str]) -> int:
                    seen_argv.append(list(argv))
                    return 0

                buf = io.StringIO()
                with patch.dict(
                    os.environ,
                    {"DFS_LANG": lang, "DFS_CONFIG": str(cfg), "DFS_HOME": str(root)},
                ), patch("dfs.svc.ServiceStore", FakeStore), patch(
                    "dfs.svc.main", side_effect=fake_svc_main
                ), patch("dfs.cli_main.main", return_value=0), redirect_stderr(buf):
                    rc = simple_cli.main(["start", "--secret", "s"])
                self.assertEqual(rc, 0)
                self.assertIn("--join", seen_argv[0])
                self.assertIn("https://l2.yashiki.top", seen_argv[0])
                self.assertIn(expected_sub, buf.getvalue())


if __name__ == "__main__":
    unittest.main()
