#!/usr/bin/env python3
"""dfssvc と dfscli の全サブコマンド一通りの統合 (E2E) テスト。"""

from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dfs import cli_main
from dfs import svc as svc_mod


def _run_cli(argv: list[str]) -> tuple[int, str, str]:
    out_raw = io.BytesIO()
    err_raw = io.BytesIO()
    out_buf = io.TextIOWrapper(out_raw, encoding="utf-8", write_through=True)
    err_buf = io.TextIOWrapper(err_raw, encoding="utf-8", write_through=True)
    with redirect_stdout(out_buf), redirect_stderr(err_buf):
        try:
            rc = cli_main.main(argv)
        except SystemExit as e:
            rc = int(e.code) if isinstance(e.code, int) else 1
    return rc, out_raw.getvalue().decode("utf-8", errors="replace"), err_raw.getvalue().decode("utf-8", errors="replace")


def _run_svc(argv: list[str]) -> tuple[int, str, str]:
    out_buf = io.StringIO()
    err_buf = io.StringIO()
    with redirect_stdout(out_buf), redirect_stderr(err_buf):
        try:
            rc = svc_mod.main(argv)
        except SystemExit as e:
            rc = int(e.code) if isinstance(e.code, int) else 1
    return rc, out_buf.getvalue(), err_buf.getvalue()


class TestCliAndSvcE2E(unittest.TestCase):
    def setUp(self) -> None:
        self._td = tempfile.TemporaryDirectory()
        self.root = Path(self._td.name)
        self.home = self.root / "home"
        self.home.mkdir()
        self.cfg_file = self.home / "remotes.json"
        self.env_patch = patch.dict(
            os.environ,
            {
                "HOME": str(self.home),
                "XDG_CONFIG_HOME": str(self.home / ".config"),
                "DFS_HOME": str(self.home),
                "DFS_CONFIG": str(self.cfg_file),
            },
        )
        self.env_patch.start()
        self.started_name: str | None = None

    def tearDown(self) -> None:
        if self.started_name:
            try:
                _run_svc(["stop", self.started_name, "--forget"])
            except Exception:
                pass
        self.env_patch.stop()
        self._td.cleanup()

    def test_all_subcommand_helps_work(self) -> None:
        svc_parser = svc_mod.build_parser()
        svc_sub = next(a for a in svc_parser._actions if getattr(a, "choices", None))
        for subcmd in svc_sub.choices:
            rc, out, err = _run_svc([subcmd, "--help"])
            self.assertEqual(rc, 0, f"dfssvc {subcmd} --help failed: {err}")
            self.assertTrue(out.strip(), f"dfssvc {subcmd} --help produced empty output")

        cli_parser = cli_main.build_parser()
        cli_sub = next(a for a in cli_parser._actions if getattr(a, "choices", None))
        for subcmd in cli_sub.choices:
            rc, out, err = _run_cli([subcmd, "--help"])
            self.assertEqual(rc, 0, f"dfscli {subcmd} --help failed: {err}")
            self.assertTrue(out.strip(), f"dfscli {subcmd} --help produced empty output")

    def test_dfssvc_lifecycle_and_dfscli_commands_e2e(self) -> None:
        start_port, _ = svc_mod.find_consecutive_free_ports(24000, 2, "127.0.0.1")
        self.started_name = "e2e"

        # 1) dfssvc 起動・一覧・状態・env・dnssec・logs・停止・再開・force再起動
        rc, out, err = _run_svc(["start", "--name", "e2e", "--port", str(start_port)])
        self.assertEqual(rc, 0, f"start failed: {out}\n{err}")

        rc, out, err = _run_svc(["list"])
        self.assertEqual(rc, 0, err)
        self.assertIn("e2e", out)

        rc, out, err = _run_svc(["--json", "list"])
        self.assertEqual(rc, 0, err)
        rows = json.loads(out)
        self.assertEqual(rows[0]["name"], "e2e")
        self.assertTrue(rows[0]["running"])

        rc, out, err = _run_svc(["status", "e2e"])
        self.assertEqual(rc, 0, err)
        self.assertIn("稼働中", out)

        rc, out, err = _run_svc(["status", "--name", "e2e"])
        self.assertEqual(rc, 0, err)
        self.assertIn("稼働中", out)

        rc, out, err = _run_svc(["env", "e2e"])
        self.assertEqual(rc, 0, err)
        self.assertIn("dfscli create e2e", out)

        rc, out, err = _run_svc(["dnssec", "e2e", "--domain", "example.com"])
        self.assertEqual(rc, 0, err)
        self.assertEqual(json.loads(out)["domain"], "example.com")

        rc, out, err = _run_svc(["logs", "e2e", "-n", "10"])
        self.assertEqual(rc, 0, err)

        rc, out, err = _run_svc(["stop", "e2e"])
        self.assertEqual(rc, 0, err)

        # 停止中なら --force なし + 位置引数で再開できること
        rc, out, err = _run_svc(["start", "e2e", "--port", str(start_port)])
        self.assertEqual(rc, 0, f"resume start failed: {out}\n{err}")

        # 稼働中の --force 無しはエラー、--force ありは再起動できること
        rc, out, err = _run_svc(["start", "e2e", "--port", str(start_port)])
        self.assertEqual(rc, 2)
        rc, out, err = _run_svc(["start", "e2e", "--port", str(start_port), "--force"])
        self.assertEqual(rc, 0, f"force restart failed: {out}\n{err}")

        # 2) dfscli リモート確認・ファイル操作一通り
        svc = svc_mod.ServiceStore().get("e2e")
        reg_url = f"http://{svc.bind}:{svc.registry_port}"

        # dfssvc start 時に自動登録されたリモート e2e に secret を設定
        rc, out, err = _run_cli([
            "config", "create", "e2e",
            "--registry", reg_url,
            "--key", svc.writer_key,
            "--path", svc.sub_path,
            "--secret", "e2e-secret-123",
            "--root-pubkey", svc.root_pub,
        ])
        self.assertEqual(rc, 0, f"config create failed: {out}\n{err}")

        rc, out, err = _run_cli(["config", "show", "e2e"])
        self.assertEqual(rc, 0, err)
        self.assertIn("e2e", out)

        with patch.object(cli_main, "_probe_root_dfs_domain", return_value={
            "name": "example.com",
            "registered": False,
            "registry": "",
            "path": "/example.com",
            "online": False,
            "l2_ok": None,
            "l2_error": "",
            "role": "root",
            "root_anchor": "",
            "paths_count": None,
            "dnssec": "none",
            "dnssec_record": "_dfs.example.com",
            "dnssec_error": "",
        }):
            rc, out, err = _run_cli(["listremotes"])
        self.assertEqual(rc, 0, err)
        self.assertIn("dfs://e2e/", out)

        rc, out, err = _run_cli(["touch", "dfs://e2e/"])
        self.assertEqual(rc, 0, f"touch failed: {out}\n{err}")

        rc, out, err = _run_cli(["about", "dfs://e2e/"])
        self.assertEqual(rc, 0, f"about failed: {out}\n{err}")

        rc, out, err = _run_cli(["mkdir", "dfs://e2e/dir1"])
        self.assertEqual(rc, 0, f"mkdir failed: {out}\n{err}")

        src_dir = self.root / "src"
        src_dir.mkdir()
        sample_file = src_dir / "hello.txt"
        sample_file.write_text("hello dfs e2e\n", encoding="utf-8", newline="\n")

        rc, out, err = _run_cli(["copy", str(sample_file), "dfs://e2e/dir1/"])
        self.assertEqual(rc, 0, f"copy failed: {out}\n{err}")

        rc, out, err = _run_cli(["copyto", str(sample_file), "dfs://e2e/dir1/renamed.txt"])
        self.assertEqual(rc, 0, f"copyto failed: {out}\n{err}")

        rc, out, err = _run_cli(["ls", "dfs://e2e/dir1"])
        self.assertEqual(rc, 0, f"ls failed: {out}\n{err}")
        self.assertIn("hello.txt", out)
        self.assertIn("renamed.txt", out)

        rc, out, err = _run_cli(["lsd", "dfs://e2e/"])
        self.assertEqual(rc, 0, f"lsd failed: {out}\n{err}")
        self.assertIn("dir1", out)

        rc, out, err = _run_cli(["lsl", "dfs://e2e/dir1"])
        self.assertEqual(rc, 0, f"lsl failed: {out}\n{err}")
        self.assertIn("hello.txt", out)

        rc, out, err = _run_cli(["lsjson", "dfs://e2e/dir1"])
        self.assertEqual(rc, 0, f"lsjson failed: {out}\n{err}")
        items = json.loads(out)
        self.assertTrue(any(i.get("Name") == "hello.txt" or i.get("Path", "").endswith("hello.txt") for i in items))

        rc, out, err = _run_cli(["size", "dfs://e2e/"])
        self.assertEqual(rc, 0, f"size failed: {out}\n{err}")

        rc, out, err = _run_cli(["cat", "dfs://e2e/dir1/renamed.txt"])
        self.assertEqual(rc, 0, f"cat failed: {out}\n{err}")
        self.assertEqual(out, "hello dfs e2e\n")

        rc, out, err = _run_cli(["mv", "dfs://e2e/dir1/renamed.txt", "dfs://e2e/dir1/moved.txt"])
        self.assertEqual(rc, 0, f"mv failed: {out}\n{err}")

        pull_dir = self.root / "pulled"
        rc, out, err = _run_cli(["pull", "dfs://e2e/dir1", str(pull_dir)])
        self.assertEqual(rc, 0, f"pull failed: {out}\n{err}")
        self.assertEqual((pull_dir / "moved.txt").read_text(encoding="utf-8"), "hello dfs e2e\n")

        rc, out, err = _run_cli(["check", "dfs://e2e/dir1", str(pull_dir)])
        self.assertEqual(rc, 0, f"check failed: {out}\n{err}")

        sync_dir = self.root / "sync_src"
        sync_dir.mkdir()
        (sync_dir / "a.txt").write_text("sync-a\n", encoding="utf-8")
        rc, out, err = _run_cli(["sync", str(sync_dir), "dfs://e2e/synced"])
        self.assertEqual(rc, 0, f"sync failed: {out}\n{err}")

        rc, out, err = _run_cli(["history", "dfs://e2e/"])
        self.assertEqual(rc, 0, f"history failed: {out}\n{err}")

        rc, out, err = _run_cli(["rm", "dfs://e2e/dir1/moved.txt"])
        self.assertEqual(rc, 0, f"rm failed: {out}\n{err}")

        rc, out, err = _run_cli(["mkdir", "dfs://e2e/emptydir"])
        self.assertEqual(rc, 0, f"mkdir emptydir failed: {out}\n{err}")
        rc, out, err = _run_cli(["rmdir", "dfs://e2e/emptydir"])
        self.assertEqual(rc, 0, f"rmdir failed: {out}\n{err}")

        rc, out, err = _run_cli(["purge", "dfs://e2e/synced"])
        self.assertEqual(rc, 0, f"purge failed: {out}\n{err}")

        # 3) invite / join / quit / config delete
        rc, out, err = _run_cli(["invite", "create", "e2e"])
        self.assertEqual(rc, 0, f"invite create failed: {out}\n{err}")
        token = out.strip()
        self.assertTrue(token.startswith("dfs-ro-v1:") or token.startswith("dfs-rw-v1:"))

        rc, out, err = _run_cli(["join", f"dfs-invite://{token}", "--name", "ro_e2e"])
        self.assertEqual(rc, 0, f"join invite failed: {out}\n{err}")

        rc, out, err = _run_cli(["ls", "dfs://ro_e2e/dir1"])
        self.assertEqual(rc, 0, f"ro ls failed: {out}\n{err}")
        self.assertIn("hello.txt", out)

        rc, out, err = _run_cli(["config", "delete", "ro_e2e"])
        self.assertEqual(rc, 0, f"config delete failed: {out}\n{err}")

        # 4) dfssvc stop --forget (--name 指定も確認)
        rc, out, err = _run_svc(["stop", "--name", "e2e", "--forget"])
        self.assertEqual(rc, 0, f"stop --forget failed: {out}\n{err}")
        self.started_name = None


if __name__ == "__main__":
    unittest.main()
