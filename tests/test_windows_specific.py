#!/usr/bin/env python3
"""Windows 固有機能およびプラットフォーム依存箇所の回帰テスト。"""

import os
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from dfs.crypto import (
    _WINDOWS_RESERVED_NAMES,
    normalize_name,
    normalize_path,
)
from dfs.fs.core import (
    _is_windows_junction,
    _probe_block_clone,
    _windows_cluster_size,
)
from dfs.paths import (
    _windows_user_sid,
    dfs_home,
    restrict_to_owner,
)
from dfs.svc import (
    _process_alive,
    _windows_pid_owns_port,
)


@unittest.skipUnless(sys.platform == "win32", "Windows 固有テスト")
class TestWindowsPlatformSpecific(unittest.TestCase):
    def test_windows_user_sid(self) -> None:
        """whoami 経由でカレントユーザーの SID が取得できること。"""
        sid = _windows_user_sid()
        self.assertTrue(bool(sid), "SID should not be empty")
        self.assertTrue(sid.startswith("S-1-5-"), f"Invalid SID format: {sid}")

    def test_restrict_to_owner_windows_acl(self) -> None:
        """icacls によるアクセス権制限がファイルおよびディレクトリで正常動作すること。"""
        with tempfile.TemporaryDirectory(prefix="dfs_win_acl_") as tmp:
            base = Path(tmp)
            f = base / "secret.txt"
            f.write_text("super-secret", encoding="utf-8")
            restrict_to_owner(f)

            d = base / "secret_dir"
            d.mkdir()
            restrict_to_owner(d)

            # icacls コマンドで ACL 出力が得られることを検証
            res = subprocess.run(
                ["icacls", str(f)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(res.returncode, 0)
            self.assertIn("secret.txt", res.stdout)

    def test_windows_process_alive(self) -> None:
        """OpenProcess + GetExitCodeProcess によるプロセス生存確認の検証。"""
        my_pid = os.getpid()
        self.assertTrue(_process_alive(my_pid))
        self.assertFalse(_process_alive(9999999))
        self.assertFalse(_process_alive(-1))
        self.assertFalse(_process_alive(0))

    def test_windows_pid_owns_port(self) -> None:
        """netstat -ano -p TCP によるポート所有 PID 判定の検証。"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", 0))
        sock.listen(1)
        port = sock.getsockname()[1]
        try:
            my_pid = os.getpid()
            self.assertTrue(_windows_pid_owns_port(my_pid, port))
            self.assertFalse(_windows_pid_owns_port(my_pid + 999999, port))
        finally:
            sock.close()

    def test_windows_cluster_size(self) -> None:
        """GetDiskFreeSpaceW によるクラスタサイズの取得。"""
        cs = _windows_cluster_size("C:\\")
        self.assertGreater(cs, 0)
        self.assertEqual(cs % 512, 0)

    def test_windows_probe_block_clone(self) -> None:
        """_probe_block_clone が ReFS / Dev Drive / NTFS を正しく判定し例外を出さないこと。"""
        with tempfile.TemporaryDirectory(prefix="dfs_win_probe_") as tmp:
            info = _probe_block_clone(Path(tmp))
            # NTFS / 一般ファイルシステムでは None または BackendInfo が返る
            if info is not None:
                self.assertEqual(info.name, "fast_clone")

    def test_windows_reserved_names_rejected(self) -> None:
        """Windows 予約デバイス名 (CON, PRN, AUX, NUL, COM1-9, LPT1-9) の拒否。"""
        reserved_stems = [
            "con", "prn", "aux", "nul",
            "com1", "com9", "lpt1", "lpt9",
            "CON", "PRN", "AUX", "NUL",
        ]
        for stem in reserved_stems:
            for ext in ["", ".txt", ".tar.gz", ".DAT"]:
                name = f"{stem}{ext}"
                with self.assertRaises(ValueError, msg=f"Should reject {name}"):
                    normalize_name(name)
                with self.assertRaises(ValueError, msg=f"Should reject path with {name}"):
                    normalize_path(f"/docs/{name}")

    def test_windows_path_forbidden_characters(self) -> None:
        """コロン (ADS / ドライブ) やバックスラッシュ、末尾空白・ピリオドの拒否。"""
        forbidden = [
            "file:stream",
            "file\\sub",
            "trailing. ",
            "trailing.",
            "trailing ",
        ]
        for name in forbidden:
            with self.assertRaises(ValueError, msg=f"Should reject {name}"):
                normalize_name(name)

    def test_windows_cmd_launchers(self) -> None:
        """dfscli.cmd および dfssvc.cmd が正常に実行できること。"""
        repo_root = Path(__file__).resolve().parent.parent
        cli_cmd = repo_root / "dfscli.cmd"
        svc_cmd = repo_root / "dfssvc.cmd"
        self.assertTrue(cli_cmd.is_file())
        self.assertTrue(svc_cmd.is_file())

        py_exe = sys.executable
        if py_exe.startswith("\\\\?\\UNC\\"):
            py_exe = "\\\\" + py_exe[8:]
        elif py_exe.startswith("\\\\?\\"):
            py_exe = py_exe[4:]

        env = dict(os.environ)
        env["DFSCLI_PYTHON"] = py_exe

        def _clean_path(p: Path) -> str:
            s = str(p)
            if s.startswith("\\\\?\\UNC\\"):
                return "\\\\" + s[8:]
            if s.startswith("\\\\?\\"):
                return s[4:]
            return s

        res_cli = subprocess.run(
            ["cmd.exe", "/c", _clean_path(cli_cmd), "--help"],
            capture_output=True,
            text=True,
            env=env,
            check=False,
        )
        self.assertEqual(res_cli.returncode, 0, f"dfscli.cmd stderr: {res_cli.stderr}")
        self.assertIn("dfscli", res_cli.stdout)

        res_svc = subprocess.run(
            ["cmd.exe", "/c", _clean_path(svc_cmd), "--help"],
            capture_output=True,
            text=True,
            env=env,
            check=False,
        )
        self.assertEqual(res_svc.returncode, 0, f"dfssvc.cmd stderr: {res_svc.stderr}")
        self.assertIn("dfssvc", res_svc.stdout)


if __name__ == "__main__":
    unittest.main()
