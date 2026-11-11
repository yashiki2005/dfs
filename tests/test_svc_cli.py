#!/usr/bin/env python3
"""
dfs5/tests/test_svc_cli.py
`dfs5svc`（ローカルにサーバを立てるコマンド）の試験。

実際に dfs5 サーバを起動するので、各試験では一時ディレクトリを HOME に見立てて
他のサービスとぶつからないようにする。プロセスは必ず後始末する。
"""

import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dfs5.svc import (
    Service,
    ServiceError,
    ServiceStore,
    find_consecutive_free_ports,
    is_port_free,
    main as svc_main,
)

ROOT = Path(__file__).resolve().parents[1]
PY = sys.executable


def l2_probe(url: str, path: str = "/example.com", timeout: float = 3.0) -> bool:
    import urllib.request

    body = json.dumps({"path": path}).encode("utf-8")
    req = urllib.request.Request(
        f"{url}/v1/resolve", data=body,
        headers={"Content-Type": "application/json"}, method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status == 200
    except Exception:  # noqa: BLE001
        return False


class PortTests(unittest.TestCase):
    """空きポートの探索（サーバは立てない）。"""

    def test_consecutive_ports_are_adjacent(self) -> None:
        start, second = find_consecutive_free_ports(19440, 2, "127.0.0.1")
        self.assertEqual(second, start + 1)

    def test_busy_port_is_skipped(self) -> None:
        """実際に待ち受けたポートは使われていると判定される。"""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("127.0.0.1", 0))
        s.listen(1)
        port = s.getsockname()[1]
        try:
            self.assertFalse(is_port_free(port), "待ち受け中のポートを空きと判定した")
        finally:
            s.close()

    def test_start_port_that_is_busy_is_avoided(self) -> None:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("127.0.0.1", 0))
        s.listen(1)
        port = s.getsockname()[1]
        try:
            first, second = find_consecutive_free_ports(port, 2, "127.0.0.1")
            self.assertNotEqual(first, port)
            self.assertGreater(first, port)
            self.assertEqual(second, first + 1)
        finally:
            s.close()

    def test_out_of_range_start_is_rejected(self) -> None:
        with self.assertRaises(ServiceError):
            find_consecutive_free_ports(65535, 2, "127.0.0.1")


class ServiceRecordTests(unittest.TestCase):
    """記録の読み書き（サーバは立てない）。"""

    def test_store_roundtrip_with_600(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "services.json"
            store = ServiceStore(path)
            store.services["a"] = Service(
                name="a", state_dir="/tmp/a", root_key="/tmp/a/k", root_pub="/tmp/a/k.pub",
                registry_port=19440, ost_port=19441, bind="127.0.0.1", advertise="127.0.0.1",
                root_anchor="/example.com", pid=0, started_at="2026-01-01T00:00:00+00:00",
            )
            store.save()
            self.assertEqual(oct(path.stat().st_mode & 0o777), "0o600")
            again = ServiceStore(path)
            self.assertEqual(list(again.services), ["a"])
            self.assertEqual(again.get("a").ost_port, 19441)
            # 派生値（registry_url）はファイルに書かない
            raw = json.loads(path.read_text(encoding="utf-8"))
            self.assertNotIn("registry_url", raw["services"]["a"])


class StartStopTests(unittest.TestCase):
    """実際にサーバを立てて、stop で確実に落ちるところまで。"""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="dfs5svc_test_")
        self.base = Path(self._tmp.name)
        self.home = self.base / "home"
        self.home.mkdir()
        # HOME を差し替えて、記録と状態をこの試験の中に閉じる
        self.old_home = os.environ.get("HOME")
        os.environ["HOME"] = str(self.home)
        self.service: Service | None = None

    def tearDown(self) -> None:
        # 記録に残っているサービスを全部止める。addCleanup は一時ディレクトリの
        # 後始末より後に走ることがあり、その前に確実に落としておく必要がある。
        from dfs5.svc import _stop_process

        try:
            store = ServiceStore()
            for name in list(store.services):
                s = store.services[name]
                _stop_process(s)
            store.services.clear()
            store.save()
        except Exception:  # noqa: BLE001 - 後始末なので落とさない
            pass
        if self.service is not None:
            _stop_process(self.service)
            self.service = None
        if self.old_home is None:
            os.environ.pop("HOME", None)
        else:
            os.environ["HOME"] = self.old_home
        self._tmp.cleanup()

    def test_start_then_stop(self) -> None:
        # 空きポートを 2 つ探してから start する
        start_port, _ = find_consecutive_free_ports(20000, 2, "127.0.0.1")
        rc = svc_main(["start", "--name", "t", "--port", str(start_port), "--wait", "30"])
        self.assertEqual(rc, 0)

        store = ServiceStore()
        service = store.get("t")
        self.service = service
        self.assertTrue(service.is_running(), "起動したのに稼働中と判定されない")
        self.assertEqual(service.ost_port, service.registry_port + 1, "L2 と L3 が連続していない")
        self.assertTrue(l2_probe(service.registry_url), "L2 が resolve に答えない")

        # status は稼働中なら 0
        self.assertEqual(svc_main(["status", "t"]), 0)

        # stop で落ちる
        self.assertEqual(svc_main(["stop", "t"]), 0)
        time.sleep(1)
        self.assertFalse(service.is_running(), "stop したのに動いている")
        self.service = None

    def test_start_registers_delegation(self) -> None:
        """start は書き手の鍵と委譲まで用意する（dfs5cli がそのまま使える）。"""
        start_port, _ = find_consecutive_free_ports(23000, 2, "127.0.0.1")
        self.assertEqual(svc_main(["start", "--name", "d", "--port", str(start_port)]), 0)
        service = ServiceStore().get("d")
        self.service = service

        # 書き手の鍵が作られている
        writer = Path(service.writer_key)
        self.assertTrue(writer.is_file(), "書き手の鍵が無い")
        self.assertTrue(Path(f"{writer}.pub").is_file(), ".pub が無い")

        # L2 に、その書き手の委譲が登録されている
        pub = Path(f"{writer}.pub").read_text(encoding="utf-8").strip()
        import urllib.request

        body = json.dumps({}).encode("utf-8")
        req = urllib.request.Request(
            f"{service.registry_url}/v1/paths", data=body,
            headers={"Content-Type": "application/json"}, method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            rows = json.loads(resp.read().decode("utf-8"))["paths"]
        self.assertTrue(
            any(r["path"] == service.sub_path and r["writer"].strip() == pub for r in rows),
            f"委譲が見つからない: {rows}",
        )
        self.assertEqual(service.sub_path, "/example.com/d")

    def test_ls_works_before_any_write(self) -> None:
        """まだ何も書いていないリモートでも ls が通る（初期化を先に求めない）。"""
        start_port, _ = find_consecutive_free_ports(24000, 2, "127.0.0.1")
        self.assertEqual(svc_main(["start", "--name", "e", "--port", str(start_port)]), 0)
        service = ServiceStore().get("e")
        self.service = service

        # リモートを定義して、touch せずに ls する
        from dfs5.remotes import Remote, RemoteStore

        remotes = RemoteStore()
        remotes.set(Remote(
            name="e", registry=service.registry_url, key=service.writer_key,
            secret="test-secret", workdir=str(self.home / "wd-e"),
        ))
        from dfs5.cli_main import main as rclone_main

        self.assertEqual(rclone_main(["ls", "e:"]), 0, "ls が初期化を要求して失敗した")

    def test_no_delegate_leaves_registry_empty(self) -> None:
        """--no-delegate なら委譲を登録しない（自分で組む場合）。"""
        start_port, _ = find_consecutive_free_ports(25000, 2, "127.0.0.1")
        rc = svc_main(["start", "--name", "nd", "--port", str(start_port), "--no-delegate"])
        self.assertEqual(rc, 0)
        service = ServiceStore().get("nd")
        self.service = service
        self.assertEqual(service.sub_path, "")

        import urllib.request

        body = json.dumps({}).encode("utf-8")
        req = urllib.request.Request(
            f"{service.registry_url}/v1/paths", data=body,
            headers={"Content-Type": "application/json"}, method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            rows = json.loads(resp.read().decode("utf-8"))["paths"]
        self.assertEqual(rows, [], "--no-delegate なのに委譲がある")

    def test_explicit_path_is_used(self) -> None:
        """--path を渡すとそのサブツリーに委譲する（親も自動で張る）。"""
        start_port, _ = find_consecutive_free_ports(26000, 2, "127.0.0.1")
        rc = svc_main([
            "start", "--name", "p", "--port", str(start_port),
            "--path", "/example.com/team/notes",
        ])
        self.assertEqual(rc, 0)
        service = ServiceStore().get("p")
        self.service = service
        self.assertEqual(service.sub_path, "/example.com/team/notes")

        import urllib.request

        body = json.dumps({}).encode("utf-8")
        req = urllib.request.Request(
            f"{service.registry_url}/v1/paths", data=body,
            headers={"Content-Type": "application/json"}, method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            paths = {r["path"] for r in json.loads(resp.read().decode("utf-8"))["paths"]}
        # 中間の /example.com/team と、末端の /example.com/team/notes の両方がある
        self.assertIn("/example.com/team", paths, "中間の委譲が無い")
        self.assertIn("/example.com/team/notes", paths, "末端の委譲が無い")

    def test_same_name_without_force_is_refused(self) -> None:
        start_port, _ = find_consecutive_free_ports(21000, 2, "127.0.0.1")
        self.assertEqual(svc_main(["start", "--name", "dup", "--port", str(start_port)]), 0)
        self.service = ServiceStore().get("dup")
        rc = svc_main(["start", "--name", "dup", "--port", str(start_port)])
        self.assertEqual(rc, 2, "同じ名前を --force 無しで上書きした")

    def test_two_services_get_different_ports(self) -> None:
        start_port, _ = find_consecutive_free_ports(22000, 4, "127.0.0.1")
        self.assertEqual(svc_main(["start", "--name", "s1", "--port", str(start_port)]), 0)
        s1 = ServiceStore().get("s1")
        self.assertEqual(svc_main(["start", "--name", "s2", "--port", str(start_port)]), 0)
        s2 = ServiceStore().get("s2")
        self.assertNotEqual(s1.registry_port, s2.registry_port)
        self.assertNotEqual(s1.ost_port, s2.ost_port)
        self.assertTrue(s2.is_running())


if __name__ == "__main__":
    unittest.main(verbosity=2)
