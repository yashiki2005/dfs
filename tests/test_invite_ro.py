#!/usr/bin/env python3
"""tests/test_invite_ro.py — 読み取り専用招待トークンと read_only リモートの試験。"""

from __future__ import annotations

import base64
import io
import subprocess
import tempfile
import threading
import time
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from dfs import cli as cli_mod
from dfs import cli_main
from dfs.crypto import canonical_json
from dfs.invite import InviteError, decode_ro_invite, encode_ro_invite
from dfs.l1_delegation import create_delegation_envelope
from dfs.l3_ost_adapter import ChunkStoreServer
from dfs.remotes import Remote, RemoteStore


def _gen_ed25519(path: Path) -> tuple[Path, str]:
    subprocess.run(
        ["ssh-keygen", "-t", "ed25519", "-N", "", "-f", str(path)],
        capture_output=True,
        text=True,
        check=True,
    )
    return path, Path(f"{path}.pub").read_text(encoding="utf-8").strip()


class ReadOnlyInviteTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.root_key, self.root_pub = _gen_ed25519(self.root / "root")
        self.writer_key, self.writer_pub = _gen_ed25519(self.root / "writer")
        self.cert = self.root / "ost.crt"
        self.key = self.root / "ost.key"
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", str(self.key), "-out", str(self.cert),
                "-days", "1", "-subj", "/CN=127.0.0.1",
            ],
            capture_output=True,
            check=True,
        )
        self.ost = ChunkStoreServer(self.cert, self.key, host="127.0.0.1", port=0)
        self.state_dir = self.root / "l2"
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.pstate = cli_mod.PersistentRegistryState(
            self.state_dir, "/example.com", self.root_pub
        )
        self.pstate.ost_endpoint = f"127.0.0.1:{self.ost.port}"
        handler = cli_mod.make_registry_http_handler(self.pstate, self.ost)
        self.httpd = cli_mod.BoundedThreadingHTTPServer(
            ("127.0.0.1", 0), handler, max_workers=8
        )
        self.reg_url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

        now = int(time.time())
        del_env = create_delegation_envelope(
            self.root_key,
            "/example.com",
            "/example.com/data",
            self.writer_pub,
            epoch=1,
            base_version=0,
            issued_at=now - 10,
            expires_at=now + 3600,
        )
        cli_mod.RemoteRegistryClient(self.reg_url).register_delegation(del_env, now=now)

    def tearDown(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.ost.close()
        self._tmp.cleanup()

    def test_encode_decode_ro_invite_validation(self) -> None:
        token = encode_ro_invite(
            name="runpod",
            registries=[self.reg_url],
            root_pubkey=self.root_pub,
            tree_secret="my-secret",
            path="/example.com/data",
            poll_seconds=15,
        )
        self.assertTrue(token.startswith("dfs-ro-v1:"))
        info = decode_ro_invite(token)
        self.assertEqual(info["mode"], "read-only")
        self.assertEqual(info["name"], "runpod")
        self.assertEqual(info["path"], "/example.com/data")
        self.assertEqual(info["poll_seconds"], 15)
        self.assertEqual(info["kdf"], "scrypt-v1")

        legacy_payload = dict(info)
        legacy_payload.pop("kdf")
        encoded = base64.urlsafe_b64encode(
            canonical_json(legacy_payload)
        ).decode("ascii").rstrip("=")
        legacy_info = decode_ro_invite(f"dfs-ro-v1:{encoded}")
        self.assertEqual(legacy_info["kdf"], "legacy-sha256-v1")

        with self.assertRaises(InviteError):
            decode_ro_invite("dfs-ro-v1:not-valid-base64!!!")
        with self.assertRaises(InviteError):
            encode_ro_invite(
                name="bad",
                registries=[self.reg_url],
                root_pubkey="",
                tree_secret="s",
            )

    def test_invite_create_join_sync_and_block_writes(self) -> None:
        writer_cfg = self.root / "writer_remotes.json"
        ro_cfg = self.root / "ro_remotes.json"
        src_dir = self.root / "src"
        src_dir.mkdir()
        (src_dir / "dataset.txt").write_text("train-data-v1\n", encoding="utf-8")
        dest_dir = self.root / "runpod_out"

        writer_remote = Remote(
            name="host",
            registry=self.reg_url,
            key=str(self.writer_key),
            ost=f"127.0.0.1:{self.ost.port}",
            path="/example.com/data",
            secret="shared-secret",
            workdir=str(self.root / "host_work"),
            root_pubkey=self.root_pub,
        )
        RemoteStore(writer_cfg).set(writer_remote)

        with patch.dict("os.environ", {"DFS_CONFIG": str(writer_cfg)}):
            rc = cli_main.main(["copy", str(src_dir), "host:"])
            self.assertEqual(rc, 0)

            buf = io.StringIO()
            with redirect_stdout(buf):
                rc2 = cli_main.main([
                    "invite", "create", "host",
                    "--name", "runpod",
                    "--poll", "10",
                ])
            self.assertEqual(rc2, 0)
            token = buf.getvalue().strip()

        with patch.dict("os.environ", {"DFS_CONFIG": str(ro_cfg)}):
            rc3 = cli_main.main([
                "invite", "join", token,
                "--workdir", str(self.root / "ro_work"),
                "--dest", str(dest_dir),
                "--sync",
            ])
            self.assertEqual(rc3, 0)
            self.assertEqual(
                (dest_dir / "dataset.txt").read_text(encoding="utf-8"),
                "train-data-v1\n",
            )
            ro_remote = RemoteStore(ro_cfg).get("runpod")
            self.assertTrue(ro_remote.read_only)
            self.assertEqual(ro_remote.key, "")

            # 読み取り専用リモートへの書き込みは拒否される
            rc4 = cli_main.main(["copy", str(src_dir), "runpod:"])
            self.assertNotEqual(rc4, 0)

    def test_method_a_rw_invite_ephemeral_output_subpath(self) -> None:
        writer_cfg = self.root / "writer_remotes.json"
        gpu_cfg = self.root / "gpu_remotes.json"
        src_dir = self.root / "src"
        src_dir.mkdir()
        (src_dir / "input.txt").write_text("input-v1\n", encoding="utf-8")
        gpu_out = self.root / "gpu_out"
        gpu_out.mkdir()
        (gpu_out / "weights.bin").write_bytes(b"trained-weights-v1")
        host_collected = self.root / "host_collected"

        writer_remote = Remote(
            name="host",
            registry=self.reg_url,
            key=str(self.writer_key),
            ost=f"127.0.0.1:{self.ost.port}",
            path="/example.com/data",
            secret="shared-secret",
            workdir=str(self.root / "host_work"),
            root_pubkey=self.root_pub,
        )
        RemoteStore(writer_cfg).set(writer_remote)

        with patch.dict("os.environ", {"DFS_CONFIG": str(writer_cfg)}):
            self.assertEqual(cli_main.main(["copy", str(src_dir), "host:"]), 0)
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = cli_main.main([
                    "invite", "create", "host",
                    "--name", "runpod",
                    "--write-path", "/example.com/runpod-out",
                    "--write-name", "runpod-out",
                    "--root-key", str(self.root_key),
                    "--ttl-days", "1",
                ])
            self.assertEqual(rc, 0)
            token = buf.getvalue().strip()
            self.assertTrue(token.startswith("dfs-rw-v1:"))

        gpu_home = self.root / "gpu_home"
        with patch.dict(
            "os.environ",
            {"DFS_CONFIG": str(gpu_cfg), "DFS_HOME": str(gpu_home), "XDG_CONFIG_HOME": str(gpu_home)},
        ):
            rc_join = cli_main.main([
                "invite", "join", token,
                "--workdir", str(self.root / "gpu_work"),
                "--dest", str(self.root / "gpu_in"),
                "--sync",
            ])
            self.assertEqual(rc_join, 0)
            self.assertEqual(
                (self.root / "gpu_in" / "input.txt").read_text(encoding="utf-8"),
                "input-v1\n",
            )
            # 入力用リモートは読み取り専用、出力用リモートには書き込める
            self.assertNotEqual(cli_main.main(["copy", str(gpu_out), "runpod:"]), 0)
            self.assertEqual(cli_main.main(["copy", str(gpu_out), "runpod-out:"]), 0)

        # ホスト側が出力サブパスから成果物を回収できる
        collector = Remote(
            name="collect",
            registry=self.reg_url,
            key=str(self.writer_key),
            ost=f"127.0.0.1:{self.ost.port}",
            path="/example.com/runpod-out",
            secret="shared-secret",
            workdir=str(self.root / "collect_work"),
            root_pubkey=self.root_pub,
            read_only=True,
        )
        RemoteStore(writer_cfg).set(collector)
        with patch.dict("os.environ", {"DFS_CONFIG": str(writer_cfg)}):
            self.assertEqual(
                cli_main.main(["pull", "collect:", str(host_collected)]), 0
            )
        self.assertEqual(
            (host_collected / "weights.bin").read_bytes(),
            b"trained-weights-v1",
        )

    def test_share_command_outputs_bootstrap_oneliner(self) -> None:
        writer_cfg = self.root / "writer_remotes.json"
        store = RemoteStore(writer_cfg)
        store.set(Remote(
            name="work",
            registry=self.reg_url,
            key=str(self.writer_key),
            ost=f"127.0.0.1:{self.ost.port}",
            path="/example.com/work",
            secret="shared-secret",
            workdir=str(self.root / "writer_work"),
            root_pubkey=self.root_pub,
        ))
        out = io.StringIO()
        with patch.dict("os.environ", {"DFS_CONFIG": str(writer_cfg)}), redirect_stdout(out):
            rc = cli_main.main(["share", "work"])
        self.assertEqual(rc, 0)
        line = out.getvalue().strip()
        self.assertTrue(line.startswith(f"curl -sSL {self.reg_url}/bootstrap.sh | bash -s -- dfs-ro-v1:"))

        out_rw = io.StringIO()
        with patch.dict("os.environ", {"DFS_CONFIG": str(writer_cfg)}), redirect_stdout(out_rw):
            rc_rw = cli_main.main([
                "share", "work",
                "--write-path", "/example.com/runpod-share",
                "--root-key", str(self.root_key),
                "--bootstrap-url", "https://dfs.example.com/bootstrap.sh",
            ])
        self.assertEqual(rc_rw, 0)
        line_rw = out_rw.getvalue().strip()
        self.assertTrue(line_rw.startswith("curl -sSL https://dfs.example.com/bootstrap.sh | bash -s -- dfs-rw-v1:"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
