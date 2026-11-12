#!/usr/bin/env python3
"""
dfs5/tests/test_cli_main.py
rclone ライク CLI (`dfs5/cli_main.py`) の試験。

ローカルに L2 名簿 (HTTP) と L3 OST (TLS) を 1 つ立て、`dfs5cli` の主要な操作を
実際に呼ぶ。サーバは既存の `cli.py` の部品をそのまま使う。
"""

import json
import io
import os
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import unittest
from contextlib import redirect_stdout
from http.server import ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dfs5 import cli as cli_mod
from dfs5.crypto import ContentAddressedCrypto
from dfs5.l1_delegation import create_delegation_envelope
from dfs5.l3_store import ChunkStoreServer
from dfs5.l4_log import MerkleTreeBuilder
from dfs5.l5_clayfs import DFS5Node
from dfs5.cli_main import main as cli_main
from dfs5.remotes import Remote, RemoteStore

ROOT = Path(__file__).resolve().parents[1]


def _keypair(base: Path, name: str) -> Path:
    priv = base / name
    subprocess.run(
        ["ssh-keygen", "-t", "ed25519", "-N", "", "-C", f"{name}@example.com", "-f", str(priv)],
        check=True, capture_output=True,
    )
    return priv


class LocalServer:
    """L2 (HTTP) と L3 (TLS) を 1 組だけ立てる試験用のサーバ。"""

    def __init__(self, base: Path, root_pub: str):
        self.base = base
        cert, key = base / "ost_cert.pem", base / "ost_key.pem"
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", str(key),
             "-out", str(cert), "-days", "1", "-nodes", "-subj", "/CN=dfs5-test"],
            check=True, capture_output=True,
        )
        self.ost = ChunkStoreServer(cert, key)
        self.pstate = cli_mod.PersistentRegistryState(base / "state", "/example.com", root_pub)
        # cmd_serve を通さないので、広告する L3 の場所はここで埋める
        self.pstate.ost_endpoint = f"tls://127.0.0.1:{self.ost.port}"
        handler = cli_mod.make_registry_http_handler(self.pstate, self.ost)
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.registry_stopped = False

    @property
    def registry_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    @property
    def ost_endpoint(self) -> str:
        return f"127.0.0.1:{self.ost.port}"

    def stop_registry(self) -> None:
        """レジストリだけを止める（OST は読み取り可用性の試験用に残す）。"""
        if self.registry_stopped:
            return
        self.registry_stopped = True
        self.httpd.shutdown()
        self.httpd.server_close()

    def close(self) -> None:
        self.stop_registry()
        self.ost.close()


class RcloneCase(unittest.TestCase):
    """共通の準備（鍵・委譲・サーバ・リモート定義・データ）。"""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="dfs5cli_test_")
        self.base = Path(self._tmp.name)
        self.root_key = _keypair(self.base, "root")
        self.alice_key = _keypair(self.base, "alice")
        self.root_pub = (self.base / "root.pub").read_text(encoding="utf-8").strip()
        self.alice_pub = (self.base / "alice.pub").read_text(encoding="utf-8").strip()

        self.server = LocalServer(self.base, self.root_pub)
        self.addCleanup(self.server.close)

        now = int(time.time())
        env = create_delegation_envelope(
            parent_priv_key=self.root_key, parent="/example.com",
            path="/example.com/alice/notes", writer_pubkey=self.alice_pub,
            epoch=1, base_version=0, issued_at=now - 60, expires_at=now + 86400,
        )
        self.server.pstate.service.register_delegation(env, now=now)

        self.config_file = self.base / "remotes.json"
        self.old_config_env = os.environ.get("DFS5_CONFIG")
        os.environ["DFS5_CONFIG"] = str(self.config_file)

        self.workdir = self.base / "wd"
        store = RemoteStore(self.config_file)
        store.set(Remote(
            name="t", registry=self.server.registry_url, ost=self.server.ost_endpoint,
            path="/example.com/alice/notes", key=str(self.alice_key), secret="s3cret",
            workdir=str(self.workdir),
        ))

        self.local = self.base / "local"
        (self.local / "docs" / "sub").mkdir(parents=True)
        (self.local / "a.txt").write_text("hello world\n", encoding="utf-8")
        (self.local / "b.bin").write_bytes(b"B" * 4096)
        (self.local / "docs" / "readme.md").write_text("readme\n", encoding="utf-8")
        (self.local / "docs" / "sub" / "deep.txt").write_text("deep\n", encoding="utf-8")

    def tearDown(self) -> None:
        if self.old_config_env is None:
            os.environ.pop("DFS5_CONFIG", None)
        else:
            os.environ["DFS5_CONFIG"] = self.old_config_env
        self._tmp.cleanup()

    def run_cli(self, *argv: str) -> int:
        """`dfs5cli` を同じプロセスで実行する（出力はそのまま出る）。"""
        return cli_main(list(argv))

    def test_config_can_omit_ost_and_path(self) -> None:
        """--ost と --path を省いても、L2 から解決して読み書きできる。

        L2 はロケータ（endpoints）で L3 の場所を知っており、委譲に書き手公開鍵を
        持っている。だから CLI はこの 2 つを要求しなくてよい。
        """
        store = RemoteStore(self.config_file)
        store.remotes.pop("t", None)
        store.save()
        # ost / path を空にして登録し直す
        rc = self.run_cli(
            "config", "create", "t",
            "--registry", self.server.registry_url,
            "--key", str(self.alice_key),
            "--secret", "s3cret",
            "--workdir", str(self.workdir),
        )
        self.assertEqual(rc, 0)
        saved = RemoteStore(self.config_file).get("t")
        self.assertEqual(saved.ost, "")
        self.assertEqual(saved.path, "")

        # touch が L2 から ost と path を解決して初期化する
        self.assertEqual(self.run_cli("touch", "t:"), 0)
        cfg = json.loads(
            (self.workdir / ".clayfs" / "dfs5_config.json").read_text(encoding="utf-8")
        )
        self.assertEqual(cfg["sub_path"], "/example.com/alice/notes")
        self.assertEqual(int(cfg["ost_port"]), self.server.ost.port)
        cfg_path = self.workdir / ".clayfs" / "dfs5_config.json"
        if sys.platform != "win32":
            self.assertEqual(oct(cfg_path.stat().st_mode & 0o777), "0o600")

        # 読み書きも通る
        self.assertEqual(self.run_cli("copy", str(self.local), "t:"), 0)
        self.assertEqual(self.run_cli("cat", "t:a.txt"), 0)
        self.assertEqual(self.run_cli("about", "t:"), 0)

    def test_registry_host_only_gets_default_port(self) -> None:
        """--registry はホスト名だけでよい（ポートを補う）。"""
        from dfs5.cli_main import normalize_registry

        self.assertEqual(normalize_registry("172.16.1.60"), "http://172.16.1.60:9440")
        self.assertEqual(normalize_registry("http://host:1234"), "http://host:1234")
        self.assertEqual(normalize_registry("host", 19440), "http://host:19440")
        self.assertEqual(normalize_registry("https://host/"), "https://host:9440")

    def test_config_create_accepts_registry_alternate(self) -> None:
        """--registry-alternate がリモート定義に保存される。"""
        rc = self.run_cli(
            "config", "create", "alt",
            "--registry", self.server.registry_url,
            "--registry-alternate", "127.0.0.1:19440",
            "--ost-alternate", "tls://127.0.0.1:19443",
            "--libp2p-peer", "/ip4/127.0.0.1/udp/19443/quic-v1/p2p/12D3KooWTest",
            "--key", str(self.alice_key),
            "--secret", "s3cret",
            "--workdir", str(self.base / "wd-alt"),
        )
        self.assertEqual(rc, 0)
        saved = RemoteStore(self.config_file).get("alt")
        self.assertEqual(saved.registry_alternates, ["http://127.0.0.1:19440"])
        self.assertEqual(saved.ost_alternates, ["127.0.0.1:19443"])
        self.assertEqual(
            saved.libp2p_peers,
            ["/ip4/127.0.0.1/udp/19443/quic-v1/p2p/12D3KooWTest"],
        )

    def test_config_create_accepts_compression_policy(self) -> None:
        store = RemoteStore(self.config_file)
        store.remotes.pop("zstd", None)
        store.save()
        rc = self.run_cli(
            "config", "create", "zstd",
            "--registry", self.server.registry_url,
            "--key", str(self.alice_key),
            "--secret", "s3cret",
            "--compression", "zstd",
            "--workdir", str(self.base / "wd-zstd"),
        )
        self.assertEqual(rc, 0)
        self.assertEqual(RemoteStore(self.config_file).get("zstd").compression, "zstd")

    def test_config_create_makes_key_when_omitted(self) -> None:
        """--key を省くと、その場で Ed25519 の鍵を作る。"""
        store = RemoteStore(self.config_file)
        store.remotes.pop("t", None)
        store.save()
        key_dir = self.base / "auto_keys"
        rc = self.run_cli(
            "config", "create", "t",
            "--registry", self.server.registry_url,
            "--key-dir", str(key_dir),
            "--secret", "s3cret",
            "--workdir", str(self.workdir),
        )
        self.assertEqual(rc, 0)
        created = key_dir / "t_ed25519"
        self.assertTrue(created.is_file(), "鍵が作られていない")
        self.assertTrue(Path(f"{created}.pub").is_file(), ".pub が無い")
        # OpenSSH 形式であること
        self.assertIn("BEGIN OPENSSH PRIVATE KEY", created.read_text(encoding="utf-8"))
        # 600 であること
        # Windows は chmod の mode bit ではなく ACL で守るため、常に 0o666 に見える。
        # (この差は既知の未対応点。鍵はユーザープロファイル配下の ACL に依存する)
        if sys.platform != "win32":
            self.assertEqual(oct(created.stat().st_mode & 0o777), "0o600")
        # 定義にも反映されている
        saved = RemoteStore(self.config_file).get("t")
        self.assertEqual(saved.key, str(created))

    def test_explicit_missing_key_is_refused(self) -> None:
        """--key で存在しないパスを渡したら断る（勝手に作らない）。"""
        store = RemoteStore(self.config_file)
        store.remotes.pop("t", None)
        store.save()
        rc = self.run_cli(
            "config", "create", "t",
            "--registry", self.server.registry_url,
            "--key", str(self.base / "nope"),
            "--secret", "s3cret",
        )
        self.assertEqual(rc, 2, "存在しない --key を受け入れた")

    def test_create_alias_exists(self) -> None:
        """`dfs5cli create` は `dfs5cli config create` と同じ（短い入口）。"""
        store = RemoteStore(self.config_file)
        store.remotes.pop("t", None)
        store.save()
        rc = self.run_cli(
            "create", "t",
            "--registry", self.server.registry_url,
            "--key", str(self.alice_key),
            "--secret", "s3cret",
            "--workdir", str(self.workdir),
        )
        self.assertEqual(rc, 0, "create が失敗した")
        saved = RemoteStore(self.config_file).get("t")
        self.assertEqual(saved.secret, "s3cret")
        self.assertEqual(saved.registry, self.server.registry_url)

    def test_prompt_verifies_secret_twice(self) -> None:
        """端末があるときは secret を 2 回聞き、一致したものだけ採る。

        擬似端末で「1 回目と 2 回目が違う」「一致する」を順に試す。
        """
        if sys.platform == "win32":
            # Windows に pty / termios は無い
            self.skipTest("pty は Windows に無い")
        import pty
        import select
        import warnings

        # forkpty は「スレッドのあるプロセスでは fork が危険」と警告する。
        # 試験の子は exec ですぐ置き換わるので、ここでは抑制する。
        warnings.filterwarnings("ignore", category=DeprecationWarning, module="pty")

        def run_create(name: str, answers: list[bytes], timeout: float = 10.0) -> tuple[int, str]:
            config = self.base / f"{name}_remotes.json"
            keys = self.base / f"{name}_keys"
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                pid, fd = pty.fork()
            if pid == 0:
                os.environ["DFS5_CONFIG"] = str(config)
                os.execv(
                    str(ROOT / "dfs5cli"),
                    ["./dfs5cli", "create", name,
                     "--registry", self.server.registry_url,
                     "--key", str(self.alice_key),
                     "--key-dir", str(keys),
                     "--workdir", str(self.base / f"{name}_wd")],
                )
                os._exit(1)
            out = b""
            idx = 0
            end = time.time() + timeout
            while time.time() < end:
                r, _, _ = select.select([fd], [], [], 0.3)
                if r:
                    try:
                        chunk = os.read(fd, 4096)
                    except OSError:
                        break
                    if not chunk:
                        break
                    out += chunk
                    # プロンプトが出るたびに次の答えを送る
                    if out.count(b"tree_secret") > idx and idx < len(answers):
                        time.sleep(0.15)
                        os.write(fd, answers[idx])
                        idx += 1
                try:
                    wpid, _ = os.waitpid(pid, os.WNOHANG)
                    if wpid:
                        break
                except ChildProcessError:
                    break
            import signal as _signal

            try:
                os.kill(pid, _signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                os.waitpid(pid, 0)
            except ChildProcessError:
                pass
            return 0, out.decode(errors="replace")

        # 1 回目と 2 回目が違う -> 照合に失敗し、やり直しを求められる
        _rc, out = run_create("mismatch", [b"one\n", b"two\n"])
        self.assertIn("一致しません", out, f"不一致を指摘していない: {out[-300:]}")

        # 一致する -> 保存される
        _rc, out = run_create("match", [b"same-secret\n", b"same-secret\n"])
        saved = json.loads((self.base / "match_remotes.json").read_text(encoding="utf-8"))
        self.assertEqual(saved["remotes"]["match"]["secret"], "same-secret")
        # 入力した文字は画面に出ない
        self.assertNotIn("same-secret", out, "入力がエコーされている")

    def test_no_prompt_keeps_secret_empty(self) -> None:
        """--no-prompt なら端末から読まず、secret は空のままになる。"""
        store = RemoteStore(self.config_file)
        store.remotes.pop("t", None)
        store.save()
        rc = self.run_cli(
            "config", "create", "t",
            "--registry", self.server.registry_url,
            "--key-dir", str(self.base / "k2"),
            "--no-prompt",
        )
        self.assertEqual(rc, 0)
        self.assertEqual(RemoteStore(self.config_file).get("t").secret, "")

    def test_path_without_leading_slash_is_accepted(self) -> None:
        """--path は / で始まらなくてもよい。"""
        store = RemoteStore(self.config_file)
        rc = self.run_cli(
            "config", "create", "nolead",
            "--registry", self.server.registry_url,
            "--key", str(self.alice_key),
            "--secret", "s3cret",
            "--path", "example.com//alice/notes/",
            "--workdir", str(self.base / "wd2"),
        )
        self.assertEqual(rc, 0)
        saved = RemoteStore(self.config_file).get("nolead")
        self.assertEqual(saved.path, "/example.com/alice/notes")

    def test_empty_secret_is_refused_on_write(self) -> None:
        """tree_secret が空のまま書こうとしたら、黙って弱い暗号にせず止める。"""
        store = RemoteStore(self.config_file)
        store.remotes.pop("t", None)
        store.save()
        self.assertEqual(
            self.run_cli(
                "config", "create", "t",
                "--registry", self.server.registry_url,
                "--key", str(self.alice_key),
                "--workdir", str(self.base / "wd3"),
            ),
            0,
        )
        rc = self.run_cli("copy", str(self.local), "t:")
        self.assertEqual(rc, 2, "secret 無しの書き込みが止まっていない")

    def test_registry_advertises_ost_and_paths(self) -> None:
        """L2 が L3 の場所と、登録済みパス（書き手公開鍵つき）を返す。"""
        from dfs5 import cli as cli_mod

        client = cli_mod.RemoteRegistryClient(self.server.registry_url)
        info = client.ost_info()
        self.assertTrue(info["endpoint"].startswith("tls://"))
        rows = client.list_paths()["paths"]
        self.assertTrue(any(r["path"] == "/example.com/alice/notes" for r in rows))
        found = client.find_path_for_writer(self.alice_pub)
        self.assertEqual(found, "/example.com/alice/notes")

    # ---- config ----
    def test_config_roundtrip(self) -> None:
        store = RemoteStore(self.config_file)
        self.assertEqual(store.names(), ["t"])
        r = store.get("t")
        self.assertEqual(r.path, "/example.com/alice/notes")
        self.assertEqual(r.resolved_workdir(), self.workdir)
        # モードが 600 であること（秘密を置くため）
        # Windows は ACL 管理で、chmod の mode bit は常に 0o666 に見える（既知の差）。
        if sys.platform != "win32":
            self.assertEqual(oct(self.config_file.stat().st_mode & 0o777), "0o600")

    def test_unknown_remote_is_an_error(self) -> None:
        with self.assertRaises(Exception):
            RemoteStore(self.config_file).get("nope")

    # ---- copy / ls / cat ----
    def test_copy_ls_cat_pull(self) -> None:
        rc = self.run_cli("copy", str(self.local), "t:")
        self.assertEqual(rc, 0)

        # copy は src の中身を宛先へ展開するので、root 直下は a.txt / b.bin / docs/
        rc = self.run_cli("cat", "t:docs/readme.md")
        self.assertEqual(rc, 0)

        # 取り出して内容が一致すること
        out = self.base / "out"
        rc = self.run_cli("pull", "t:", str(out))
        self.assertEqual(rc, 0)
        self.assertEqual((out / "a.txt").read_text(encoding="utf-8"), "hello world\n")
        self.assertEqual((out / "docs" / "sub" / "deep.txt").read_text(encoding="utf-8"), "deep\n")
        self.assertEqual((out / "b.bin").read_bytes(), b"B" * 4096)

    def test_pull_rejects_parent_prefix(self) -> None:
        """``remote:../../outside`` で作業ツリー外を読めないこと。"""
        outside = self.base / "outside"
        outside.mkdir()
        (outside / "LEAK.txt").write_text("OUTSIDE-SECRET", encoding="utf-8")
        out = self.base / "escaped_out"
        rc = self.run_cli("pull", "t:../../outside", str(out))
        self.assertEqual(rc, 2)
        self.assertFalse((out / "LEAK.txt").exists())

    def test_copy_is_idempotent(self) -> None:
        """2 回目の copy は変更なしで、新しい版を作らない。"""
        self.assertEqual(self.run_cli("copy", str(self.local), "t:"), 0)
        store = RemoteStore(self.config_file)
        node = cli_mod.load_node_from_mount(store.get("t").resolved_workdir())[0]
        v1 = node.l4.pin.version

        self.assertEqual(self.run_cli("copy", str(self.local), "t:"), 0)
        node2 = cli_mod.load_node_from_mount(store.get("t").resolved_workdir())[0]
        self.assertEqual(node2.l4.pin.version, v1, "無変更の copy が新しい版を作っている")

    def test_registry_state_can_use_external_ost_dir(self) -> None:
        ost_dir = self.base / "external-ost"
        state = cli_mod.PersistentRegistryState(
            self.base / "external_state",
            "/example.com",
            self.root_pub,
            chunks_dir=ost_dir,
        )

        class DummyOST:
            store = {"abc123": b"external chunk"}

        state.save_ost_chunks(DummyOST())
        self.assertEqual((ost_dir / "abc123.blk").read_bytes(), b"external chunk")

        loaded = type("LoadedOST", (), {"store": {}})()
        state.load_ost_chunks(loaded)
        self.assertEqual(loaded.store["abc123"], b"external chunk")

    def test_read_uses_l2_cache_after_all_registries_stop(self) -> None:
        """registry が全滅しても、検証済みキャッシュと生きている OST で読める。"""
        self.assertEqual(self.run_cli("copy", str(self.local), "t:"), 0)
        cache_path = self.workdir / ".clayfs" / "l2_cache.json"
        self.assertTrue(cache_path.is_file(), "L2 キャッシュが作られていない")

        self.server.stop_registry()
        node = cli_mod.load_node_from_mount(self.workdir)[0]
        self.assertEqual(node.read_remote("a.txt"), b"hello world\n")
        paths = {e["path"] for e in node.list_remote()}
        self.assertIn("docs/readme.md", paths)

    def test_expired_l2_cache_is_not_used(self) -> None:
        """期限切れのキャッシュは読み取りに使わない。"""
        self.assertEqual(self.run_cli("copy", str(self.local), "t:"), 0)
        cache_path = self.workdir / ".clayfs" / "l2_cache.json"
        data = json.loads(cache_path.read_text(encoding="utf-8"))
        entry = next(iter(data["paths"].values()))
        entry["locator"]["payload"]["expires_at"] = int(time.time()) - 1
        cache_path.write_text(json.dumps(data), encoding="utf-8")

        self.server.stop_registry()
        node = cli_mod.load_node_from_mount(self.workdir)[0]
        with self.assertRaises(Exception):
            node.read_remote("a.txt")

    def test_copyto_and_checksum(self) -> None:
        one = self.base / "one.txt"
        one.write_text("one file\n", encoding="utf-8")
        self.assertEqual(self.run_cli("copyto", str(one), "t:docs/one.txt"), 0)
        store = RemoteStore(self.config_file)
        node = cli_mod.load_node_from_mount(store.get("t").resolved_workdir())[0]
        v1 = node.l4.pin.version
        # 同じ内容をもう一度 copyto しても版が増えない
        self.assertEqual(self.run_cli("copyto", str(one), "t:docs/one.txt"), 0)
        node2 = cli_mod.load_node_from_mount(store.get("t").resolved_workdir())[0]
        self.assertEqual(node2.l4.pin.version, v1, "同じ内容の copyto が版を作っている")

    def test_checksum_modes(self) -> None:
        src = self.base / "same-size.txt"
        src.write_text("AAAA\n", encoding="utf-8")
        self.assertEqual(self.run_cli("copyto", str(src), "t:same-size.txt"), 0)
        store = RemoteStore(self.config_file)
        node = cli_mod.load_node_from_mount(store.get("t").resolved_workdir())[0]
        v1 = node.l4.pin.version

        src.write_text("BBBB\n", encoding="utf-8")
        self.assertEqual(
            self.run_cli("copyto", str(src), "t:same-size.txt", "--checksum", "size"),
            0,
        )
        node2 = cli_mod.load_node_from_mount(store.get("t").resolved_workdir())[0]
        self.assertEqual(node2.l4.pin.version, v1, "size checksum が内容変更を検出した")

        self.assertEqual(
            self.run_cli("copyto", str(src), "t:same-size.txt", "--checksum", "crc32"),
            0,
        )
        node3 = cli_mod.load_node_from_mount(store.get("t").resolved_workdir())[0]
        self.assertEqual(node3.l4.pin.version, v1 + 1, "crc32 checksum が更新しない")

        src.write_text("CCCC\n", encoding="utf-8")
        self.assertEqual(
            self.run_cli("copyto", str(src), "t:same-size.txt", "--checksum", "sha1"),
            0,
        )
        node4 = cli_mod.load_node_from_mount(store.get("t").resolved_workdir())[0]
        self.assertEqual(node4.l4.pin.version, v1 + 2, "sha1 checksum が更新しない")
        self.assertEqual(node4.read_remote("same-size.txt"), b"CCCC\n")

    def test_import_tar_supports_all_compression_formats(self) -> None:
        source = self.base / "tar_source" / "bundle"
        (source / "docs").mkdir(parents=True)
        (source / "docs" / "readme.txt").write_text("from tar\n", encoding="utf-8")
        (source / "empty").mkdir()

        for suffix, mode in (
            (".tar", "w"),
            (".tar.gz", "w:gz"),
            (".tar.xz", "w:xz"),
            (".tar.bz2", "w:bz2"),
        ):
            archive = self.base / f"import{suffix}"
            with tarfile.open(archive, mode) as tf:
                tf.add(source, arcname="bundle")
            self.assertEqual(
                self.run_cli(
                    "import_tar", str(archive), "t:", "--strip-components", "1"
                ),
                0,
                f"import_tar failed for {suffix}",
            )

        node = cli_mod.load_node_from_mount(self.workdir)[0]
        self.assertEqual(node.read_remote("docs/readme.txt"), b"from tar\n")
        paths = {e["path"]: e["type"] for e in node.list_remote()}
        self.assertEqual(paths.get("empty"), "dir")
        self.assertEqual(paths.get("docs"), "dir")

    def test_import_tar_rejects_parent_traversal(self) -> None:
        archive = self.base / "evil.tar"
        payload = b"must not escape\n"
        with tarfile.open(archive, "w") as tf:
            info = tarfile.TarInfo("../escape.txt")
            info.size = len(payload)
            tf.addfile(info, io.BytesIO(payload))

        self.assertEqual(self.run_cli("import_tar", str(archive), "t:"), 2)
        self.assertFalse((self.base / "escape.txt").exists())
        self.assertEqual(self.server.pstate.service.logs, {})

    def test_import_tar_dry_run_does_not_write(self) -> None:
        source = self.base / "dry_source"
        source.mkdir()
        (source / "dry.txt").write_text("dry\n", encoding="utf-8")
        archive = self.base / "dry.tar"
        with tarfile.open(archive, "w") as tf:
            tf.add(source, arcname="dry")

        self.assertEqual(
            self.run_cli("import_tar", str(archive), "t:", "--dry-run"), 0
        )
        node = cli_mod.load_node_from_mount(self.workdir)[0]
        self.assertEqual(node.list_remote(), [])

    def test_mv_file_uses_one_version(self) -> None:
        """mv は copy + rm ではなく、1 版でファイルを改名する。"""
        self.assertEqual(self.run_cli("copy", str(self.local), "t:"), 0)
        store = RemoteStore(self.config_file)
        before = cli_mod.load_node_from_mount(store.get("t").resolved_workdir())[0]
        before_version = before.l4.pin.version

        self.assertEqual(self.run_cli("mv", "t:a.txt", "t:renamed.txt"), 0)
        node = cli_mod.load_node_from_mount(store.get("t").resolved_workdir())[0]
        self.assertEqual(node.l4.pin.version, before_version + 1)
        paths = {e["path"] for e in node.list_remote()}
        self.assertNotIn("a.txt", paths)
        self.assertIn("renamed.txt", paths)
        self.assertEqual(node.read_remote("renamed.txt"), b"hello world\n")

    def test_mv_directory_and_dry_run(self) -> None:
        """ディレクトリ全体を移動でき、dry-run では版を進めない。"""
        self.assertEqual(self.run_cli("copy", str(self.local), "t:"), 0)
        store = RemoteStore(self.config_file)
        node = cli_mod.load_node_from_mount(store.get("t").resolved_workdir())[0]
        before = node.l4.pin.version

        self.assertEqual(self.run_cli("mv", "t:docs", "t:documents", "--dry-run"), 0)
        node2 = cli_mod.load_node_from_mount(store.get("t").resolved_workdir())[0]
        self.assertEqual(node2.l4.pin.version, before, "dry-run が版を進めた")
        self.assertIn("docs/readme.md", {e["path"] for e in node2.list_remote()})

        self.assertEqual(self.run_cli("mv", "t:docs", "t:documents"), 0)
        node3 = cli_mod.load_node_from_mount(store.get("t").resolved_workdir())[0]
        paths = {e["path"] for e in node3.list_remote()}
        self.assertNotIn("docs", paths)
        self.assertIn("documents", paths)
        self.assertIn("documents/sub/deep.txt", paths)
        self.assertEqual(node3.read_remote("documents/sub/deep.txt"), b"deep\n")

    def test_mv_refuses_collision_and_allows_file_overwrite(self) -> None:
        """既存宛先は拒否し、--overwrite ならファイルだけ置換する。"""
        self.assertEqual(self.run_cli("copy", str(self.local), "t:"), 0)
        self.assertEqual(self.run_cli("copyto", str(self.base / "local" / "a.txt"), "t:target.txt"), 0)
        self.assertEqual(self.run_cli("mv", "t:b.bin", "t:target.txt"), 2)

        self.assertEqual(self.run_cli("mv", "t:b.bin", "t:target.txt", "--overwrite"), 0)
        store = RemoteStore(self.config_file)
        node = cli_mod.load_node_from_mount(store.get("t").resolved_workdir())[0]
        self.assertNotIn("b.bin", {e["path"] for e in node.list_remote()})
        self.assertEqual(node.read_remote("target.txt"), b"B" * 4096)

    def test_mv_rejects_cross_remote_and_descendant_destination(self) -> None:
        self.assertEqual(self.run_cli("copy", str(self.local), "t:"), 0)
        self.assertEqual(self.run_cli("mv", "t:a.txt", "other:a.txt"), 2)
        self.assertEqual(self.run_cli("mv", "t:docs", "t:docs/sub/docs2"), 2)

    def test_copy_include_exclude(self) -> None:
        """copy のフィルタは相対パスに適用され、exclude が優先される。"""
        self.assertEqual(
            self.run_cli(
                "copy", str(self.local), "t:",
                "--include", "docs/*", "--exclude", "docs/sub/*",
            ),
            0,
        )
        node = cli_mod.load_node_from_mount(
            RemoteStore(self.config_file).get("t").resolved_workdir()
        )[0]
        paths = {e["path"] for e in node.list_remote() if e["type"] == "file"}
        self.assertEqual(paths, {"docs/readme.md"})

    def test_sync_delete_does_not_touch_excluded_paths(self) -> None:
        """sync --delete はフィルタの外側を削除しない。"""
        self.assertEqual(self.run_cli("copy", str(self.local), "t:"), 0)
        (self.local / "docs" / "readme.md").unlink()
        self.assertEqual(
            self.run_cli(
                "sync", str(self.local), "t:", "--delete",
                "--exclude", "docs/readme.md",
            ),
            0,
        )
        store = RemoteStore(self.config_file)
        node = cli_mod.load_node_from_mount(store.get("t").resolved_workdir())[0]
        self.assertIn("docs/readme.md", {e["path"] for e in node.list_remote()})

    def test_pull_include_and_exclude(self) -> None:
        self.assertEqual(self.run_cli("copy", str(self.local), "t:"), 0)
        included = self.base / "pull_included"
        self.assertEqual(
            self.run_cli("pull", "t:", str(included), "--include", "*.md"), 0
        )
        self.assertTrue((included / "docs" / "readme.md").is_file())
        self.assertFalse((included / "a.txt").exists())
        self.assertFalse((included / "b.bin").exists())

        excluded = self.base / "pull_excluded"
        self.assertEqual(
            self.run_cli("pull", "t:", str(excluded), "--exclude", "*.bin"), 0
        )
        self.assertTrue((excluded / "docs" / "sub" / "deep.txt").is_file())
        self.assertFalse((excluded / "b.bin").exists())

    def test_lsd_lists_only_directories(self) -> None:
        self.assertEqual(self.run_cli("copy", str(self.local), "t:"), 0)
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(self.run_cli("lsd", "t:"), 0)
        self.assertEqual(out.getvalue().splitlines(), ["docs/"])

        out2 = io.StringIO()
        with redirect_stdout(out2):
            self.assertEqual(self.run_cli("lsd", "t:docs"), 0)
        self.assertEqual(out2.getvalue().splitlines(), ["sub/"])

    def test_sync_delete(self) -> None:
        self.assertEqual(self.run_cli("copy", str(self.local), "t:"), 0)
        (self.local / "docs" / "readme.md").unlink()
        rc = self.run_cli("sync", str(self.local), "t:", "--delete")
        self.assertEqual(rc, 0)

        store = RemoteStore(self.config_file)
        node = cli_mod.load_node_from_mount(store.get("t").resolved_workdir())[0]
        paths = {e["path"] for e in node.list_remote()}
        self.assertNotIn("docs/readme.md", paths)
        self.assertIn("a.txt", paths)

    def test_sync_without_delete_keeps_remote_only_files(self) -> None:
        one = self.base / "one.txt"
        one.write_text("remote only\n", encoding="utf-8")
        self.assertEqual(self.run_cli("copyto", str(one), "t:keep.txt"), 0)
        self.assertEqual(self.run_cli("sync", str(self.local), "t:"), 0)
        store = RemoteStore(self.config_file)
        node = cli_mod.load_node_from_mount(store.get("t").resolved_workdir())[0]
        paths = {e["path"] for e in node.list_remote()}
        self.assertIn("keep.txt", paths, "--delete なしの sync がリモートのファイルを消した")

    def test_rm_file_leaves_empty_dir(self) -> None:
        """ファイルを消すと空ディレクトリが残る（dfs5 は空も版に残す）。"""
        self.assertEqual(self.run_cli("copy", str(self.local), "t:"), 0)

        # docs/sub は空になるが、ディレクトリ自体は残る
        self.assertEqual(self.run_cli("rm", "t:docs/readme.md"), 0)
        self.assertEqual(self.run_cli("rm", "t:docs/sub/deep.txt"), 0)

        store = RemoteStore(self.config_file)
        node = cli_mod.load_node_from_mount(store.get("t").resolved_workdir())[0]
        paths = {e["path"]: e["type"] for e in node.list_remote()}
        self.assertNotIn("docs/readme.md", paths)
        self.assertNotIn("docs/sub/deep.txt", paths)
        self.assertEqual(paths.get("docs"), "dir", "空になったディレクトリが消えている")
        self.assertEqual(paths.get("docs/sub"), "dir", "空になったディレクトリが消えている")

    def test_rm_rmdirs_prunes_empty(self) -> None:
        """--rmdirs なら、空になったディレクトリも片付く。"""
        self.assertEqual(self.run_cli("copy", str(self.local), "t:"), 0)

        self.assertEqual(self.run_cli("rm", "t:docs/readme.md"), 0)
        self.assertEqual(self.run_cli("rm", "t:docs/sub/deep.txt", "--rmdirs"), 0)

        store = RemoteStore(self.config_file)
        node = cli_mod.load_node_from_mount(store.get("t").resolved_workdir())[0]
        paths = {e["path"] for e in node.list_remote()}
        self.assertNotIn("docs/sub", paths, "--rmdirs なのに空ディレクトリが残っている")

    def test_rm_dir_needs_recursive(self) -> None:
        """中身のあるディレクトリは --recursive 無しでは消さない。"""
        self.assertEqual(self.run_cli("copy", str(self.local), "t:"), 0)
        rc = self.run_cli("rm", "t:docs")
        self.assertEqual(rc, 2, "ディレクトリを --recursive 無しで消した")

        self.assertEqual(self.run_cli("rm", "t:docs", "--recursive"), 0)
        store = RemoteStore(self.config_file)
        node = cli_mod.load_node_from_mount(store.get("t").resolved_workdir())[0]
        paths = {e["path"] for e in node.list_remote() if e["type"] == "file"}
        self.assertFalse(any(p.startswith("docs/") for p in paths), "中身が残っている")

    def test_rm_missing_is_an_error(self) -> None:
        self.assertEqual(self.run_cli("copy", str(self.local), "t:"), 0)
        rc = self.run_cli("rm", "t:nope.txt")
        self.assertEqual(rc, 2)

    def test_mkdir_and_rmdir(self) -> None:
        """空のディレクトリを作って消せる（空も版に残る）。"""
        self.assertEqual(self.run_cli("copy", str(self.local), "t:"), 0)
        self.assertEqual(self.run_cli("mkdir", "t:empty-dir"), 0)

        store = RemoteStore(self.config_file)
        node = cli_mod.load_node_from_mount(store.get("t").resolved_workdir())[0]
        paths = {e["path"]: e["type"] for e in node.list_remote()}
        self.assertEqual(paths.get("empty-dir"), "dir", "作った空ディレクトリが無い")

        self.assertEqual(self.run_cli("rmdir", "t:empty-dir"), 0)
        node2 = cli_mod.load_node_from_mount(store.get("t").resolved_workdir())[0]
        paths2 = {e["path"] for e in node2.list_remote()}
        self.assertNotIn("empty-dir", paths2)

    def test_rmdir_refuses_non_empty(self) -> None:
        self.assertEqual(self.run_cli("copy", str(self.local), "t:"), 0)
        rc = self.run_cli("rmdir", "t:docs")
        self.assertEqual(rc, 2, "中身のあるディレクトリを rmdir で消した")

    def test_purge_removes_everything(self) -> None:
        self.assertEqual(self.run_cli("copy", str(self.local), "t:"), 0)
        self.assertEqual(self.run_cli("purge", "t:"), 0)
        store = RemoteStore(self.config_file)
        node = cli_mod.load_node_from_mount(store.get("t").resolved_workdir())[0]
        self.assertEqual(node.list_remote(), [], "purge したのに残っている")
        # 取り出しても何も無い
        out = self.base / "out_purged"
        self.assertEqual(self.run_cli("pull", "t:", str(out)), 0)
        self.assertEqual(list(out.rglob("*")), [])

    def test_empty_dir_survives_roundtrip(self) -> None:
        """空のディレクトリは版に残り、pull で降りてくる。"""
        self.run_cli("copy", str(self.local), "t:")
        self.assertEqual(self.run_cli("mkdir", "t:keep/empty"), 0)

        out = self.base / "out_empty"
        self.assertEqual(self.run_cli("pull", "t:", str(out)), 0)
        self.assertTrue((out / "keep" / "empty").is_dir(), "空ディレクトリが降りてこない")
        self.assertEqual(list((out / "keep" / "empty").iterdir()), [])

    def test_rm_dry_run(self) -> None:
        self.assertEqual(self.run_cli("copy", str(self.local), "t:"), 0)
        store = RemoteStore(self.config_file)
        node = cli_mod.load_node_from_mount(store.get("t").resolved_workdir())[0]
        before = {e["path"] for e in node.list_remote()}

        self.assertEqual(self.run_cli("rm", "t:a.txt", "--dry-run"), 0)
        node2 = cli_mod.load_node_from_mount(store.get("t").resolved_workdir())[0]
        after = {e["path"] for e in node2.list_remote()}
        self.assertEqual(before, after, "dry-run が実際に消した")

    def test_dry_run_does_not_write(self) -> None:
        rc = self.run_cli("copy", str(self.local), "t:", "--dry-run")
        self.assertEqual(rc, 0)
        store = RemoteStore(self.config_file)
        node = cli_mod.load_node_from_mount(store.get("t").resolved_workdir())[0]
        self.assertEqual(node.list_remote(), [], "dry-run がリモートに書いた")

    def test_check_reports_difference(self) -> None:
        self.assertEqual(self.run_cli("copy", str(self.local), "t:"), 0)
        rc = self.run_cli("check", "t:", str(self.local))
        self.assertEqual(rc, 0, "一致しているのに check が失敗した")
        (self.local / "extra.txt").write_text("extra\n", encoding="utf-8")
        rc2 = self.run_cli("check", "t:", str(self.local))
        self.assertEqual(rc2, 1, "差分があるのに check が成功した")

    def test_ls_prefix_only_lists_direct_children(self) -> None:
        self.assertEqual(self.run_cli("copy", str(self.local), "t:"), 0)
        store = RemoteStore(self.config_file)
        node = cli_mod.load_node_from_mount(store.get("t").resolved_workdir())[0]
        entries = node.list_remote()
        top = {e["path"] for e in entries if "/" not in e["path"]}
        self.assertEqual(top, {"a.txt", "b.bin", "docs"})

    def test_no_default_remote_is_reported(self) -> None:
        """`path` だけを渡して --remote も無いときは、使い方の誤り（終了コード 2）。"""
        rc = self.run_cli("ls", "just-a-path")
        self.assertEqual(rc, 2)

    def test_remote_error_exit_code(self) -> None:
        """知らないリモートは終了コード 2 で返る（例外を投げない）。"""
        rc = self.run_cli("ls", "nope:")
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
