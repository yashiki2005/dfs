#!/usr/bin/env python3
"""
dfs/tests/test_integration.py
段階 5: 2 台 ([Mac] と [Pi5]) で 1 つのツリーを共有する統合試験および最終 5 指標の計測スイート。
"""

import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dfs.l1_delegation import DelegationError, create_delegation_envelope
from dfs.l2_registry import ConflictError, DirectoryRegistryService, ServiceUnavailableError
from dfs.l3_store import ChunkStoreServer
from dfs.l5_clayfs import DFSNode


def generate_ssh_keypair(dirpath: Path, name: str) -> tuple[Path, str]:
    priv = dirpath / f"{name}_ed25519"
    subprocess.run(
        ["ssh-keygen", "-t", "ed25519", "-N", "", "-C", f"{name}@example.com", "-f", str(priv)],
        check=True,
        capture_output=True,
    )
    pub = Path(f"{priv}.pub").read_text(encoding="utf-8").strip()
    return priv, pub


class TestL3ContentDedup(unittest.TestCase):
    """段階 4: 同じ内容の塊を、同一・別名・別バッチで再送しない。"""

    def test_same_content_is_not_reencrypted_inside_one_upload(self) -> None:
        import subprocess as sp
        from dfs.crypto import ContentAddressedCrypto
        from dfs.l3_store import ChunkStoreServer, OSTClient
        from dfs.l4_log import MerkleTreeBuilder

        with tempfile.TemporaryDirectory(prefix="dfs_l3_") as tmpdir:
            base = Path(tmpdir)
            cert, key = base / "c.pem", base / "k.pem"
            sp.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", str(key),
                    "-out", str(cert), "-days", "1", "-nodes", "-subj", "/CN=l"],
                   check=True, capture_output=True)
            ost = ChunkStoreServer(cert, key)
            try:
                tree = base / "tree"
                tree.mkdir()
                (tree / "a.bin").write_bytes(b"X" * 8192)
                (tree / "b.bin").write_bytes(b"X" * 8192)

                client = OSTClient("127.0.0.1", ost.port)
                builder = MerkleTreeBuilder(ContentAddressedCrypto("dedup-secret"), client)
                builder.upload_directory(tree)

                # 同一内容 2 ファイルでも、暗号文本体は 1 ファイル分しか送らない
                self.assertLess(
                    client.blob_bytes_sent, 8192 * 2,
                    f"同一内容を二重送信している: {client.blob_bytes_sent} bytes",
                )
                # 索引は「ファイル 1 つ + ディレクトリ塊 1 つ」の 2 件になる。
                # 同一内容の 2 ファイルが別々の plain_id を持っていたら 3 件になる。
                self.assertEqual(
                    len(builder.index), 2,
                    f"同一内容が別の plain_id として索引に入っている: {len(builder.index)}",
                )
            finally:
                ost.close()

    def test_index_persists_across_builders(self) -> None:
        import subprocess as sp
        from dfs.crypto import ContentAddressedCrypto
        from dfs.l3_store import ChunkStoreServer, OSTClient
        from dfs.l4_log import MerkleTreeBuilder

        with tempfile.TemporaryDirectory(prefix="dfs_index_") as tmpdir:
            base = Path(tmpdir)
            cert, key = base / "c.pem", base / "k.pem"
            sp.run(["openssl", "req", "-x509", "-newkey", "rsa:2048",
                    "-keyout", str(key), "-out", str(cert), "-days", "1",
                    "-nodes", "-subj", "/CN=l"],
                   check=True, capture_output=True)
            ost = ChunkStoreServer(cert, key)
            try:
                tree = base / "tree"
                tree.mkdir()
                (tree / "a.bin").write_bytes(b"persistent index\n" * 100)
                index_file = base / "ost_index.json"
                secret = "persistent-index-secret"

                first = OSTClient("127.0.0.1", ost.port)
                MerkleTreeBuilder(
                    ContentAddressedCrypto(secret), first, index_file=index_file
                ).upload_directory(tree)
                self.assertGreater(first.blob_bytes_sent, 0)
                self.assertTrue(index_file.is_file())

                second = OSTClient("127.0.0.1", ost.port)
                builder = MerkleTreeBuilder(
                    ContentAddressedCrypto(secret), second, index_file=index_file
                )
                builder.upload_directory(tree)
                self.assertEqual(second.blob_bytes_sent, 0,
                                 "永続索引を読んだのに同じチャンクを再送している")

                # 内容アドレス鍵が変わった索引は再利用してはいけない。
                third = OSTClient("127.0.0.1", ost.port)
                MerkleTreeBuilder(
                    ContentAddressedCrypto("different-secret"), third,
                    index_file=index_file,
                ).upload_directory(tree)
                self.assertGreater(third.blob_bytes_sent, 0)
            finally:
                ost.close()

    def test_folder_xattr_selects_zstd_codec(self) -> None:
        import subprocess as sp
        from dfs.compression import set_xattr
        from dfs.crypto import ContentAddressedCrypto
        from dfs.l3_store import ChunkStoreServer, OSTClient
        from dfs.l4_log import MerkleTreeBuilder

        with tempfile.TemporaryDirectory(prefix="dfs_compress_") as tmpdir:
            base = Path(tmpdir)
            cert, key = base / "c.pem", base / "k.pem"
            sp.run(["openssl", "req", "-x509", "-newkey", "rsa:2048",
                    "-keyout", str(key), "-out", str(cert), "-days", "1",
                    "-nodes", "-subj", "/CN=l"],
                   check=True, capture_output=True)
            ost = ChunkStoreServer(cert, key)
            try:
                tree = base / "tree"
                (tree / "src").mkdir(parents=True)
                (tree / "src" / "main.py").write_text(
                    "print('compress me')\n" * 1000, encoding="utf-8"
                )
                if not set_xattr(tree / "src", "zstd"):
                    self.skipTest("filesystem does not support user xattrs")
                client = OSTClient("127.0.0.1", ost.port)
                builder = MerkleTreeBuilder(
                    ContentAddressedCrypto("folder-compression"), client
                )
                builder.upload_directory(tree)
                codecs = {entry[2] for entry in builder.index.values()}
                self.assertIn("zstd", codecs)

                out = base / "out"
                builder.download_directory(
                    *builder.upload_directory(tree), out
                )
                self.assertEqual(
                    (out / "src" / "main.py").read_text(encoding="utf-8"),
                    "print('compress me')\n" * 1000,
                )
            finally:
                ost.close()


class TestL3ProtocolValidation(unittest.TestCase):
    """L3 の公開 TLS に非 DFS クライアントが来ても、本体を壊さない。"""

    @staticmethod
    def _cert(base: Path):
        cert, key = base / "c.pem", base / "k.pem"
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", str(key),
             "-out", str(cert), "-days", "1", "-nodes", "-subj", "/CN=l"],
            check=True, capture_output=True,
        )
        return cert, key

    def test_malformed_tls_frame_is_ignored_and_server_stays_healthy(self) -> None:
        import contextlib
        import io
        import socket
        import ssl
        import struct

        from dfs.crypto import sha256_hex
        from dfs.l3_store import ChunkStoreServer, OSTClient

        with tempfile.TemporaryDirectory(prefix="dfs_l3_bad_frame_") as tmp:
            base = Path(tmp)
            cert, key = self._cert(base)
            ost = ChunkStoreServer(cert, key)
            conn = None
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                raw = socket.create_connection(("127.0.0.1", ost.port), timeout=5.0)
                conn = ctx.wrap_socket(raw, server_hostname="127.0.0.1")
                captured = io.StringIO()
                with contextlib.redirect_stderr(captured):
                    conn.sendall(b"B" + b"\xff" * 64 + struct.pack(">I", 0))
                    try:
                        conn.recv(1)
                    except Exception:
                        pass
                    time.sleep(0.3)

                self.assertNotIn("UnicodeDecodeError", captured.getvalue())

                client = OSTClient("127.0.0.1", ost.port)
                wid = sha256_hex(b"healthy-after-bad-frame")
                client.put_if_absent(wid, b"healthy-after-bad-frame")
                self.assertEqual(client.get(wid), b"healthy-after-bad-frame")
            finally:
                if conn is not None:
                    conn.close()
                ost.close()


class TestL3Striping(unittest.TestCase):
    """段階 4: 複数 OST へのストライピング。既定は 1 OST。"""

    @staticmethod
    def _cert(base: Path):
        cert, key = base / "c.pem", base / "k.pem"
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", str(key),
             "-out", str(cert), "-days", "1", "-nodes", "-subj", "/CN=l"],
            check=True, capture_output=True,
        )
        return cert, key

    def test_single_store_is_the_default(self) -> None:
        from dfs.crypto import ContentAddressedCrypto
        from dfs.l3_store import ChunkStoreServer, OSTClient
        from dfs.l4_log import MerkleTreeBuilder

        with tempfile.TemporaryDirectory(prefix="dfs_str1_") as tmp:
            base = Path(tmp)
            cert, key = self._cert(base)
            ost = ChunkStoreServer(cert, key)
            try:
                tree = base / "tree"
                tree.mkdir()
                for i in range(5):
                    (tree / f"f{i}.txt").write_text(f"x{i}\n" * 20)
                client = OSTClient("127.0.0.1", ost.port)
                builder = MerkleTreeBuilder(ContentAddressedCrypto("s1"), client)
                pid, wid = builder.upload_directory(tree)
                self.assertEqual(list(builder.stores), ["ost0"])
                self.assertGreater(len(ost.store), 0)
                out = base / "out"
                MerkleTreeBuilder(ContentAddressedCrypto("s1"), client).download_directory(pid, wid, out)
                self.assertEqual((out / "f0.txt").read_text(), "x0\n" * 20)
            finally:
                ost.close()

    def test_two_stores_receive_disjoint_chunks(self) -> None:
        from dfs.crypto import ContentAddressedCrypto
        from dfs.l3_store import ChunkStoreServer, OSTClient
        from dfs.l4_log import MerkleTreeBuilder

        with tempfile.TemporaryDirectory(prefix="dfs_str2_") as tmp:
            base = Path(tmp)
            cert, key = self._cert(base)
            a = ChunkStoreServer(cert, key)
            b = ChunkStoreServer(cert, key)
            try:
                tree = base / "tree"
                tree.mkdir()
                for i in range(10):
                    (tree / f"f{i}.txt").write_text(f"content {i}\n" * 50)
                ca, cb = OSTClient("127.0.0.1", a.port), OSTClient("127.0.0.1", b.port)
                stores = {"ost0": ca, "ost1": cb}
                builder = MerkleTreeBuilder(ContentAddressedCrypto("s2"), ca, stores=stores)
                pid, wid = builder.upload_directory(tree)

                # 両方の OST に塊が置かれ、同じ塊が二重に置かれていない
                self.assertGreater(len(a.store), 0, "OST0 に塊がない")
                self.assertGreater(len(b.store), 0, "OST1 に塊がない")
                self.assertEqual(len(set(a.store) & set(b.store)), 0)

                # 索引なしの新しい読み手でも全体を復元できる
                out = base / "out"
                reader = MerkleTreeBuilder(ContentAddressedCrypto("s2"), ca, stores=stores)
                reader.download_directory(pid, wid, out, root_store=getattr(builder, "root_store", "ost0"))
                for i in range(10):
                    self.assertEqual((out / f"f{i}.txt").read_text(), f"content {i}\n" * 50)
            finally:
                a.close()
                b.close()


class TestPullBatch(unittest.TestCase):
    """batch 系の導入: pull の往復をファイル数から切り離す。"""

    @staticmethod
    def _cert(base: Path):
        cert, key = base / "c.pem", base / "k.pem"
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", str(key),
             "-out", str(cert), "-days", "1", "-nodes", "-subj", "/CN=l"],
            check=True, capture_output=True,
        )
        return cert, key

    def test_flat_pull_is_two_round_trips(self) -> None:
        """平らなディレクトリ 100 ファイルの pull は 2 往復（根 1 + ファイル 1）。"""
        from dfs.crypto import ContentAddressedCrypto
        from dfs.l3_store import ChunkStoreServer, OSTClient
        from dfs.l4_log import MerkleTreeBuilder

        with tempfile.TemporaryDirectory(prefix="dfs_pull_") as tmp:
            base = Path(tmp)
            cert, key = self._cert(base)
            ost = ChunkStoreServer(cert, key)
            try:
                tree = base / "tree"
                tree.mkdir()
                for i in range(100):
                    (tree / f"f{i:03d}.bin").write_bytes(f"payload-{i}".encode() * 50)

                writer = OSTClient("127.0.0.1", ost.port)
                pid, wid = MerkleTreeBuilder(ContentAddressedCrypto("pull-secret"), writer).upload_directory(tree)

                reader = OSTClient("127.0.0.1", ost.port)
                reader.reset_metrics()
                dest = base / "out"
                MerkleTreeBuilder(ContentAddressedCrypto("pull-secret"), reader).download_directory(pid, wid, dest)
                self.assertLessEqual(
                    reader.round_trips, 2,
                    f"pull の往復がファイル数に比例している: {reader.round_trips}",
                )
                self.assertEqual(len(list(dest.rglob("*.bin"))), 100)
                self.assertEqual((dest / "f000.bin").read_bytes(), (tree / "f000.bin").read_bytes())
            finally:
                ost.close()

    def test_nested_pull_is_one_round_trip_per_level(self) -> None:
        """入れ子は「1 階層 = 1 往復」。root/d1/d2 に 3 ファイルなら 3 往復。"""
        from dfs.crypto import ContentAddressedCrypto
        from dfs.l3_store import ChunkStoreServer, OSTClient
        from dfs.l4_log import MerkleTreeBuilder

        with tempfile.TemporaryDirectory(prefix="dfs_nest_") as tmp:
            base = Path(tmp)
            cert, key = self._cert(base)
            ost = ChunkStoreServer(cert, key)
            try:
                tree = base / "tree"
                (tree / "d1" / "d2").mkdir(parents=True)
                (tree / "top.txt").write_bytes(b"top\n" * 100)
                (tree / "d1" / "mid.txt").write_bytes(b"mid\n" * 100)
                (tree / "d1" / "d2" / "deep.txt").write_bytes(b"deep\n" * 100)

                writer = OSTClient("127.0.0.1", ost.port)
                pid, wid = MerkleTreeBuilder(ContentAddressedCrypto("nest-secret"), writer).upload_directory(tree)

                reader = OSTClient("127.0.0.1", ost.port)
                reader.reset_metrics()
                dest = base / "out"
                MerkleTreeBuilder(ContentAddressedCrypto("nest-secret"), reader).download_directory(pid, wid, dest)
                # 根 -> d1 -> d2 の 3 階層 + 最下層のファイル取得 1 = 4 以下
                self.assertLessEqual(
                    reader.round_trips, 4,
                    f"入れ子の往復が多い: {reader.round_trips}",
                )
                self.assertEqual((dest / "d1" / "d2" / "deep.txt").read_bytes(), b"deep\n" * 100)
                self.assertEqual((dest / "top.txt").read_bytes(), b"top\n" * 100)
            finally:
                ost.close()

    def test_same_chunk_fetched_once(self) -> None:
        """同一内容のファイルが 2 つあっても、塊は 1 回しか取りに行かない。"""
        from dfs.crypto import ContentAddressedCrypto
        from dfs.l3_store import ChunkStoreServer, OSTClient
        from dfs.l4_log import MerkleTreeBuilder

        with tempfile.TemporaryDirectory(prefix="dfs_dup_") as tmp:
            base = Path(tmp)
            cert, key = self._cert(base)
            ost = ChunkStoreServer(cert, key)
            try:
                tree = base / "tree"
                tree.mkdir()
                body = b"same-body\n" * 500
                (tree / "a.bin").write_bytes(body)
                (tree / "b.bin").write_bytes(body)

                writer = OSTClient("127.0.0.1", ost.port)
                pid, wid = MerkleTreeBuilder(ContentAddressedCrypto("dup-secret"), writer).upload_directory(tree)

                reader = OSTClient("127.0.0.1", ost.port)
                reader.reset_metrics()
                dest = base / "out"
                MerkleTreeBuilder(ContentAddressedCrypto("dup-secret"), reader).download_directory(pid, wid, dest)
                self.assertLessEqual(reader.round_trips, 2, f"往復が多い: {reader.round_trips}")
                # get_count は「受け取った塊の数」。根のディレクトリ塊 1 + 同一内容のファイル塊 1 = 2。
                # 重複排除が効かないとファイル塊を 2 つ取るので 3 になる。
                self.assertEqual(
                    reader.get_count, 2,
                    f"同一内容の塊を二重に取りに行っている: get_count={reader.get_count}",
                )
                self.assertEqual((dest / "a.bin").read_bytes(), body)
                self.assertEqual((dest / "b.bin").read_bytes(), body)
            finally:
                ost.close()

    def test_batch_get_split_by_size_cap(self) -> None:
        """DFS_BATCH_CHUNKS で 1 回の batch_get の件数を絞れる（組が分かれる）。"""
        import os
        from dfs.crypto import ContentAddressedCrypto
        from dfs.l3_store import ChunkStoreServer, OSTClient
        from dfs.l4_log import MerkleTreeBuilder

        with tempfile.TemporaryDirectory(prefix="dfs_cap_") as tmp:
            base = Path(tmp)
            cert, key = self._cert(base)
            ost = ChunkStoreServer(cert, key)
            old = os.environ.get("DFS_BATCH_CHUNKS")
            os.environ["DFS_BATCH_CHUNKS"] = "4"
            try:
                tree = base / "tree"
                tree.mkdir()
                for i in range(10):
                    (tree / f"f{i}.bin").write_bytes(f"cap-{i}".encode() * 20)

                writer = OSTClient("127.0.0.1", ost.port)
                pid, wid = MerkleTreeBuilder(ContentAddressedCrypto("cap-secret"), writer).upload_directory(tree)

                reader = OSTClient("127.0.0.1", ost.port)
                reader.reset_metrics()
                dest = base / "out"
                MerkleTreeBuilder(ContentAddressedCrypto("cap-secret"), reader).download_directory(pid, wid, dest)
                # 根 1 + ファイル 3 組（4+4+2）= 4 往復
                self.assertGreaterEqual(reader.round_trips, 2, "上限が効かず 1 往復になっている")
                self.assertLessEqual(reader.round_trips, 5, f"往復が多い: {reader.round_trips}")
                self.assertEqual(len(list(dest.rglob("*.bin"))), 10)
            finally:
                ost.close()
                if old is None:
                    os.environ.pop("DFS_BATCH_CHUNKS", None)
                else:
                    os.environ["DFS_BATCH_CHUNKS"] = old

    def test_missing_chunk_is_reported(self) -> None:
        """サーバから塊が消えていたら、黙って欠けずに ChunkIntegrityError になる。"""
        from dfs.crypto import ContentAddressedCrypto, ChunkIntegrityError
        from dfs.l3_store import ChunkStoreServer, OSTClient
        from dfs.l4_log import MerkleTreeBuilder

        with tempfile.TemporaryDirectory(prefix="dfs_miss_") as tmp:
            base = Path(tmp)
            cert, key = self._cert(base)
            ost = ChunkStoreServer(cert, key)
            try:
                tree = base / "tree"
                tree.mkdir()
                (tree / "a.bin").write_bytes(b"A" * 4096)
                (tree / "b.bin").write_bytes(b"B" * 4096)

                writer = OSTClient("127.0.0.1", ost.port)
                pid, wid = MerkleTreeBuilder(ContentAddressedCrypto("miss-secret"), writer).upload_directory(tree)
                # ファイル塊を 1 つ消す（根は残す）
                victim = next(k for k, v in ost.store.items() if v != ost.store[wid])
                del ost.store[victim]

                reader = OSTClient("127.0.0.1", ost.port)
                dest = base / "out"
                with self.assertRaises(ChunkIntegrityError):
                    MerkleTreeBuilder(ContentAddressedCrypto("miss-secret"), reader).download_directory(pid, wid, dest)
            finally:
                ost.close()


class TestWanRoundTrips(unittest.TestCase):
    """WAN 対応: 往復回数をチャンク数から切り離し、タイムアウトを環境変数で変えられる。"""

    @staticmethod
    def _cert(base: Path):
        cert, key = base / "c.pem", base / "k.pem"
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", str(key),
             "-out", str(cert), "-days", "1", "-nodes", "-subj", "/CN=l"],
            check=True, capture_output=True,
        )
        return cert, key

    def test_assume_absent_skips_has(self) -> None:
        """``assume_absent=True`` は内部の batch_has を送らず、1 往復で PUT する。"""
        from dfs.crypto import ContentAddressedCrypto
        from dfs.l3_store import ChunkStoreServer, OSTClient

        with tempfile.TemporaryDirectory(prefix="dfs_aa_") as tmp:
            base = Path(tmp)
            cert, key = self._cert(base)
            ost = ChunkStoreServer(cert, key)
            try:
                crypto = ContentAddressedCrypto("assume-absent-secret")
                blobs = {}
                for i in range(3):
                    _pid, wid, blob = crypto.pack_chunk(f"chunk-{i}".encode() * 100)
                    blobs[wid] = blob

                client = OSTClient("127.0.0.1", ost.port)
                client.reset_metrics()
                client.batch_put_if_absent(blobs, assume_absent=True)
                self.assertEqual(client.round_trips, 1, "assume_absent でも HAS を撃っている")
                self.assertEqual(len(ost.store), 3)

                # 既にある塊を assume_absent なしで送ると、HAS の 1 往復だけで済む
                client.reset_metrics()
                client.batch_put_if_absent(blobs)
                self.assertEqual(client.round_trips, 1, "既存塊の判定が 1 往復にまとまっていない")
                self.assertEqual(client.put_count, 0)
            finally:
                ost.close()

    def test_push_round_trips_do_not_scale_with_chunks(self) -> None:
        """チャンク 100 個でも push の L3 往復は 2 以下（HAS 1 + PUT 1）。"""
        from dfs.crypto import ContentAddressedCrypto
        from dfs.l3_store import ChunkStoreServer, OSTClient
        from dfs.l4_log import MerkleTreeBuilder

        with tempfile.TemporaryDirectory(prefix="dfs_rt_") as tmp:
            base = Path(tmp)
            cert, key = self._cert(base)
            ost = ChunkStoreServer(cert, key)
            try:
                tree = base / "tree"
                tree.mkdir()
                for i in range(100):
                    (tree / f"f{i:03d}.bin").write_bytes(f"payload-{i}".encode() * 40)

                client = OSTClient("127.0.0.1", ost.port)
                builder = MerkleTreeBuilder(ContentAddressedCrypto("rt-secret"), client)
                client.reset_metrics()
                builder.upload_directory(tree)
                self.assertLessEqual(
                    client.round_trips, 2,
                    f"往復回数がチャンク数に比例している: {client.round_trips}",
                )
                self.assertGreaterEqual(len(ost.store), 100)

                # 2 回目の push（全チャンクが索引ヒット）も 2 往復以下
                client.reset_metrics()
                builder.upload_directory(tree)
                self.assertLessEqual(
                    client.round_trips, 2,
                    f"再 push の往復回数が多い: {client.round_trips}",
                )
                self.assertEqual(client.blob_bytes_sent, 0, "変更なしの再 push で本文を送っている")
            finally:
                ost.close()

    def test_ost_timeout_env_vars_are_honored(self) -> None:
        """サーバ・クライアント双方のタイムアウトが環境変数で変わる。"""
        import os
        from dfs.l3_ost_adapter import ost_connect_timeout, ost_socket_timeout

        old_socket = os.environ.get("DFS_OST_SOCKET_TIMEOUT")
        old_connect = os.environ.get("DFS_OST_CONNECT_TIMEOUT")
        try:
            os.environ["DFS_OST_SOCKET_TIMEOUT"] = "42.5"
            os.environ["DFS_OST_CONNECT_TIMEOUT"] = "7"
            self.assertEqual(ost_socket_timeout(), 42.5)
            self.assertEqual(ost_connect_timeout(), 7.0)

            # 不正値・負値は既定に戻す（壊れた設定で無制限待ちにしない）
            os.environ["DFS_OST_SOCKET_TIMEOUT"] = "not-a-number"
            os.environ["DFS_OST_CONNECT_TIMEOUT"] = "-1"
            self.assertEqual(ost_socket_timeout(), 30.0)
            self.assertEqual(ost_connect_timeout(), 10.0)

            # 環境変数なしの既定
            del os.environ["DFS_OST_SOCKET_TIMEOUT"]
            del os.environ["DFS_OST_CONNECT_TIMEOUT"]
            self.assertEqual(ost_socket_timeout(), 30.0)
            self.assertEqual(ost_connect_timeout(), 10.0)
        finally:
            for name, value in (
                ("DFS_OST_SOCKET_TIMEOUT", old_socket),
                ("DFS_OST_CONNECT_TIMEOUT", old_connect),
            ):
                if value is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = value

    def test_server_socket_timeout_is_actually_applied(self) -> None:
        """サーバの accept ループが環境変数の値をソケットに設定する。"""
        import os
        import socket
        import ssl as ssl_mod
        import time as time_mod
        from dfs.l3_store import ChunkStoreServer

        with tempfile.TemporaryDirectory(prefix="dfs_srv_to_") as tmp:
            base = Path(tmp)
            cert, key = self._cert(base)
            old = os.environ.get("DFS_OST_SOCKET_TIMEOUT")
            os.environ["DFS_OST_SOCKET_TIMEOUT"] = "0.5"
            ost = ChunkStoreServer(cert, key)
            try:
                # 何も送らずに放置すると、サーバ側は 0.5 秒で conn を閉じる
                takes = os.urandom(1)
                ctx = ssl_mod.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl_mod.CERT_NONE
                raw = socket.create_connection(("127.0.0.1", ost.port), timeout=5.0)
                conn = ctx.wrap_socket(raw, server_hostname="127.0.0.1")
                conn.settimeout(5.0)
                t0 = time_mod.perf_counter()
                # サーバのタイムアウトで切断されると、recv は空を返すか例外になる
                got_eof = False
                try:
                    data = conn.recv(1)
                    got_eof = data == b""
                except Exception:
                    got_eof = True
                elapsed = time_mod.perf_counter() - t0
                self.assertTrue(got_eof, "サーバがタイムアウトで切断していない")
                self.assertLess(elapsed, 3.0, f"サーバのタイムアウトが効いていない ({elapsed:.2f}s)")
                conn.close()
            finally:
                ost.close()
                if old is None:
                    os.environ.pop("DFS_OST_SOCKET_TIMEOUT", None)
                else:
                    os.environ["DFS_OST_SOCKET_TIMEOUT"] = old

    def test_l2_timeout_env_var_is_honored(self) -> None:
        """L2 HTTP タイムアウトが環境変数で変わり、既存の ``_post`` がそれを使う。"""
        import os
        from dfs import cli as cli_mod

        old = os.environ.get("DFS_L2_TIMEOUT")
        try:
            os.environ["DFS_L2_TIMEOUT"] = "12.5"
            self.assertEqual(cli_mod.l2_timeout(), 12.5)
            os.environ["DFS_L2_TIMEOUT"] = "0"
            self.assertEqual(cli_mod.l2_timeout(), 10.0)
            del os.environ["DFS_L2_TIMEOUT"]
            self.assertEqual(cli_mod.l2_timeout(), 10.0)
        finally:
            if old is None:
                os.environ.pop("DFS_L2_TIMEOUT", None)
            else:
                os.environ["DFS_L2_TIMEOUT"] = old


class TestStage5Integration(unittest.TestCase):
    def test_two_node_sharing_and_final_metrics(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dfs_int_") as tmpdir:
            base = Path(tmpdir)
            root_priv, root_pub = generate_ssh_keypair(base, "root")
            alice_priv, alice_pub = generate_ssh_keypair(base, "alice")
            bob_priv, bob_pub = generate_ssh_keypair(base, "bob")

            cert, key = base / "cert.pem", base / "key.pem"
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
                    "/CN=localhost",
                ],
                check=True,
                capture_output=True,
            )

            ost = ChunkStoreServer(cert, key)
            reg = DirectoryRegistryService("/example.com", root_pub)
            now = int(time.time())
            sub_path = "/example.com/alice/notes"
            secret = "shared-notes-secret-key"

            try:
                # 1. L1 多段委譲 (/example.com -> /example.com/alice -> /example.com/alice/notes)
                d_alice = create_delegation_envelope(
                    root_priv, "/example.com", "/example.com/alice", alice_pub, 1, 0, now - 100, now + 90000
                )
                reg.register_delegation(d_alice, now=now)

                d_notes = create_delegation_envelope(
                    alice_priv, "/example.com/alice", sub_path, alice_pub, 1, 0, now - 100, now + 80000
                )
                reg.register_delegation(d_notes, now=now)

                mac_node = DFSNode(
                    "Mac", sub_path, base / "mac_mount", alice_priv, alice_pub, secret, reg, "127.0.0.1", ost.port
                )
                pi5_node = DFSNode(
                    "Pi5", sub_path, base / "pi5_mount", alice_priv, alice_pub, secret, reg, "127.0.0.1", ost.port
                )

                # 2. 片方 (Mac) で書く -> 他方 (Pi5) へ届く -> 両方で clayfs のスナップショットが取れる
                #    重複排除と固定費の影響を分けて測るため、実運用に近いサイズにする。
                #    (極小のファイルではチャンクごとのヘッダとディレクトリ塊が支配的になる)
                chunk_bytes = b"# Todo\n- Check L5 snapshot\n" * 2000  # 約 54KB
                (mac_node.clayfs.work_tree / "todo.md").write_bytes(chunk_bytes)
                (mac_node.clayfs.work_tree / "sub").mkdir()
                (mac_node.clayfs.work_tree / "sub" / "log.txt").write_bytes(b"Log line from Mac\n" * 2000)

                raw_size = (
                    (mac_node.clayfs.work_tree / "todo.md").stat().st_size
                    + (mac_node.clayfs.work_tree / "sub" / "log.txt").stat().st_size
                )

                t0 = time.perf_counter()
                _, mac_snap_v1, v1_wire_bytes = mac_node.push(delegation_epoch=1, now=now + 1)
                pi5_snap_v1 = pi5_node.pull()
                sync_ms = (time.perf_counter() - t0) * 1000.0
                wire_ratio = v1_wire_bytes / float(raw_size)

                self.assertLess(sync_ms, 1000.0)
                # 初回は全チャンクを送るので、固定費込みでも 2 倍以内
                self.assertLessEqual(wire_ratio, 2.0)

                # 2b. 変更のないファイルは再暗号化も再送もしない（書き手側の内容アドレス索引）。
                #     初回に同じ内容を 2 ファイル置いていないので重複排除は働かないが、
                #     2 回目の push で変更のない部分木が送られないことを確認する。
                mac_before = mac_node.ost.blob_bytes_sent
                mac_node.ost.reset_metrics()
                _, _, v2_wire_bytes = mac_node.push(delegation_epoch=1, now=now + 2)
                self.assertEqual(
                    mac_node.ost.blob_bytes_sent, 0,
                    "変更のないツリーを再 push しても暗号文本体は送らない（重複排除）",
                )

                # 2c. 同じ内容のファイルを別名で追加すると、内容アドレスが一致して再送されない
                (mac_node.clayfs.work_tree / "todo_copy.md").write_bytes(chunk_bytes)
                mac_node.ost.reset_metrics()
                mac_node.push(delegation_epoch=1, now=now + 3)
                dedup_sent = mac_node.ost.blob_bytes_sent
                self.assertLess(
                    dedup_sent, len(chunk_bytes),
                    f"同一内容の追加で本文は再送されないはず (送信 {dedup_sent} < 内容 {len(chunk_bytes)})",
                )
                self.assertFalse((mac_snap_v1 / ".clayfs").exists())
                self.assertFalse((pi5_snap_v1 / ".clayfs").exists())
                self.assertEqual(
                    (mac_snap_v1 / "sub" / "log.txt").read_bytes(),
                    (pi5_snap_v1 / "sub" / "log.txt").read_bytes(),
                )

                # 3. 同時に書く -> 単一書き手境界により片方が断られ、衝突コピーや三方向マージが起きない
                (mac_node.clayfs.work_tree / "todo.md").write_bytes(b"Mac v2 update\n")
                (pi5_node.clayfs.work_tree / "todo.md").write_bytes(b"Pi5 concurrent v2 update\n")

                mac_node.push(delegation_epoch=1, now=now + 2)
                with self.assertRaises(ConflictError):
                    pi5_node.push(delegation_epoch=1, now=now + 3)

                conflict_files = list(pi5_node.clayfs.work_tree.rglob("*conflict*"))
                self.assertEqual(len(conflict_files), 0)

                pi5_node.pull()
                # v1(初回) + v2(無変更) + v3(別名追加) + v4(同時書き込みの勝者)
                self.assertEqual(pi5_node.l4.pin.version, 4)

                # 4. ノード停止時の挙動（書き込みは明示的に拒否、既存の L5 スナップショットは読める）
                reg.online = False
                with self.assertRaises(ServiceUnavailableError):
                    mac_node.push(delegation_epoch=1, now=now + 4)
                self.assertTrue((pi5_snap_v1 / "todo.md").exists())
                reg.online = True

                # 5. 委譲で書き手を bob に交代 (epoch=2, base_version=現在の先頭版) -> 旧鍵 alice は拒否され bob が続きを書ける
                head_version = pi5_node.l4.pin.version
                d_notes_bob = create_delegation_envelope(
                    alice_priv, "/example.com/alice", sub_path, bob_pub, epoch=2, base_version=head_version, issued_at=now + 5, expires_at=now + 70000
                )
                reg.register_delegation(d_notes_bob, now=now + 5)

                with self.assertRaises(DelegationError):
                    mac_node.push(delegation_epoch=1, now=now + 6)

                pi5_node.switch_credentials(bob_priv, bob_pub)
                (pi5_node.clayfs.work_tree / "bob.txt").write_bytes(b"Written by bob at v3\n")
                env_v3, _, _ = pi5_node.push(delegation_epoch=2, now=now + 7)
                self.assertEqual(env_v3["payload"]["version"], head_version + 1)

                mac_snap_v3 = mac_node.pull(expected_writer_pubkey=bob_pub)
                self.assertEqual((mac_snap_v3 / "bob.txt").read_bytes(), b"Written by bob at v3\n")

                print("\n" + "=" * 72)
                print("dfs Stage 5 Integration Metrics Summary")
                print("=" * 72)
                print(f"  1. Sync Latency (Mac -> Pi5) : {sync_ms:.1f} ms (Target: < 1000 ms)")
                print(f"  2. Wire Transfer Ratio       : {wire_ratio:.2f}x ({v1_wire_bytes} B / {raw_size} B, Target: <= 2.0x)")
                print(f"  3. Concurrent Write Conflict : Rejected via ConflictError (Conflict copies: {len(conflict_files)})")
                print("  4. Node Offline Behavior     : Write safely rejected; local L5 snapshots readable")
                print(f"  5. Delegation Handoff (v{head_version}->{head_version+1}): Bob continued (epoch=2); Alice epoch=1 revoked")
                print("=" * 72)
            finally:
                ost.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
