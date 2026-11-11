#!/usr/bin/env python3
"""
dfs5/tests/test_evil_suite.py
段階 1・2・4 のセキュリティ・耐攻撃性（evil 試験 A2, A5, B6, B7、L1 5不変条件、単一書き手排他、委譲失効）回帰試験。
"""

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dfs5.crypto import ChunkIntegrityError
from dfs5.l1_delegation import (
    DelegationError,
    create_delegation_envelope,
    verify_delegation_chain,
)
from dfs5.l2_registry import ConflictError, DirectoryRegistryService
from dfs5.l3_ost_adapter import MiniLustreOSTServer
from dfs5.l4_log import RollbackDetectedError, SilentDropDetectedError
from dfs5.l5_clayfs import DFS5Node


def generate_ssh_keypair(dirpath: Path, name: str) -> tuple[Path, str]:
    priv = dirpath / f"{name}_ed25519"
    subprocess.run(
        ["ssh-keygen", "-t", "ed25519", "-N", "", "-C", f"{name}@example.com", "-f", str(priv)],
        check=True,
        capture_output=True,
    )
    pub = Path(f"{priv}.pub").read_text(encoding="utf-8").strip()
    return priv, pub


def generate_tls_cert(dirpath: Path) -> tuple[Path, Path]:
    cert, key = dirpath / "cert.pem", dirpath / "key.pem"
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
    return cert, key


class TestEvilSuite(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmpdir = tempfile.TemporaryDirectory(prefix="dfs5_evil_")
        cls.base = Path(cls.tmpdir.name)
        cls.root_priv, cls.root_pub = generate_ssh_keypair(cls.base, "root")
        cls.alice_priv, cls.alice_pub = generate_ssh_keypair(cls.base, "alice")
        cls.bob_priv, cls.bob_pub = generate_ssh_keypair(cls.base, "bob")
        cls.cert, cls.key = generate_tls_cert(cls.base)
        cls.now = 1763000000

    @classmethod
    def tearDownClass(cls) -> None:
        cls.tmpdir.cleanup()

    def _create_env(self, test_id: str) -> tuple[MiniLustreOSTServer, DirectoryRegistryService, DFS5Node]:
        ost = MiniLustreOSTServer(self.cert, self.key)
        reg = DirectoryRegistryService("/example.com", self.root_pub)
        del_env = create_delegation_envelope(
            self.root_priv,
            parent="/example.com",
            path="/example.com/alice",
            writer_pubkey=self.alice_pub,
            epoch=1,
            base_version=0,
            issued_at=self.now - 100,
            expires_at=self.now + 10000,
        )
        reg.register_delegation(del_env, now=self.now)
        node = DFS5Node(
            name="alice_node",
            sub_path="/example.com/alice",
            mount_root=self.base / f"mount_{test_id}",
            priv_key_path=self.alice_priv,
            pub_key_str=self.alice_pub,
            tree_secret="evil-suite-secret",
            registry=reg,
            ost_host="127.0.0.1",
            ost_port=ost.port,
        )
        return ost, reg, node

    def test_l1_delegation_invariants(self) -> None:
        """段階1: L1 の 4 ケース (a: 正常, b: 偽造/スコープ外, c: 期限切れ, d: 再委譲と期限包含)"""
        # (a) 正しい委譲と (d) 再委譲チェーン
        d1 = create_delegation_envelope(
            self.root_priv, "/example.com", "/example.com/alice", self.alice_pub, 1, 0, self.now - 50, self.now + 5000
        )
        d2 = create_delegation_envelope(
            self.alice_priv,
            "/example.com/alice",
            "/example.com/alice/shared",
            self.bob_pub,
            1,
            0,
            self.now - 10,
            self.now + 4000,
        )
        leaf = verify_delegation_chain("/example.com", self.root_pub, [d1, d2], now=self.now)
        self.assertEqual(leaf["writer"], self.bob_pub)

        # (b) 偽の委譲（bob が root のふりをして署名）
        fake_d1 = create_delegation_envelope(
            self.bob_priv, "/example.com", "/example.com/alice", self.bob_pub, 1, 0, self.now - 50, self.now + 5000
        )
        with self.assertRaises(DelegationError):
            verify_delegation_chain("/example.com", self.root_pub, [fake_d1], now=self.now)

        # (c) 期限切れ
        with self.assertRaises(DelegationError):
            verify_delegation_chain("/example.com", self.root_pub, [d1, d2], now=self.now + 4500)

        # (d-fail) 子の有効期限が親の有効期限を超えている場合は拒否
        d2_exceed = create_delegation_envelope(
            self.alice_priv,
            "/example.com/alice",
            "/example.com/alice/shared",
            self.bob_pub,
            1,
            0,
            self.now - 10,
            self.now + 9999,
        )
        with self.assertRaises(DelegationError):
            verify_delegation_chain("/example.com", self.root_pub, [d1, d2_exceed], now=self.now)

    def test_evil_A2_chunk_tampering(self) -> None:
        """evil A2: OST 上の塊が 1 バイトでも改ざんされたら pull 時に検知して拒否すること"""
        ost, reg, node_a = self._create_env("a2_a")
        try:
            (node_a.clayfs.work_tree / "secret.txt").write_bytes(b"Unmodified payload")
            node_a.push(delegation_epoch=1, now=self.now)

            # OST 内の全チャンクの末尾 1 バイトを破壊
            for wid in list(ost.store.keys()):
                corrupted = bytearray(ost.store[wid])
                corrupted[-1] ^= 0xFF
                ost.store[wid] = bytes(corrupted)

            node_b = DFS5Node(
                "reader",
                "/example.com/alice",
                self.base / "mount_a2_b",
                self.alice_priv,
                self.alice_pub,
                "evil-suite-secret",
                reg,
                "127.0.0.1",
                ost.port,
            )
            with self.assertRaises(ChunkIntegrityError):
                node_b.pull()
        finally:
            ost.close()

    def test_evil_A5_replay_attack(self) -> None:
        """evil A5: 盗聴した正当な署名付き書き込み要求を再送しても CAS 単調性により拒否されること"""
        ost, reg, node = self._create_env("a5")
        try:
            (node.clayfs.work_tree / "a.txt").write_bytes(b"v1")
            log_env_v1, _, _ = node.push(delegation_epoch=1, now=self.now)
            _, loc_env_v1, _ = reg.resolve("/example.com/alice")
            assert loc_env_v1 is not None

            with self.assertRaises(ConflictError):
                reg.announce_and_append("/example.com/alice", log_env_v1, loc_env_v1, now=self.now + 5)
        finally:
            ost.close()

    def test_evil_B6_rollback_detection(self) -> None:
        """evil B6: 中継者が古い索引 (v1) を最新と見せかけても RollbackDetectedError で拒否すること"""
        ost, reg, node = self._create_env("b6")
        try:
            (node.clayfs.work_tree / "a.txt").write_bytes(b"v1")
            node.push(delegation_epoch=1, now=self.now)
            (node.clayfs.work_tree / "a.txt").write_bytes(b"v2")
            node.push(delegation_epoch=1, now=self.now + 1)
            self.assertEqual(node.l4.pin.version, 2)

            # 名簿が v2 を隠して v1 (index=0) を返すように細工
            reg.simulate_rollback_b6_to_index = 0
            with self.assertRaises(RollbackDetectedError):
                node.pull()
        finally:
            ost.close()

    def test_evil_B7_silent_drop_detection(self) -> None:
        """evil B7: 書き込みを黙って捨てる中継者に対して成功と報告せず SilentDropDetectedError を出すこと"""
        ost, reg, node = self._create_env("b7")
        try:
            (node.clayfs.work_tree / "a.txt").write_bytes(b"v1")
            node.push(delegation_epoch=1, now=self.now)

            reg.simulate_silent_drop_b7 = True
            (node.clayfs.work_tree / "a.txt").write_bytes(b"v2 dropped")
            with self.assertRaises(SilentDropDetectedError):
                node.push(delegation_epoch=1, now=self.now + 1)

            # ピンが v1 のまま維持されていること
            self.assertEqual(node.l4.pin.version, 1)
        finally:
            ost.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)