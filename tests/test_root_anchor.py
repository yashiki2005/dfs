#!/usr/bin/env python3
"""
dfs/tests/test_root_anchor.py
root アンカーによる委譲チェーン検証（穴を塞いだこと）の試験。

要点:
  - 名簿を信頼しない。末端の委譲が root まで連鎖することを、手元の root 公開鍵で検証する。
  - 名簿が「root 公開鍵」を主張しても、手元の記録と違えば使わない。
  - TOFU（初回に名簿から取って記録）と、明示指定（本番）の両方。
"""

import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dfs.crypto import (
    EMPTY_SHA256,
    NS_L4_LOG,
    canonical_json,
    sha256_hex,
    ssh_key_fingerprint,
    ssh_sign,
)
from dfs.l1_delegation import create_delegation_envelope, verify_delegation_chain
from dfs.l2_registry import DirectoryRegistryService
from dfs.l4_log import L4LogClient


def keypair(base: Path, name: str) -> Path:
    priv = base / name
    subprocess.run(
        ["ssh-keygen", "-t", "ed25519", "-N", "", "-C", f"{name}@test", "-f", str(priv)],
        check=True, capture_output=True,
    )
    return priv


class RootAnchorCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="dfs_root_")
        self.base = Path(self._tmp.name)
        self.root_key = keypair(self.base, "root")
        self.alice_key = keypair(self.base, "alice")
        self.attacker_key = keypair(self.base, "attacker")
        self.client_key = keypair(self.base, "client")
        self.root_pub = Path(f"{self.root_key}.pub").read_text(encoding="utf-8").strip()
        self.alice_pub = Path(f"{self.alice_key}.pub").read_text(encoding="utf-8").strip()
        self.attacker_pub = Path(f"{self.attacker_key}.pub").read_text(encoding="utf-8").strip()
        self.client_pub = Path(f"{self.client_key}.pub").read_text(encoding="utf-8").strip()
        self.now = int(time.time())
        self.path = "/example.com/alice/notes"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    # ---- 補助 ----
    def _registry_with_real_chain(self) -> DirectoryRegistryService:
        """root -> alice -> notes の正しいチェーンを持つ名簿。"""
        svc = DirectoryRegistryService("/example.com", self.root_pub)
        d1 = create_delegation_envelope(
            self.root_key, "/example.com", "/example.com/alice",
            self.alice_pub, 1, 0, self.now - 60, self.now + 90000,
        )
        svc.register_delegation(d1, now=self.now)
        d2 = create_delegation_envelope(
            self.alice_key, "/example.com/alice", self.path,
            self.alice_pub, 1, 0, self.now - 60, self.now + 80000,
        )
        svc.register_delegation(d2, now=self.now)
        return svc

    def _evil_registry(self):
        """root に連鎖しない偽の委譲と、攻撃者の鍵で署名した先頭版を返す名簿。"""
        leaf = create_delegation_envelope(
            self.attacker_key, "/example.com", self.path, self.attacker_pub,
            epoch=1, base_version=0, issued_at=self.now - 60, expires_at=self.now + 90000,
        )
        leaf = dict(leaf)
        leaf["chain"] = [leaf]
        leaf["root_anchor"] = "/example.com"

        payload = {
            "delegation_epoch": 1, "parent_hash": EMPTY_SHA256, "parent_version": 0,
            "path": self.path, "root_plain_id": "aa" * 32, "root_wire_id": "bb" * 32,
            "timestamp": self.now, "version": 1,
        }
        raw = canonical_json(payload)
        head = {
            "entry_hash": sha256_hex(raw), "payload": payload,
            "signature": ssh_sign(self.attacker_key, NS_L4_LOG, raw),
        }

        class Evil:
            def resolve(self, p):
                return leaf, None, head

        return Evil()

    # ---- 試験 ----
    def test_resolve_returns_chain_and_root_anchor(self) -> None:
        """名簿は末端の委譲に、チェーン全体と root アンカーを足して返す。"""
        svc = self._registry_with_real_chain()
        del_env, _loc, _head = svc.resolve(self.path)
        self.assertIn("chain", del_env)
        self.assertEqual(del_env["root_anchor"], "/example.com")
        paths = [e["payload"]["path"] for e in del_env["chain"]]
        self.assertEqual(paths, ["/example.com/alice", self.path], "チェーンの順序が違う")

    def test_valid_chain_is_accepted_with_root_pubkey(self) -> None:
        """正しいチェーンは、手元の root 公開鍵で検証して通る。"""
        svc = self._registry_with_real_chain()
        del_env, _loc, head = svc.resolve(self.path)
        # 末端の委譲の writer で、先頭版を署名する（名簿はこれをしないので、ここで作る）
        payload = {
            "delegation_epoch": 1, "parent_hash": EMPTY_SHA256, "parent_version": 0,
            "path": self.path, "root_plain_id": "cc" * 32, "root_wire_id": "dd" * 32,
            "timestamp": self.now, "version": 1,
        }
        raw = canonical_json(payload)
        head = {
            "entry_hash": sha256_hex(raw), "payload": payload,
            "signature": ssh_sign(self.alice_key, NS_L4_LOG, raw),
        }

        class Reg:
            def resolve(self, p):
                return del_env, None, head

        client = L4LogClient(
            self.path, self.client_key, self.client_pub,
            pin_file=self.base / "pin_ok.json", root_pubkey=self.root_pub,
        )
        result = client.sync_head(Reg())
        self.assertEqual(result["payload"]["version"], 1)

    def test_evil_chain_is_rejected_with_root_pubkey(self) -> None:
        """root に連鎖しない偽の委譲は、手元の root 公開鍵で拒否する（穴を塞いだ）。"""
        client = L4LogClient(
            self.path, self.client_key, self.client_pub,
            pin_file=self.base / "pin_bad.json", root_pubkey=self.root_pub,
        )
        with self.assertRaises(Exception) as ctx:
            client.sync_head(self._evil_registry())
        self.assertIn("Invalid L1 delegation signature", str(ctx.exception))

    def test_evil_chain_is_accepted_before_tofu(self) -> None:
        """TOFU 前（root 未設定）は検証できないので通る。これは既知の限界。

        SSH の known_hosts と同じで、初回に欺かれると弱い。本番は --root-pubkey で
        初回から固定する。ここで「通ってしまう」ことを記録として残しておく。
        """
        client = L4LogClient(
            self.path, self.client_key, self.client_pub,
            pin_file=self.base / "pin_tofu.json",  # root_pubkey を渡さない
        )
        result = client.sync_head(self._evil_registry())
        self.assertEqual(result["payload"]["version"], 1)

    def test_fingerprint_matches_openssh(self) -> None:
        """指紋の計算が ssh-keygen -lf と一致する。"""
        res = subprocess.run(
            ["ssh-keygen", "-lf", f"{self.root_key}.pub"],
            capture_output=True, text=True, check=True,
        )
        expected = res.stdout.split()[1]
        self.assertEqual(ssh_key_fingerprint(self.root_pub), expected)

    def test_registry_reports_root_pubkey(self) -> None:
        """名簿の /v1/paths 相当（root_anchor_info）が root 公開鍵を返す。"""
        # DirectoryRegistryService は root 公開鍵を持っている
        svc = self._registry_with_real_chain()
        self.assertEqual(svc.root_anchor_pubkey, self.root_pub)

    def test_chain_must_start_at_root(self) -> None:
        """root から始まらないチェーンは verify_delegation_chain が拒否する。"""
        d = create_delegation_envelope(
            self.alice_key, "/example.com/alice", self.path,
            self.alice_pub, 1, 0, self.now - 60, self.now + 80000,
        )
        with self.assertRaises(Exception):
            verify_delegation_chain("/example.com", self.root_pub, [d], now=self.now)


if __name__ == "__main__":
    unittest.main(verbosity=2)
