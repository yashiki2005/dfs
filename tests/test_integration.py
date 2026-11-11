#!/usr/bin/env python3
"""
dfs5/tests/test_integration.py
段階 5: 2 台 ([Mac] と [Pi5]) で 1 つのツリーを共有する統合試験および最終 5 指標の計測スイート。
"""

import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dfs5.l1_delegation import DelegationError, create_delegation_envelope
from dfs5.l2_registry import ConflictError, DirectoryRegistryService, ServiceUnavailableError
from dfs5.l3_ost_adapter import MiniLustreOSTServer
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


class TestStage5Integration(unittest.TestCase):
    def test_two_node_sharing_and_final_metrics(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dfs5_int_") as tmpdir:
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

            ost = MiniLustreOSTServer(cert, key)
            reg = DirectoryRegistryService("/example.com", root_pub)
            now = 1763000000
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

                mac_node = DFS5Node(
                    "Mac", sub_path, base / "mac_mount", alice_priv, alice_pub, secret, reg, "127.0.0.1", ost.port
                )
                pi5_node = DFS5Node(
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
                print("dfs5 Stage 5 Integration Metrics Summary")
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