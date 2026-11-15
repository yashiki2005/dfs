#!/usr/bin/env python3
"""libp2p/QUIC chunk source の試験（サーバは別プロセス）。"""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dfs.crypto import ChunkIntegrityError
from dfs.l2_registry import ServiceUnavailableError
from dfs.l3_ost_adapter import SwarmOSTClient
from dfs.libp2p_chunk import (
    Libp2pChunkClient,
    Libp2pHostManager,
    Libp2pPeerClient,
    is_libp2p_available,
)


class TestLibp2pChunkSource(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="dfs_libp2p_")
        self.base = Path(self._tmp.name)
        self.chunks = self.base / "chunks"
        self.chunks.mkdir()
        self.store = {}
        for blob in (b"alpha", b"bravo" * 100):
            wid = hashlib.sha256(blob).hexdigest()
            self.store[wid] = blob
            (self.chunks / f"{wid}.blk").write_bytes(blob)

        repo = str(Path(__file__).resolve().parents[1])
        env = dict(os.environ)
        env["PYTHONPATH"] = repo + (
            os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else ""
        )
        self.proc = subprocess.Popen(
            [
                sys.executable, "-m", "dfs.libp2p_chunk",
                "--chunks-dir", str(self.chunks),
                "--listen", "/ip4/127.0.0.1/udp/0/quic-v1",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        )
        self.addCleanup(self._stop)
        line = self.proc.stdout.readline().strip()
        if not line.startswith("READY "):
            err = self.proc.stderr.read()
            self.skipTest(f"libp2p QUIC unavailable: {line} {err}")
        self.addr = line[len("READY ") :]
        self.client = Libp2pChunkClient([self.addr]).start()
        self.addCleanup(self.client.close)

    def _stop(self) -> None:
        self.proc.terminate()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        self._tmp.cleanup()

    def test_quic_batch_has_and_get(self) -> None:
        ids = sorted(self.store)
        self.assertEqual(self.client.batch_has(ids), {wid: True for wid in ids})
        self.assertEqual(self.client.batch_get(ids), self.store)
        self.assertEqual(self.client.get(ids[0]), self.store[ids[0]])

    def test_missing_chunk_is_rejected(self) -> None:
        missing = hashlib.sha256(b"missing").hexdigest()
        self.assertFalse(self.client.batch_has([missing])[missing])
        with self.assertRaises(ChunkIntegrityError):
            self.client.batch_get([missing])

    def test_source_is_read_only(self) -> None:
        with self.assertRaises(ServiceUnavailableError):
            self.client.batch_put_if_absent({"x": b"y"})


class TestLibp2pHostManagerAndDHT(unittest.TestCase):
    def setUp(self) -> None:
        if not is_libp2p_available():
            self.skipTest("libp2p is not installed")

    def test_resident_host_allowlist_and_connection_reuse(self) -> None:
        blob1 = b"p2p-chunk-one-" * 64
        blob2 = b"p2p-chunk-two-" * 64
        w1 = hashlib.sha256(blob1).hexdigest()
        w2 = hashlib.sha256(blob2).hexdigest()
        store = {w1: blob1, w2: blob2}

        # 許可リスト空で起動 → 未登録 PeerID は拒否される
        server_mgr = Libp2pHostManager(
            store=store,
            listen=["/ip4/127.0.0.1/udp/0/quic-v1"],
            allowed_peer_ids=[],
            enable_dht=True,
            dht_mode="server",
            enable_relay=True,
            relay_hop=True,
            enable_dcutr=True,
        ).start()
        self.addCleanup(server_mgr.close)

        client_mgr = Libp2pHostManager(
            listen=["/ip4/127.0.0.1/udp/0/quic-v1"],
            enable_dht=True,
            dht_mode="server",
            enable_relay=True,
            relay_hop=False,
            enable_dcutr=True,
            bootstrap_peers=[server_mgr.addrs[0]],
        ).start()
        self.addCleanup(client_mgr.close)

        peer_client = Libp2pPeerClient(client_mgr, server_mgr.peer_id, server_mgr.addrs)
        with self.assertRaises(Exception):
            peer_client.batch_has([w1])

        # PeerID をドメイン許可リストに追加すると接続・取得が通る
        server_mgr.allow_peer_id(client_mgr.peer_id)
        self.assertEqual(peer_client.batch_has([w1, w2]), {w1: True, w2: True})
        self.assertEqual(peer_client.batch_get([w1]), {w1: blob1})
        # 2 回目も常駐ホスト・接続を再利用して取得できる
        self.assertEqual(peer_client.batch_get([w2]), {w2: blob2})

    def test_dht_discovery_and_swarm_integration(self) -> None:
        blob = b"dht-discovered-payload-" * 32
        wid = hashlib.sha256(blob).hexdigest()
        store = {wid: blob}

        server_mgr = Libp2pHostManager(
            store=store,
            listen=["/ip4/127.0.0.1/udp/0/quic-v1"],
            enable_dht=True,
            dht_mode="server",
        ).start()
        self.addCleanup(server_mgr.close)

        client_mgr = Libp2pHostManager(
            listen=["/ip4/127.0.0.1/udp/0/quic-v1"],
            enable_dht=True,
            dht_mode="server",
            bootstrap_peers=[server_mgr.addrs[0]],
        ).start()
        self.addCleanup(client_mgr.close)

        domain_key = "example.com:test-dht"
        self.assertTrue(server_mgr.provide_domain(domain_key, timeout=5.0))
        provs = client_mgr.find_domain_providers(domain_key, timeout=5.0)
        self.assertTrue(any(p["peer_id"] == server_mgr.peer_id for p in provs))

        from dfs.l3_ost_adapter import make_ost_client

        swarm = SwarmOSTClient([make_ost_client("http://127.0.0.1:1")])
        added = swarm.discover_from_p2p(
            client_mgr,
            domain_key=domain_key,
            timeout=3.0,
        )
        self.assertEqual(added, [f"libp2p://{server_mgr.peer_id}"])
        self.assertEqual(swarm.batch_get([wid]), {wid: blob})

    def test_bootstrap_from_peers_and_circuit_addrs(self) -> None:
        server_mgr = Libp2pHostManager(
            listen=["/ip4/127.0.0.1/udp/0/quic-v1"],
            enable_dht=True,
            dht_mode="server",
            enable_relay=True,
            relay_hop=True,
        ).start()
        self.addCleanup(server_mgr.close)

        client_mgr = Libp2pHostManager(
            listen=["/ip4/127.0.0.1/udp/0/quic-v1"],
            enable_dht=True,
            dht_mode="client",
            enable_relay=True,
            relay_hop=False,
        ).start()
        self.addCleanup(client_mgr.close)

        connected = client_mgr.bootstrap_from_peers(
            [
                {
                    "peer_id": server_mgr.peer_id,
                    "role": "hub",
                    "addrs": server_mgr.addrs,
                }
            ],
            timeout=3.0,
        )
        self.assertEqual(connected, 1)

        effective = client_mgr.effective_addrs()
        self.assertTrue(
            any(a.endswith(f"/p2p-circuit/p2p/{client_mgr.peer_id}") for a in effective)
        )
        # 非ループバックのリレーアドレスがある場合はそちらを優先し、多重 /p2p-circuit は作らない
        mixed = client_mgr.build_circuit_addrs(
            [
                server_mgr.addrs[0],
                f"/ip4/203.0.113.10/udp/4001/quic-v1/p2p/{server_mgr.peer_id}",
                f"/ip4/203.0.113.10/udp/4001/quic-v1/p2p/{server_mgr.peer_id}/p2p-circuit/p2p/QmDummy",
            ]
        )
        self.assertEqual(
            mixed,
            [
                f"/ip4/203.0.113.10/udp/4001/quic-v1/p2p/{server_mgr.peer_id}/p2p-circuit/p2p/{client_mgr.peer_id}"
            ],
        )

        domain_key = "example.com:bootstrapped"
        self.assertTrue(client_mgr.provide_domain(domain_key, timeout=5.0))
        provs = server_mgr.find_domain_providers(domain_key, timeout=5.0)
        self.assertTrue(any(p["peer_id"] == client_mgr.peer_id for p in provs))

    def test_circuit_relay_v2_chunk_fetch_through_hop(self) -> None:
        blob = b"relayed-firewall-traversal-chunk-" * 64
        wid = hashlib.sha256(blob).hexdigest()

        relay_mgr = Libp2pHostManager(
            listen=["/ip4/127.0.0.1/tcp/0"],
            enable_dht=False,
            enable_relay=True,
            relay_hop=True,
            enable_dcutr=True,
        ).start()
        self.addCleanup(relay_mgr.close)

        target_mgr = Libp2pHostManager(
            store={wid: blob},
            listen=["/ip4/127.0.0.1/tcp/0"],
            enable_dht=False,
            enable_relay=True,
            relay_hop=False,
            enable_dcutr=True,
        ).start()
        self.addCleanup(target_mgr.close)

        dialer_mgr = Libp2pHostManager(
            listen=["/ip4/127.0.0.1/tcp/0"],
            enable_dht=False,
            enable_relay=True,
            relay_hop=False,
            enable_dcutr=True,
        ).start()
        self.addCleanup(dialer_mgr.close)

        # target が relay に接続して Reservation を張る
        connected = target_mgr.bootstrap_from_peers(
            [{"peer_id": relay_mgr.peer_id, "role": "hub", "addrs": relay_mgr.addrs}],
            timeout=3.0,
        )
        self.assertEqual(connected, 1)

        circuit_addrs = target_mgr.build_circuit_addrs(relay_mgr.addrs)
        self.assertEqual(len(circuit_addrs), 1)

        # dialer には直接アドレスを渡さず /p2p-circuit のみを渡してチャンク取得する
        peer_client = Libp2pPeerClient(
            dialer_mgr,
            target_mgr.peer_id,
            addrs=circuit_addrs,
        )
        self.assertEqual(peer_client.batch_has([wid]), {wid: True})
        self.assertEqual(peer_client.batch_get([wid]), {wid: blob})

    def test_provide_domain_background_returns_immediately(self) -> None:
        import time

        server_mgr = Libp2pHostManager(
            listen=["/ip4/127.0.0.1/udp/0/quic-v1"],
            enable_dht=True,
            dht_mode="server",
        ).start()
        self.addCleanup(server_mgr.close)

        client_mgr = Libp2pHostManager(
            listen=["/ip4/127.0.0.1/udp/0/quic-v1"],
            enable_dht=True,
            dht_mode="client",
            bootstrap_peers=[server_mgr.addrs[0]],
        ).start()
        self.addCleanup(client_mgr.close)

        domain_key = "example.com:bg-provide"
        t0 = time.monotonic()
        ok = client_mgr.provide_domain(domain_key, timeout=5.0, background=True)
        elapsed = time.monotonic() - t0
        self.assertTrue(ok)
        self.assertLess(elapsed, 0.5)

        found = False
        for _ in range(20):
            provs = server_mgr.find_domain_providers(domain_key, timeout=1.0)
            if any(p["peer_id"] == client_mgr.peer_id for p in provs):
                found = True
                break
            time.sleep(0.1)
        self.assertTrue(found)

    def test_list_chunks_and_sync_from_peer(self) -> None:
        from dfs.libp2p_chunk import Libp2pHostManager, Libp2pPeerClient, sync_from_peer

        blobs = [f"chunk-{i}".encode("utf-8") for i in range(5)]
        src_store = {hashlib.sha256(b).hexdigest(): b for b in blobs}
        dst_store: dict[str, bytes] = {}

        src_mgr = Libp2pHostManager(
            store=src_store,
            listen=["/ip4/127.0.0.1/udp/0/quic-v1"],
            enable_dht=False,
        ).start()
        self.addCleanup(src_mgr.close)

        dst_mgr = Libp2pHostManager(
            store=dst_store,
            listen=["/ip4/127.0.0.1/udp/0/quic-v1"],
            enable_dht=False,
        ).start()
        self.addCleanup(dst_mgr.close)

        client = Libp2pPeerClient(dst_mgr, src_mgr.peer_id, src_mgr.addrs, owns_manager=False)
        total, page1 = client.list_chunks(offset=0, limit=2)
        self.assertEqual(total, 5)
        self.assertEqual(len(page1), 2)

        stats1 = sync_from_peer(dst_mgr, dst_store, src_mgr.peer_id, src_mgr.addrs, batch_size=2)
        self.assertEqual(stats1["remote_total"], 5)
        self.assertEqual(stats1["fetched"], 5)
        self.assertEqual(dst_store, src_store)

        # 2回目は既存チャンクをスキップすること
        stats2 = sync_from_peer(dst_mgr, dst_store, src_mgr.peer_id, src_mgr.addrs, batch_size=2)
        self.assertEqual(stats2["missing"], 0)
        self.assertEqual(stats2["fetched"], 0)

    def test_relay_hub_sync_id_and_svc_subscribe_flags(self) -> None:
        from dfs.relay import RelayHub
        from dfs.svc import build_parser

        hub = RelayHub()
        hub.allow_peer_id(
            "12D3KooWTestPeer",
            node_id="mac",
            role="primary",
            addrs=["/ip4/127.0.0.1/tcp/1234/p2p/12D3KooWTestPeer"],
            sync_id="HxsWZRX7hQIUmdBA",
            sub_path="/example.com/HxsWZRX7hQIUmdBA",
        )
        info = hub.get_allowed_peers()
        self.assertEqual(info["peers"][0]["sync_id"], "HxsWZRX7hQIUmdBA")
        self.assertEqual(info["peers"][0]["sub_path"], "/example.com/HxsWZRX7hQIUmdBA")

        ns = build_parser().parse_args([
            "start", "--join", "https://l2.example.com",
            "--subscribe", "ID1", "--subscribe", "ID2",
        ])
        self.assertEqual(ns.subscribe, ["ID1", "ID2"])

    def test_ipv6_listen_and_relay_parallel_race(self) -> None:
        import time
        from unittest.mock import patch
        from dfs.libp2p_chunk import (
            Libp2pHostManager,
            _is_private_multiaddr,
            _supports_ipv6_bind,
        )

        self.assertFalse(_is_private_multiaddr("/ip4/133.125.58.250/tcp/35355/p2p/abc"))
        self.assertFalse(_is_private_multiaddr("/ip6/2404:7a80:f61:2800::1/tcp/35355/p2p/abc"))
        self.assertTrue(_is_private_multiaddr("/ip4/172.17.0.1/tcp/35355/p2p/abc"))
        self.assertTrue(_is_private_multiaddr("/ip4/192.168.0.3/tcp/35355/p2p/abc"))

        mgr = Libp2pHostManager(enable_dht=False)
        if _supports_ipv6_bind():
            self.assertTrue(any(a.startswith("/ip6/::/") for a in mgr.listen))

        mgr.addrs = [
            "/ip4/0.0.0.0/tcp/4001/p2p/12D3KooWTest",
            "/ip6/::/tcp/4002/p2p/12D3KooWTest",
        ]
        with patch("dfs.libp2p_chunk._local_non_loopback_ipv4s", return_value=["192.168.0.10"]), \
             patch("dfs.libp2p_chunk._local_non_loopback_ipv6s", return_value=["2404:7a80:f61:2800::1"]):
            eff = mgr.effective_addrs()
        self.assertIn("/ip4/192.168.0.10/tcp/4001/p2p/12D3KooWTest", eff)
        self.assertIn("/ip6/2404:7a80:f61:2800::1/tcp/4002/p2p/12D3KooWTest", eff)

        # リレー並列レース: 到達不能アドレスが混ざっていても即座に生きるリレーへ繋がること
        src_mgr = Libp2pHostManager(
            store={"aa" * 32: b"hello"},
            listen=["/ip4/127.0.0.1/tcp/0"],
            enable_dht=False,
        ).start()
        self.addCleanup(src_mgr.close)
        dst_mgr = Libp2pHostManager(
            listen=["/ip4/127.0.0.1/tcp/0"],
            enable_dht=False,
        ).start()
        self.addCleanup(dst_mgr.close)

        relay_mgr = Libp2pHostManager(
            listen=["/ip4/127.0.0.1/tcp/0"],
            enable_dht=False,
            enable_relay=True,
            relay_hop=True,
        ).start()
        self.addCleanup(relay_mgr.close)

        src_mgr.bootstrap_from_peers([{"peer_id": relay_mgr.peer_id, "role": "hub", "addrs": relay_mgr.addrs}], timeout=2.0)
        dead_relay_pid = "12D3KooWDeadRelayPeer11111111111111111111111111111111"
        bad_relay = f"/ip4/192.0.2.1/tcp/39999/p2p/{dead_relay_pid}/p2p-circuit/p2p/{src_mgr.peer_id}"
        good_relay = f"{relay_mgr.addrs[0]}/p2p-circuit/p2p/{src_mgr.peer_id}"
        t0 = time.monotonic()
        pid = dst_mgr._run_sync(
            dst_mgr._ensure_connected_async,
            src_mgr.peer_id,
            [],
            [bad_relay, good_relay],
            4.0,
        )
        elapsed = time.monotonic() - t0
        self.assertEqual(str(pid), src_mgr.peer_id)
        self.assertLess(elapsed, 3.5)

    def test_sync_from_peers_distributes_across_multiple_seeds(self) -> None:
        from dfs.libp2p_chunk import Libp2pHostManager, sync_from_peers

        blobs = [f"multi-seed-chunk-{i}".encode("utf-8") for i in range(12)]
        expected = {hashlib.sha256(b).hexdigest(): b for b in blobs}
        seed1_store = dict(expected)
        seed2_store = dict(expected)
        dst_store: dict[str, bytes] = {}

        s1_mgr = Libp2pHostManager(
            store=seed1_store,
            listen=["/ip4/127.0.0.1/udp/0/quic-v1"],
            enable_dht=False,
        ).start()
        s2_mgr = Libp2pHostManager(
            store=seed2_store,
            listen=["/ip4/127.0.0.1/udp/0/quic-v1"],
            enable_dht=False,
        ).start()
        dst_mgr = Libp2pHostManager(
            store=dst_store,
            listen=["/ip4/127.0.0.1/udp/0/quic-v1"],
            enable_dht=False,
        ).start()
        self.addCleanup(s1_mgr.close)
        self.addCleanup(s2_mgr.close)
        self.addCleanup(dst_mgr.close)

        stats = sync_from_peers(
            dst_mgr,
            dst_store,
            [(s1_mgr.peer_id, s1_mgr.addrs), (s2_mgr.peer_id, s2_mgr.addrs)],
            batch_size=2,
        )
        self.assertEqual(stats["remote_total"], 12)
        self.assertEqual(stats["fetched"], 12)
        self.assertEqual(dst_store, expected)
        per_peer = stats["per_peer"]
        self.assertEqual(sum(per_peer.values()), 12)
        self.assertEqual(len(per_peer), 2)

    def test_sync_from_peers_endgame_races_slow_peer(self) -> None:
        import time
        from unittest.mock import patch
        from dfs.libp2p_chunk import Libp2pHostManager, Libp2pPeerClient, sync_from_peers

        blobs = [f"endgame-chunk-{i}".encode("utf-8") for i in range(6)]
        expected = {hashlib.sha256(b).hexdigest(): b for b in blobs}
        s1_store = dict(expected)
        s2_store = dict(expected)
        dst_store: dict[str, bytes] = {}

        s1_mgr = Libp2pHostManager(
            store=s1_store,
            listen=["/ip4/127.0.0.1/udp/0/quic-v1"],
            enable_dht=False,
        ).start()
        s2_mgr = Libp2pHostManager(
            store=s2_store,
            listen=["/ip4/127.0.0.1/udp/0/quic-v1"],
            enable_dht=False,
        ).start()
        dst_mgr = Libp2pHostManager(
            store=dst_store,
            listen=["/ip4/127.0.0.1/udp/0/quic-v1"],
            enable_dht=False,
        ).start()
        self.addCleanup(s1_mgr.close)
        self.addCleanup(s2_mgr.close)
        self.addCleanup(dst_mgr.close)

        orig_batch_get = Libp2pPeerClient.batch_get

        def slow_on_s2(client_self, wire_ids):
            if client_self.peer_id == s2_mgr.peer_id:
                time.sleep(0.35)
            return orig_batch_get(client_self, wire_ids)

        with patch.object(Libp2pPeerClient, "batch_get", slow_on_s2):
            t0 = time.monotonic()
            stats = sync_from_peers(
                dst_mgr,
                dst_store,
                [(s1_mgr.peer_id, s1_mgr.addrs), (s2_mgr.peer_id, s2_mgr.addrs)],
                batch_size=2,
            )
            elapsed = time.monotonic() - t0

        self.assertEqual(stats["fetched"], 6)
        self.assertEqual(dst_store, expected)
        self.assertEqual(sum(stats["per_peer"].values()), 6)
        self.assertGreater(stats["per_peer"].get(s1_mgr.peer_id, 0), 0)
        self.assertLess(elapsed, 2.0)

    def test_sync_from_peers_pipelines_multiple_streams_per_peer(self) -> None:
        from dfs.libp2p_chunk import Libp2pHostManager, sync_from_peers

        blobs = [f"pipe-chunk-{i}".encode("utf-8") for i in range(10)]
        expected = {hashlib.sha256(b).hexdigest(): b for b in blobs}
        s_store = dict(expected)
        dst_store: dict[str, bytes] = {}
        s_mgr = Libp2pHostManager(
            store=s_store,
            listen=["/ip4/127.0.0.1/udp/0/quic-v1"],
            enable_dht=False,
        ).start()
        dst_mgr = Libp2pHostManager(
            store=dst_store,
            listen=["/ip4/127.0.0.1/udp/0/quic-v1"],
            enable_dht=False,
        ).start()
        self.addCleanup(s_mgr.close)
        self.addCleanup(dst_mgr.close)

        stats = sync_from_peers(
            dst_mgr,
            dst_store,
            [(s_mgr.peer_id, s_mgr.addrs)],
            batch_size=2,
            streams_per_peer=3,
        )
        self.assertEqual(stats["fetched"], 10)
        self.assertEqual(dst_store, expected)

    def test_sync_from_peers_dynamic_peer_discovery_mid_sync(self) -> None:
        from unittest.mock import patch
        from dfs.libp2p_chunk import Libp2pHostManager, Libp2pPeerClient, sync_from_peers

        blobs = [f"dyn-peer-{i}".encode("utf-8") for i in range(8)]
        expected = {hashlib.sha256(b).hexdigest(): b for b in blobs}
        s1_store = dict(expected)
        s2_store = dict(expected)
        dst_store: dict[str, bytes] = {}

        s1_mgr = Libp2pHostManager(
            store=s1_store,
            listen=["/ip4/127.0.0.1/udp/0/quic-v1"],
            enable_dht=False,
        ).start()
        s2_mgr = Libp2pHostManager(
            store=s2_store,
            listen=["/ip4/127.0.0.1/udp/0/quic-v1"],
            enable_dht=False,
        ).start()
        dst_mgr = Libp2pHostManager(
            store=dst_store,
            listen=["/ip4/127.0.0.1/udp/0/quic-v1"],
            enable_dht=False,
        ).start()
        self.addCleanup(s1_mgr.close)
        self.addCleanup(s2_mgr.close)
        self.addCleanup(dst_mgr.close)

        calls = {"n": 0}
        orig_batch_get = Libp2pPeerClient.batch_get

        def slow_s1(client_self, wire_ids):
            if client_self.peer_id == s1_mgr.peer_id:
                time.sleep(0.15)
            return orig_batch_get(client_self, wire_ids)

        def provider():
            calls["n"] += 1
            return [(s2_mgr.peer_id, s2_mgr.addrs)]

        import time
        with patch.object(Libp2pPeerClient, "batch_get", slow_s1):
            stats = sync_from_peers(
                dst_mgr,
                dst_store,
                [(s1_mgr.peer_id, s1_mgr.addrs)],
                batch_size=1,
                streams_per_peer=1,
                peer_provider=provider,
                refresh_interval=0.2,
            )

        self.assertEqual(stats["fetched"], 8)
        self.assertEqual(dst_store, expected)
        self.assertIn(s2_mgr.peer_id, stats["per_peer"])

    def test_sync_from_peers_rarest_first_ordering(self) -> None:
        import threading
        import time
        from unittest.mock import patch
        from dfs.libp2p_chunk import Libp2pHostManager, Libp2pPeerClient, sync_from_peers

        blobs = [f"rare-chunk-{i}".encode("utf-8") for i in range(6)]
        wids = [hashlib.sha256(b).hexdigest() for b in blobs]
        expected = dict(zip(wids, blobs))
        # s1 has all 6, s2 has only the last 4 -> first 2 are rarest (count=1)
        s1_store = dict(expected)
        s2_store = {wids[i]: blobs[i] for i in range(2, 6)}
        dst_store: dict[str, bytes] = {}

        s1_mgr = Libp2pHostManager(
            store=s1_store, listen=["/ip4/127.0.0.1/udp/0/quic-v1"], enable_dht=False
        ).start()
        s2_mgr = Libp2pHostManager(
            store=s2_store, listen=["/ip4/127.0.0.1/udp/0/quic-v1"], enable_dht=False
        ).start()
        dst_mgr = Libp2pHostManager(
            store=dst_store, listen=["/ip4/127.0.0.1/udp/0/quic-v1"], enable_dht=False
        ).start()
        self.addCleanup(s1_mgr.close)
        self.addCleanup(s2_mgr.close)
        self.addCleanup(dst_mgr.close)

        s1_first_batch: list[str] = []
        orig_batch_get = Libp2pPeerClient.batch_get
        orig_list_chunks = Libp2pPeerClient.list_chunks
        probe_barrier = threading.Barrier(2, timeout=5.0)

        def synced_list_chunks(client_self, offset=0, limit=4096):
            res = orig_list_chunks(client_self, offset=offset, limit=limit)
            probe_barrier.wait()
            if client_self.peer_id == s1_mgr.peer_id:
                time.sleep(0.02)
            return res

        def capture_s1(client_self, wire_ids):
            if client_self.peer_id == s1_mgr.peer_id and not s1_first_batch:
                s1_first_batch.extend(wire_ids)
            return orig_batch_get(client_self, wire_ids)

        with patch.object(Libp2pPeerClient, "list_chunks", synced_list_chunks), patch.object(
            Libp2pPeerClient, "batch_get", capture_s1
        ):
            stats = sync_from_peers(
                dst_mgr,
                dst_store,
                [(s1_mgr.peer_id, s1_mgr.addrs), (s2_mgr.peer_id, s2_mgr.addrs)],
                batch_size=2,
                streams_per_peer=1,
            )

        self.assertEqual(stats["fetched"], 6)
        self.assertEqual(set(s1_first_batch), {wids[0], wids[1]})

    def test_adapt_batch_size_adjusts_for_rtt_and_failures(self) -> None:
        from dfs.libp2p_chunk import _adapt_batch_size

        self.assertEqual(_adapt_batch_size(4, 0.1), 8)
        self.assertEqual(_adapt_batch_size(8, 0.1), 16)
        self.assertEqual(_adapt_batch_size(16, 0.1), 16)
        self.assertEqual(_adapt_batch_size(8, 1.0), 8)
        self.assertEqual(_adapt_batch_size(8, 3.0), 4)
        self.assertEqual(_adapt_batch_size(4, 0.1, failed=True), 2)
        self.assertEqual(_adapt_batch_size(1, 3.0, failed=True), 1)

    def test_sync_from_peers_starts_immediately_without_waiting_for_slow_probe(self) -> None:
        import time
        from unittest.mock import patch
        from dfs.libp2p_chunk import Libp2pHostManager, Libp2pPeerClient, sync_from_peers

        blobs = [f"fast-start-{i}".encode("utf-8") for i in range(4)]
        expected = {hashlib.sha256(b).hexdigest(): b for b in blobs}
        s1_store = dict(expected)
        s2_store = dict(expected)
        dst_store: dict[str, bytes] = {}

        s1_mgr = Libp2pHostManager(
            store=s1_store, listen=["/ip4/127.0.0.1/udp/0/quic-v1"], enable_dht=False
        ).start()
        s2_mgr = Libp2pHostManager(
            store=s2_store, listen=["/ip4/127.0.0.1/udp/0/quic-v1"], enable_dht=False
        ).start()
        dst_mgr = Libp2pHostManager(
            store=dst_store, listen=["/ip4/127.0.0.1/udp/0/quic-v1"], enable_dht=False
        ).start()
        self.addCleanup(s1_mgr.close)
        self.addCleanup(s2_mgr.close)
        self.addCleanup(dst_mgr.close)

        orig_list = Libp2pPeerClient.list_chunks
        s1_done_at = {"t": 0.0}
        orig_get = Libp2pPeerClient.batch_get

        def slow_probe_s2(client_self, offset=0, limit=4096):
            if client_self.peer_id == s2_mgr.peer_id:
                time.sleep(1.2)
            return orig_list(client_self, offset=offset, limit=limit)

        def track_get(client_self, wire_ids):
            res = orig_get(client_self, wire_ids)
            if client_self.peer_id == s1_mgr.peer_id and s1_done_at["t"] == 0.0:
                s1_done_at["t"] = time.monotonic()
            return res

        t0 = time.monotonic()
        with patch.object(Libp2pPeerClient, "list_chunks", slow_probe_s2), patch.object(
            Libp2pPeerClient, "batch_get", track_get
        ):
            stats = sync_from_peers(
                dst_mgr,
                dst_store,
                [(s1_mgr.peer_id, s1_mgr.addrs), (s2_mgr.peer_id, s2_mgr.addrs)],
                batch_size=2,
            )
        self.assertEqual(stats["fetched"], 4)
        self.assertLess(s1_done_at["t"] - t0, 0.8)

    def test_upnp_port_mapper_soap_and_cleanup(self) -> None:
        from unittest.mock import patch
        from dfs import nat

        soap_calls: list[str] = []

        def fake_soap(ctrl_url, stype, action, body_xml, timeout=2.0):
            soap_calls.append(action)
            if action == "AddPortMapping":
                return "<AddPortMappingResponse/>"
            if action == "GetExternalIPAddress":
                return "<NewExternalIPAddress>1.2.3.4</NewExternalIPAddress>"
            if action == "DeletePortMapping":
                return "<DeletePortMappingResponse/>"
            return None

        with patch.object(nat, "_ssdp_discover_igd", return_value="http://192.168.0.1:5000/rootDesc.xml"), patch.object(
            nat,
            "_find_wan_control_url",
            return_value=("http://192.168.0.1:5000/ctl/IPConn", "urn:schemas-upnp-org:service:WANIPConnection:1"),
        ), patch.object(nat, "_local_ip_for_target", return_value="192.168.0.10"), patch.object(
            nat, "_upnp_soap_call", side_effect=fake_soap
        ):
            mapper = nat.UPnPPortMapper(timeout=1.0)
            res = mapper.map_port(41337, protocol="UDP")
            self.assertEqual(res, ("1.2.3.4", 41337))
            mapper.close()

        self.assertEqual(soap_calls, ["AddPortMapping", "GetExternalIPAddress", "DeletePortMapping"])

    def test_connection_summary_reports_direct_and_ipv6(self) -> None:
        from dfs.libp2p_chunk import Libp2pHostManager, sync_from_peers

        s_store = {hashlib.sha256(b"dcutr-vis").hexdigest(): b"dcutr-vis"}
        d_store: dict[str, bytes] = {}
        s_mgr = Libp2pHostManager(
            store=s_store, listen=["/ip4/127.0.0.1/udp/0/quic-v1"], enable_dht=False
        ).start()
        d_mgr = Libp2pHostManager(
            store=d_store, listen=["/ip4/127.0.0.1/udp/0/quic-v1"], enable_dht=False
        ).start()
        self.addCleanup(s_mgr.close)
        self.addCleanup(d_mgr.close)

        sync_from_peers(d_mgr, d_store, [(s_mgr.peer_id, s_mgr.addrs)])
        summary = d_mgr.connection_summary()
        self.assertGreaterEqual(summary["total"], 1)
        self.assertGreaterEqual(summary["direct"], 1)
        self.assertEqual(summary["relayed"], 0)

    def test_rank_and_prune_dead_multiaddrs(self) -> None:
        from dfs.libp2p_chunk import Libp2pHostManager

        mgr = Libp2pHostManager(store={}, enable_dht=False)
        dead = "/ip4/192.0.2.1/tcp/4001/p2p/12D3KooWDead"
        good = "/ip4/127.0.0.1/tcp/4001/p2p/12D3KooWGood"
        for _ in range(3):
            mgr._record_addr_outcome(dead, ok=False)
        ranked = mgr._rank_and_prune_addrs([dead, good], cooldown_s=60.0, max_fails=3)
        self.assertEqual(ranked, [good])
        mgr._record_addr_outcome(dead, ok=True)
        ranked2 = mgr._rank_and_prune_addrs([dead, good], cooldown_s=60.0, max_fails=3)
        self.assertEqual(ranked2, [dead, good])

    def test_sync_from_peers_probe_cache_skips_unchanged_list_chunks(self) -> None:
        from unittest.mock import patch
        from dfs.libp2p_chunk import Libp2pHostManager, Libp2pPeerClient, sync_from_peers

        blobs = [f"cache-chunk-{i}".encode("utf-8") for i in range(4)]
        expected = {hashlib.sha256(b).hexdigest(): b for b in blobs}
        s_store = dict(expected)
        d_store: dict[str, bytes] = {}
        s_mgr = Libp2pHostManager(
            store=s_store, listen=["/ip4/127.0.0.1/udp/0/quic-v1"], enable_dht=False
        ).start()
        d_mgr = Libp2pHostManager(
            store=d_store, listen=["/ip4/127.0.0.1/udp/0/quic-v1"], enable_dht=False
        ).start()
        self.addCleanup(s_mgr.close)
        self.addCleanup(d_mgr.close)

        probe_cache: dict = {}
        stats1 = sync_from_peers(
            d_mgr, d_store, [(s_mgr.peer_id, s_mgr.addrs)], probe_cache=probe_cache
        )
        self.assertEqual(stats1["fetched"], 4)
        self.assertIn(s_mgr.peer_id, probe_cache)

        limits_seen: list[int] = []
        orig_list = Libp2pPeerClient.list_chunks

        def spy_list(client_self, offset=0, limit=4096):
            limits_seen.append(limit)
            return orig_list(client_self, offset=offset, limit=limit)

        with patch.object(Libp2pPeerClient, "list_chunks", spy_list):
            stats2 = sync_from_peers(
                d_mgr, d_store, [(s_mgr.peer_id, s_mgr.addrs)], probe_cache=probe_cache
            )
        self.assertEqual(stats2["fetched"], 0)
        self.assertEqual(limits_seen, [1])

    def test_memory_budget_caps_scale_with_available_ram(self) -> None:
        from unittest.mock import patch
        from dfs import libp2p_chunk

        with patch.object(libp2p_chunk, "_get_available_memory_bytes", return_value=100 * 1024 * 1024):
            self.assertEqual(libp2p_chunk._memory_budget_caps(), (1, 2, 2))
        with patch.object(libp2p_chunk, "_get_available_memory_bytes", return_value=200 * 1024 * 1024):
            self.assertEqual(libp2p_chunk._memory_budget_caps(), (1, 4, 4))
        with patch.object(libp2p_chunk, "_get_available_memory_bytes", return_value=400 * 1024 * 1024):
            self.assertEqual(libp2p_chunk._memory_budget_caps(), (2, 8, 6))
        with patch.object(libp2p_chunk, "_get_available_memory_bytes", return_value=2 * 1024**3):
            self.assertEqual(libp2p_chunk._memory_budget_caps(), (4, 16, 8))


if __name__ == "__main__":
    unittest.main(verbosity=2)
