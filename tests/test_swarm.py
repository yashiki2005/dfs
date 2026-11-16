#!/usr/bin/env python3
"""BitTorrent 式マルチピア並列取得 + Relay フォールバック (SwarmOSTClient) の試験。"""

from __future__ import annotations

import subprocess
from pathlib import Path

from dfs.crypto import sha256_hex
from dfs.l3_ost_adapter import ChunkStoreServer, HttpOSTClient, OSTClient, SwarmOSTClient


def _start_ost(tmp_path: Path, name: str) -> ChunkStoreServer:
    d = tmp_path / name
    d.mkdir(parents=True, exist_ok=True)
    cert = d / "cert.pem"
    key = d / "key.pem"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(key), "-out", str(cert),
            "-days", "1", "-subj", "/CN=127.0.0.1",
        ],
        capture_output=True,
        check=True,
    )
    return ChunkStoreServer(cert, key, host="127.0.0.1", port=0)


def test_swarm_distributes_across_healthy_peers(tmp_path: Path) -> None:
    s1 = _start_ost(tmp_path, "s1")
    s2 = _start_ost(tmp_path, "s2")
    try:
        blobs = [f"chunk-{i}".encode("utf-8") * 50 for i in range(6)]
        wids = [sha256_hex(b) for b in blobs]
        for wid, blob in zip(wids, blobs):
            s1.store[wid] = blob
            s2.store[wid] = blob

        c1 = OSTClient("127.0.0.1", s1.port)
        c2 = OSTClient("127.0.0.1", s2.port)
        relay_dummy = HttpOSTClient("http://127.0.0.1:1/relay/mac1")

        swarm = SwarmOSTClient([c1, c2, relay_dummy])
        with swarm.session():
            got = swarm.batch_get(wids)

        assert got == dict(zip(wids, blobs))
        # 全生存ピアで並列取得し、負荷を分散する
        assert c1.round_trips >= 1 and c2.round_trips >= 1
        assert c1.get_count > 0 and c2.get_count > 0
        assert c1.get_count + c2.get_count == 6
        # 直接ピアで完結したのでリレー層には一切触らない
        assert relay_dummy.round_trips == 0

        # 2 回目以降のバッチでも両ピアへ比例配分される
        c1.get_count = 0
        c2.get_count = 0
        c1.round_trips = 0
        c2.round_trips = 0
        blobs2 = [f"slow-{i}".encode("utf-8") * 50 for i in range(12)]
        wids2 = [sha256_hex(b) for b in blobs2]
        for wid, blob in zip(wids2, blobs2):
            s1.store[wid] = blob
            s2.store[wid] = blob
        with swarm.session():
            got2 = swarm.batch_get(wids2)
        assert got2 == dict(zip(wids2, blobs2))
        assert c1.round_trips >= 1 and c2.round_trips >= 1
        assert c1.get_count > 0 and c2.get_count > 0
        assert c1.get_count + c2.get_count == 12
        assert relay_dummy.round_trips == 0
    finally:
        s1.close()
        s2.close()


def test_swarm_stitches_partial_peers_and_falls_back_to_relay(tmp_path: Path) -> None:
    s1 = _start_ost(tmp_path, "p1")
    s2 = _start_ost(tmp_path, "p2")
    s_relay = _start_ost(tmp_path, "prelay")
    try:
        blobs = [f"part-{i}".encode("utf-8") * 20 for i in range(4)]
        wids = [sha256_hex(b) for b in blobs]
        s1.store[wids[0]] = blobs[0]
        s1.store[wids[1]] = blobs[1]
        s2.store[wids[1]] = blobs[1]
        s2.store[wids[2]] = blobs[2]
        # wids[3] だけはリレー先（第3層）にしかない
        s_relay.store[wids[3]] = blobs[3]

        c1 = OSTClient("127.0.0.1", s1.port)
        c2 = OSTClient("127.0.0.1", s2.port)

        class _RelayTagClient(OSTClient):
            base_url = "http://127.0.0.1/relay/mac1"

        c_relay = _RelayTagClient("127.0.0.1", s_relay.port)
        swarm = SwarmOSTClient([c1, c2, c_relay])
        got = swarm.batch_get(wids)

        assert got == dict(zip(wids, blobs))
        # wids[3] だけをリレー層から補完した
        assert c_relay.get_count == 1
    finally:
        s1.close()
        s2.close()
        s_relay.close()


def test_adaptive_transport_probing_and_cache(tmp_path: Path) -> None:
    from dfs.cli import BoundedThreadingHTTPServer, PersistentRegistryState, make_registry_http_handler
    import subprocess as sp
    import threading

    s_direct = _start_ost(tmp_path, "adapt_direct")
    root_key = tmp_path / "root"
    sp.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", str(root_key)], check=True, capture_output=True)
    pub_text = Path(f"{root_key}.pub").read_text(encoding="utf-8").strip()
    pstate = PersistentRegistryState(tmp_path / "state", "/example.com", pub_text)
    httpd = BoundedThreadingHTTPServer(("127.0.0.1", 0), make_registry_http_handler(pstate, s_direct))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        dead_tls = OSTClient("127.0.0.1", 1)
        ok_http = HttpOSTClient(f"http://127.0.0.1:{httpd.server_port}")
        relay_client = HttpOSTClient("http://127.0.0.1:1/relay/mac1")
        cache_path = tmp_path / "transport_cache.json"

        swarm = SwarmOSTClient([dead_tls, ok_http, relay_client], cache_file=cache_path)
        ordered = swarm.adapt_order()
        assert ordered[0] is ok_http
        assert cache_path.is_file()

        # キャッシュが効くため、2 つ目のインスタンスはプローブせずに即 ok_http を先頭にする
        swarm2 = SwarmOSTClient([dead_tls, ok_http, relay_client], cache_file=cache_path)
        ordered2 = swarm2.adapt_order()
        assert ordered2[0] is ok_http

        # 直接経路が全滅している場合はリレーが先頭に昇格する
        ok_relay = HttpOSTClient(f"http://127.0.0.1:{httpd.server_port}/relay/mac1")
        ok_relay.probe = lambda timeout=None: 0.002  # type: ignore[method-assign]
        swarm3 = SwarmOSTClient([dead_tls, ok_relay])
        ordered3 = swarm3.adapt_order()
        assert ordered3[0] is ok_relay
    finally:
        httpd.shutdown()
        httpd.server_close()
        s_direct.close()


def test_rarest_first_prioritizes_scarce_chunks(tmp_path: Path) -> None:
    s1 = _start_ost(tmp_path, "rf1")
    s2 = _start_ost(tmp_path, "rf2")
    try:
        common = [f"common-{i}".encode("utf-8") * 20 for i in range(6)]
        rare = [f"rare-{i}".encode("utf-8") * 20 for i in range(2)]
        common_ids = [sha256_hex(b) for b in common]
        rare_ids = [sha256_hex(b) for b in rare]
        for wid, blob in zip(common_ids, common):
            s1.store[wid] = blob
            s2.store[wid] = blob
        # rare は s2 のみ保有
        for wid, blob in zip(rare_ids, rare):
            s2.store[wid] = blob

        c1 = OSTClient("127.0.0.1", s1.port)
        c2 = OSTClient("127.0.0.1", s2.port)
        batches_seen: list[list[str]] = []
        orig_c2_get = c2.batch_get

        def spy_c2_get(wids):
            batches_seen.append(list(wids))
            return orig_c2_get(wids)

        c2.batch_get = spy_c2_get  # type: ignore[method-assign]
        swarm = SwarmOSTClient([c1, c2])
        swarm._slow_hosts = {swarm._client_uri(c1), swarm._client_uri(c2)}

        # common を先に並べても Phase A では rare が先頭にソートされる
        all_ids = common_ids + rare_ids
        with swarm.session():
            got = swarm.batch_get(all_ids)
        assert len(got) == len(all_ids)
        assert batches_seen
        # 帯域配分によって最初のバッチサイズは変わるため、全rareが同じ
        # バッチに入ることは要求しない。最初の取得が希少chunkを含めばよい。
        assert set(rare_ids) & set(batches_seen[0])
    finally:
        s1.close()
        s2.close()


def test_swarm_proportional_weights_use_measured_bps(tmp_path: Path) -> None:
    s1 = _start_ost(tmp_path, "pw1")
    s2 = _start_ost(tmp_path, "pw2")
    try:
        blobs = [f"prop-{i}".encode("utf-8") * 50 for i in range(10)]
        wids = [sha256_hex(b) for b in blobs]
        for wid, blob in zip(wids, blobs):
            s1.store[wid] = blob
            s2.store[wid] = blob

        c1 = OSTClient("127.0.0.1", s1.port)
        c2 = OSTClient("127.0.0.1", s2.port)
        swarm = SwarmOSTClient([c1, c2])
        # s1 を 4 倍高帯域として記録すると、初回バッチ要求サイズも s1 に多く配分される
        swarm._peer_bps[swarm._client_uri(c1)] = 40 * 1024 * 1024
        swarm._peer_bps[swarm._client_uri(c2)] = 10 * 1024 * 1024

        c1_batches: list[int] = []
        orig_c1 = c1.batch_get

        def spy_c1(w):
            c1_batches.append(len(w))
            return orig_c1(w)

        c1.batch_get = spy_c1  # type: ignore[method-assign]
        with swarm.session():
            got = swarm.batch_get(wids)
        assert got == dict(zip(wids, blobs))
        assert c1_batches and c1_batches[0] >= 7
        assert c1.get_count > c2.get_count > 0
    finally:
        s1.close()
        s2.close()
