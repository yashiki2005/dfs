#!/usr/bin/env python3
"""root dfssvc 経由のアウトバウンドリレー (RelayHub + RelayAgent) のエンドツーエンド試験。"""

from __future__ import annotations

import json
import subprocess
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import List

import pytest

from dfs.cli import (
    BoundedThreadingHTTPServer,
    PersistentRegistryState,
    RemoteRegistryClient,
    make_registry_http_handler,
)
from dfs.l1_delegation import create_delegation_envelope
from dfs.l3_ost_adapter import ChunkStoreServer
from dfs.l5_fs import DFSNode
from dfs.relay import RelayAgent, RelayHub


def _gen_ed25519(path: Path) -> tuple[Path, str]:
    subprocess.run(
        ["ssh-keygen", "-t", "ed25519", "-N", "", "-f", str(path)],
        capture_output=True,
        text=True,
        check=True,
    )
    return path, Path(f"{path}.pub").read_text(encoding="utf-8").strip()


def _start_server(tmp_path: Path, name: str, relay_hub: RelayHub | None = None):
    d = tmp_path / name
    d.mkdir(parents=True, exist_ok=True)
    _, pub = _gen_ed25519(d / "root")
    cert = d / "ost.crt"
    key = d / "ost.key"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(key), "-out", str(cert),
            "-days", "1", "-subj", "/CN=127.0.0.1",
        ],
        capture_output=True,
        check=True,
    )
    ost = ChunkStoreServer(cert, key, host="127.0.0.1", port=0)
    pstate = PersistentRegistryState(d / "state", "/example.com", pub)
    handler = make_registry_http_handler(pstate, ost, relay_hub=relay_hub)
    httpd = BoundedThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return ost, pstate, httpd


def _wait_node_connected(root_url: str, token: str, node_id: str) -> None:
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        req = urllib.request.Request(
            f"{root_url}/_relay/status",
            headers={"X-DFS-Relay-Token": token},
            method="GET",
        )
        try:
            with urllib.request.urlopen(req, timeout=2.0) as resp:
                import json

                data = json.loads(resp.read().decode("utf-8"))
                for row in data.get("nodes", []):
                    if row.get("node_id") == node_id and row.get("active_pullers", 0) >= 1:
                        return
        except Exception:
            pass
        time.sleep(0.05)
    raise AssertionError(f"Relay node {node_id!r} did not connect in time")


def test_relay_end_to_end_push_and_pull(tmp_path: Path) -> None:
    relay_token = "relay-secret-123"
    hub = RelayHub(token=relay_token)
    root_ost, _root_pstate, root_httpd = _start_server(tmp_path, "root_hub", relay_hub=hub)
    nat_ost, nat_pstate, nat_httpd = _start_server(tmp_path, "nat_mac", relay_hub=None)

    root_url = f"http://127.0.0.1:{root_httpd.server_port}"
    agent = RelayAgent(
        relay_url=root_url,
        node_id="mac1",
        local_port=nat_httpd.server_port,
        token=relay_token,
        workers=2,
        pull_timeout=5.0,
    )
    agent.start()
    try:
        _wait_node_connected(root_url, relay_token, "mac1")

        # L1 委譲とクライアントは root の /relay/mac1 だけを見る
        nat_root_priv = tmp_path / "nat_mac" / "root"
        nat_root_pub = Path(f"{nat_root_priv}.pub").read_text(encoding="utf-8").strip()
        writer_priv, writer_pub = _gen_ed25519(tmp_path / "writer")
        relay_endpoint = f"{root_url}/relay/mac1"
        reg_client = RemoteRegistryClient(relay_endpoint)

        now = int(time.time())
        del_env = create_delegation_envelope(
            parent_priv_key=nat_root_priv,
            parent="/example.com",
            path="/example.com/mac1",
            writer_pubkey=writer_pub,
            epoch=1,
            base_version=0,
            issued_at=now - 5,
            expires_at=now + 3600,
        )
        reg_client.register_delegation(del_env, now=now)

        writer_mount = tmp_path / "writer_mount"
        writer = DFSNode(
            name="mac1",
            sub_path="/example.com/mac1",
            mount_root=writer_mount,
            priv_key_path=writer_priv,
            pub_key_str=writer_pub,
            tree_secret="relay-tree-secret",
            registry=reg_client,  # type: ignore[arg-type]
            ost_host="127.0.0.1",
            ost_port=0,
            ost_endpoint=relay_endpoint,
            root_pubkey=nat_root_pub,
        )
        (writer.clayfs.work_tree / "hello.txt").write_text("through-relay\n", encoding="utf-8")
        writer.push(delegation_epoch=1, now=now)

        # 実データは NAT 裏の nat_ost にだけ保存され、root_ost には残らない
        assert len(nat_ost.store) > 0
        assert len(root_ost.store) == 0
        assert "/example.com/mac1" in nat_pstate.service.logs

        # 別クライアント (RunPod 想定) が /relay/mac1 経由で pull できる
        reader_mount = tmp_path / "reader_mount"
        reader = DFSNode(
            name="runpod",
            sub_path="/example.com/mac1",
            mount_root=reader_mount,
            priv_key_path="",
            pub_key_str="",
            tree_secret="relay-tree-secret",
            registry=reg_client,  # type: ignore[arg-type]
            ost_host="127.0.0.1",
            ost_port=0,
            ost_endpoint=relay_endpoint,
            root_pubkey=nat_root_pub,
        )
        reader.pull()
        assert (reader.clayfs.work_tree / "hello.txt").read_text(encoding="utf-8") == "through-relay\n"
    finally:
        DFSNode.close_all()
        agent.close()
        nat_httpd.shutdown()
        nat_httpd.server_close()
        nat_ost.close()
        root_httpd.shutdown()
        root_httpd.server_close()
        root_ost.close()


def test_relay_auth_and_offline_node(tmp_path: Path) -> None:
    hub = RelayHub(token="top-secret")
    root_ost, _root_pstate, root_httpd = _start_server(tmp_path, "root_auth", relay_hub=hub)
    try:
        root_url = f"http://127.0.0.1:{root_httpd.server_port}"
        bad_req = urllib.request.Request(
            f"{root_url}/_relay/status",
            headers={"X-DFS-Relay-Token": "wrong"},
            method="GET",
        )
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(bad_req, timeout=2.0)
        assert exc_info.value.code == 403

        offline_req = urllib.request.Request(
            f"{root_url}/relay/missing/v1/paths",
            data=b"{}",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as exc_off:
            urllib.request.urlopen(offline_req, timeout=2.0)
        assert exc_off.value.code == 503
    finally:
        root_httpd.shutdown()
        root_httpd.server_close()
        root_ost.close()


def test_direct_first_and_relay_fallback(tmp_path: Path) -> None:
    relay_token = "direct-first-token"
    hub = RelayHub(token=relay_token)
    forward_calls: list[str] = []
    orig_forward = hub.forward

    def counted_forward(node_id: str, method: str, sub_path: str, content_type: str, body: bytes, timeout: float = 35.0, **kwargs):
        forward_calls.append(sub_path)
        return orig_forward(node_id, method, sub_path, content_type, body, timeout=timeout, **kwargs)

    hub.forward = counted_forward  # type: ignore[method-assign]

    root_ost, _root_pstate, root_httpd = _start_server(tmp_path, "root_df", relay_hub=hub)
    nat_ost, _nat_pstate, nat_httpd = _start_server(tmp_path, "nat_df", relay_hub=None)
    root_url = f"http://127.0.0.1:{root_httpd.server_port}"
    direct_url = f"http://127.0.0.1:{nat_httpd.server_port}"
    relay_url = f"{root_url}/relay/mac1"

    agent = RelayAgent(
        relay_url=root_url,
        node_id="mac1",
        local_port=nat_httpd.server_port,
        token=relay_token,
        workers=2,
        pull_timeout=5.0,
    )
    agent.start()
    try:
        _wait_node_connected(root_url, relay_token, "mac1")
        nat_root_priv = tmp_path / "nat_df" / "root"
        nat_root_pub = Path(f"{nat_root_priv}.pub").read_text(encoding="utf-8").strip()
        writer_priv, writer_pub = _gen_ed25519(tmp_path / "writer_df")
        now = int(time.time())

        # 1) 直接到達できるときはリレーを一切通らない
        direct_reg = RemoteRegistryClient([direct_url, relay_url])
        del_env = create_delegation_envelope(
            parent_priv_key=nat_root_priv,
            parent="/example.com",
            path="/example.com/df",
            writer_pubkey=writer_pub,
            epoch=1,
            base_version=0,
            issued_at=now - 5,
            expires_at=now + 3600,
        )
        direct_reg.register_delegation(del_env, now=now)
        direct_writer = DFSNode(
            name="direct-w",
            sub_path="/example.com/df",
            mount_root=tmp_path / "dw",
            priv_key_path=writer_priv,
            pub_key_str=writer_pub,
            tree_secret="df-secret",
            registry=direct_reg,  # type: ignore[arg-type]
            ost_host="127.0.0.1",
            ost_port=nat_ost.port,
            ost_alternates=[relay_url],
            root_pubkey=nat_root_pub,
        )
        (direct_writer.clayfs.work_tree / "a.txt").write_text("direct-ok\n", encoding="utf-8")
        direct_writer.push(delegation_epoch=1, now=now)
        assert forward_calls == []

        # 2) 直接エンドポイントが死んでいるときは自動でリレーにフォールバックして push / pull できる
        dead_url = "http://127.0.0.1:1"
        fallback_reg = RemoteRegistryClient([dead_url, relay_url])
        fallback_node = DFSNode(
            name="fallback-rw",
            sub_path="/example.com/df",
            mount_root=tmp_path / "fw",
            priv_key_path=writer_priv,
            pub_key_str=writer_pub,
            tree_secret="df-secret",
            registry=fallback_reg,  # type: ignore[arg-type]
            ost_host="127.0.0.1",
            ost_port=1,
            ost_alternates=[relay_url],
            root_pubkey=nat_root_pub,
        )
        fallback_node.pull()
        assert (fallback_node.clayfs.work_tree / "a.txt").read_text(encoding="utf-8") == "direct-ok\n"
        (fallback_node.clayfs.work_tree / "b.txt").write_text("relay-ok\n", encoding="utf-8")
        fallback_node.push(delegation_epoch=1, now=now + 1)
        assert len(forward_calls) > 0
    finally:
        DFSNode.close_all()
        agent.close()
        nat_httpd.shutdown()
        nat_httpd.server_close()
        nat_ost.close()
        root_httpd.shutdown()
        root_httpd.server_close()
        root_ost.close()


def test_ice_stun_endpoint(tmp_path: Path) -> None:
    hub = RelayHub()
    ost, _pstate, httpd = _start_server(tmp_path, "stun_root", relay_hub=hub)
    base_url = f"http://127.0.0.1:{httpd.server_port}"
    try:
        with urllib.request.urlopen(f"{base_url}/_ice/stun", timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        assert data["observed_ip"] == "127.0.0.1"

        req = urllib.request.Request(
            f"{base_url}/_ice/stun",
            headers={"X-Forwarded-For": "203.0.113.42, 10.0.0.1"},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            data_xff = json.loads(resp.read().decode("utf-8"))
        assert data_xff["observed_ip"] == "203.0.113.42"
    finally:
        httpd.shutdown()
        httpd.server_close()
        ost.close()


def test_ice_candidates_via_relay_agent(tmp_path: Path) -> None:
    hub = RelayHub()
    ost, _pstate, httpd = _start_server(tmp_path, "ice_root", relay_hub=hub)
    base_url = f"http://127.0.0.1:{httpd.server_port}"

    agent = RelayAgent(
        relay_url=base_url,
        node_id="mac1",
        local_port=httpd.server_port,
        workers=1,
        pull_timeout=2.0,
        direct_endpoints=["http://198.51.100.50:9000", "http://198.51.100.2:9000"],
    )
    agent.start()
    try:
        payload = None
        for _ in range(50):
            with urllib.request.urlopen(f"{base_url}/_ice/candidates?node=mac1", timeout=5) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            if data.get("online") and any(c.get("type") == "host" for c in data.get("candidates", [])):
                payload = data
                break
            time.sleep(0.05)

        assert payload is not None
        assert payload["node_id"] == "mac1"
        assert payload["observed_ip"] == "127.0.0.1"
        assert payload["online"] is True

        cands = payload["candidates"]
        types = [c["type"] for c in cands]
        assert types == ["host", "host", "srflx", "relay"]
        assert cands[0] == {"type": "host", "endpoint": "http://198.51.100.50:9000", "priority": 100}
        assert cands[1] == {"type": "host", "endpoint": "http://198.51.100.2:9000", "priority": 100}
        assert cands[2] == {"type": "srflx", "endpoint": "http://127.0.0.1:9000", "priority": 50}
        assert cands[3] == {"type": "relay", "endpoint": "/relay/mac1", "priority": 10}
    finally:
        agent.close()
        httpd.shutdown()
        httpd.server_close()
        ost.close()


def test_ice_discover_multiple_peers_into_swarm(tmp_path: Path) -> None:
    from dfs.l3_ost_adapter import SwarmOSTClient, make_ost_client

    hub = RelayHub()
    root_ost, _pstate, root_httpd = _start_server(tmp_path, "ice_multi_root", relay_hub=hub)
    peer1_ost, _p1, peer1_httpd = _start_server(tmp_path, "ice_peer1")
    peer2_ost, _p2, peer2_httpd = _start_server(tmp_path, "ice_peer2")
    root_url = f"http://127.0.0.1:{root_httpd.server_port}"
    peer1_url = f"http://127.0.0.1:{peer1_httpd.server_port}"
    peer2_url = f"http://127.0.0.1:{peer2_httpd.server_port}"

    agent1 = RelayAgent(
        relay_url=root_url,
        node_id="peer1",
        local_port=peer1_httpd.server_port,
        workers=1,
        pull_timeout=2.0,
        direct_endpoints=[peer1_url],
    )
    agent2 = RelayAgent(
        relay_url=root_url,
        node_id="peer2",
        local_port=peer2_httpd.server_port,
        workers=1,
        pull_timeout=2.0,
        direct_endpoints=[peer2_url],
    )
    agent1.start()
    agent2.start()
    try:
        _wait_node_connected(root_url, "", "peer1")
        _wait_node_connected(root_url, "", "peer2")

        swarm = SwarmOSTClient([make_ost_client(root_url)])
        added = swarm.discover_from_ice([root_url], timeout=2.0)
        assert sorted(added) == sorted([peer1_url, peer2_url])
        assert len(swarm.clients) == 3

        # 両ピアに別々のチャンクを置いて並列取得できること
        import hashlib

        b1, b2 = b"from-peer-1", b"from-peer-2"
        w1, w2 = hashlib.sha256(b1).hexdigest(), hashlib.sha256(b2).hexdigest()
        make_ost_client(peer1_url).batch_put_if_absent({w1: b1})
        make_ost_client(peer2_url).batch_put_if_absent({w2: b2})
        with swarm.session():
            got = swarm.batch_get([w1, w2])
        assert got == {w1: b1, w2: b2}
    finally:
        agent1.close()
        agent2.close()
        for h in (peer1_httpd, peer2_httpd, root_httpd):
            h.shutdown()
            h.server_close()
        for o in (peer1_ost, peer2_ost, root_ost):
            o.close()


def test_ice_unreachable_triggers_safe_mode(tmp_path: Path) -> None:
    import hashlib
    from dfs.l3_ost_adapter import SwarmOSTClient, make_ost_client

    hub = RelayHub()
    root_ost, _r_state, root_httpd = _start_server(tmp_path, "safe_root", relay_hub=hub)
    nat_ost, _n_state, nat_httpd = _start_server(tmp_path, "safe_nat")
    root_url = f"http://127.0.0.1:{root_httpd.server_port}"
    nat_url = f"http://127.0.0.1:{nat_httpd.server_port}"

    agent = RelayAgent(
        relay_url=root_url,
        node_id="blocked",
        local_port=nat_httpd.server_port,
        workers=1,
        pull_timeout=2.0,
        direct_endpoints=["http://127.0.0.1:1"],
    )
    agent.start()
    try:
        _wait_node_connected(root_url, "", "blocked")
        blob = b"safe-mode-payload"
        wid = hashlib.sha256(blob).hexdigest()
        make_ost_client(nat_url).batch_put_if_absent({wid: blob})

        swarm = SwarmOSTClient([make_ost_client(f"{root_url}/relay/blocked")])
        assert swarm.safe_mode is False
        added = swarm.discover_from_ice([root_url], timeout=0.5)
        assert added == []
        assert swarm.safe_mode is True
        assert swarm.safe_mode_reason == "ice_candidates_unreachable"

        with swarm.session():
            got = swarm.batch_get([wid])
        assert got == {wid: blob}
    finally:
        agent.close()
        for h in (nat_httpd, root_httpd):
            h.shutdown()
            h.server_close()
        for o in (nat_ost, root_ost):
            o.close()
def test_swarm_direct_failure_triggers_safe_mode(tmp_path: Path) -> None:
    import hashlib
    from dfs.l3_ost_adapter import SwarmOSTClient, make_ost_client

    hub = RelayHub()
    root_ost, _r_state, root_httpd = _start_server(tmp_path, "safe2_root", relay_hub=hub)
    nat_ost, _n_state, nat_httpd = _start_server(tmp_path, "safe2_nat")
    root_url = f"http://127.0.0.1:{root_httpd.server_port}"
    nat_url = f"http://127.0.0.1:{nat_httpd.server_port}"

    agent = RelayAgent(
        relay_url=root_url,
        node_id="n2",
        local_port=nat_httpd.server_port,
        workers=1,
        pull_timeout=2.0,
    )
    agent.start()
    try:
        _wait_node_connected(root_url, "", "n2")
        blob = b"relay-rescued"
        wid = hashlib.sha256(blob).hexdigest()
        make_ost_client(nat_url).batch_put_if_absent({wid: blob})

        swarm = SwarmOSTClient(
            [
                make_ost_client("http://127.0.0.1:1"),
                make_ost_client("http://127.0.0.1:2"),
                make_ost_client(f"{root_url}/relay/n2"),
            ]
        )
        assert swarm.safe_mode is False
        with swarm.session():
            got = swarm.batch_get([wid])
        assert got == {wid: blob}
        assert swarm.safe_mode is True
        assert swarm.safe_mode_reason == "swarm_direct_failed"
    finally:
        agent.close()
        for h in (nat_httpd, root_httpd):
            h.shutdown()
            h.server_close()
        for o in (nat_ost, root_ost):
            o.close()


def test_overload_header_excludes_busy_peer(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import hashlib
    from dfs.l3_ost_adapter import SwarmOSTClient, make_ost_client

    monkeypatch.setenv("DFS_OST_OVERLOAD_INFLIGHT", "1")
    ost1, _s1, httpd1 = _start_server(tmp_path, "ol_p1")
    monkeypatch.delenv("DFS_OST_OVERLOAD_INFLIGHT", raising=False)
    ost2, _s2, httpd2 = _start_server(tmp_path, "ol_p2")

    url1 = f"http://127.0.0.1:{httpd1.server_port}"
    url2 = f"http://127.0.0.1:{httpd2.server_port}"
    try:
        blob = b"overload-test-chunk"
        wid = hashlib.sha256(blob).hexdigest()
        make_ost_client(url1).batch_put_if_absent({wid: blob})
        make_ost_client(url2).batch_put_if_absent({wid: blob})

        c1 = make_ost_client(url1)
        c2 = make_ost_client(url2)
        swarm = SwarmOSTClient([c1, c2])
        swarm._adapted = True
        with swarm.session():
            got1 = swarm.batch_get([wid])
            assert got1 == {wid: blob}
            assert c1.last_overloaded is True
            rt1_after_first = c1.round_trips

            got2 = swarm.batch_get([wid])
            assert got2 == {wid: blob}
            # 2 回目は過負荷の c1 を除外して c2 から取得すること
            assert c1.round_trips == rt1_after_first
            assert c2.round_trips >= 1
    finally:
        for h in (httpd1, httpd2):
            h.shutdown()
            h.server_close()
        for o in (ost1, ost2):
            o.close()


def test_ice_announce_seeder_and_discover(tmp_path: Path) -> None:
    import hashlib
    from dfs.l3_ost_adapter import SwarmOSTClient, make_ost_client
    from dfs.relay import announce_ice_peer

    hub = RelayHub()
    root_ost, _rs, root_httpd = _start_server(tmp_path, "seed_root", relay_hub=hub)
    seeder_ost, _ss, seeder_httpd = _start_server(tmp_path, "seed_reader")
    root_url = f"http://127.0.0.1:{root_httpd.server_port}"
    seeder_url = f"http://127.0.0.1:{seeder_httpd.server_port}"
    try:
        blob = b"seeded-by-reader"
        wid = hashlib.sha256(blob).hexdigest()
        make_ost_client(seeder_url).batch_put_if_absent({wid: blob})

        ok = announce_ice_peer(root_url, "reader-seeder", [seeder_url], role="seeder")
        assert ok is True

        info = hub.get_ice_candidates("reader-seeder")
        assert info["role"] == "seeder"
        assert info["online"] is True

        swarm = SwarmOSTClient([make_ost_client(root_url)])
        added = swarm.discover_from_ice([root_url], timeout=2.0)
        assert seeder_url in added

        with swarm.session():
            got = swarm.batch_get([wid])
        assert got == {wid: blob}
    finally:
        for h in (seeder_httpd, root_httpd):
            h.shutdown()
            h.server_close()
        for o in (seeder_ost, root_ost):
            o.close()


def test_dfssvc_simple_flags_and_dfscli_join(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from dfs.cli_main import main as cli_main
    from dfs.remotes import RemoteStore
    from dfs.svc import _normalize_hub_url, build_parser

    parser = build_parser()
    ns_local = parser.parse_args(["start"])
    assert ns_local.hub is None
    assert ns_local.join is None

    ns_hub = parser.parse_args(["start", "--hub", "dfs.example.com"])
    assert ns_hub.hub == "dfs.example.com"
    assert _normalize_hub_url("dfs.example.com") == "https://dfs.example.com"
    assert _normalize_hub_url("192.0.2.254:19100") == "http://192.0.2.254:19100"

    ns_join = parser.parse_args(["start", "--join", "https://dfs.example.com"])
    assert ns_join.join == "https://dfs.example.com"

    # dfscli join で既存ローカルサービス設定と RemoteStore が更新されること
    hub = RelayHub()
    root_ost, _rs, root_httpd = _start_server(tmp_path, "join_root", relay_hub=hub)
    peer_ost, _ps, peer_httpd = _start_server(tmp_path, "join_peer")
    root_url = f"http://127.0.0.1:{root_httpd.server_port}"
    peer_url = f"http://127.0.0.1:{peer_httpd.server_port}"
    try:
        from dfs.relay import announce_ice_peer

        assert announce_ice_peer(root_url, "peer1", [peer_url], role="seeder") is True

        fake_home = tmp_path / "home"
        svc_dir = fake_home / "dfssvc" / "local"
        svc_dir.mkdir(parents=True)
        monkeypatch.setenv("HOME", str(fake_home))
        monkeypatch.setenv("XDG_CONFIG_HOME", str(fake_home / ".config"))

        rc = cli_main([
            "join",
            root_url,
            "--name", "workstation",
            "--path", "/example.com/shared",
            "--secret", "sec-123",
        ])
        assert rc == 0

        cfg = json.loads((svc_dir / "dfssvc.json").read_text(encoding="utf-8"))
        assert cfg["join"] == root_url

        remote = RemoteStore().get("workstation")
        assert remote.registry == root_url
        assert remote.ost == peer_url
    finally:
        for h in (peer_httpd, root_httpd):
            h.shutdown()
            h.server_close()
        for o in (peer_ost, root_ost):
            o.close()


def test_dfscli_quit_and_rejoin_another_domain(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from dfs.cli_main import main as cli_main
    from dfs.remotes import RemoteStore

    hub_a = RelayHub()
    ost_a, _sa, httpd_a = _start_server(tmp_path, "quit_a", relay_hub=hub_a)
    hub_b = RelayHub()
    ost_b, _sb, httpd_b = _start_server(tmp_path, "quit_b", relay_hub=hub_b)
    url_a = f"http://127.0.0.1:{httpd_a.server_port}"
    url_b = f"http://127.0.0.1:{httpd_b.server_port}"
    try:
        fake_home = tmp_path / "home"
        svc_dir = fake_home / "dfssvc" / "local"
        svc_dir.mkdir(parents=True)
        monkeypatch.setenv("HOME", str(fake_home))
        monkeypatch.setenv("XDG_CONFIG_HOME", str(fake_home / ".config"))

        # 1) Domain A に join
        assert cli_main([
            "join", url_a, "--name", "dom_a", "--path", "/a/data", "--secret", "sec-a"
        ]) == 0
        assert json.loads((svc_dir / "dfssvc.json").read_text(encoding="utf-8"))["join"] == url_a
        assert "dom_a" in RemoteStore().names()

        # 2) Domain A から quit
        assert cli_main(["quit", "dom_a"]) == 0
        cfg_after_quit = json.loads((svc_dir / "dfssvc.json").read_text(encoding="utf-8"))
        assert cfg_after_quit["join"] == ""
        assert cfg_after_quit["relay_node"] == ""
        assert "dom_a" not in RemoteStore().names()

        # 3) Domain B に再 join
        assert cli_main([
            "join", url_b, "--name", "dom_b", "--path", "/b/data", "--secret", "sec-b"
        ]) == 0
        assert json.loads((svc_dir / "dfssvc.json").read_text(encoding="utf-8"))["join"] == url_b
        assert RemoteStore().get("dom_b").registry == url_b
    finally:
        for h in (httpd_a, httpd_b):
            h.shutdown()
            h.server_close()
        for o in (ost_a, ost_b):
            o.close()


def test_relay_hub_p2p_peer_allowlist_and_ice_announce(tmp_path: Path) -> None:
    from dfs.relay import announce_ice_peer, discover_ice_candidates, fetch_p2p_peers, register_p2p_peer

    hub = RelayHub()
    observed_changes: List[List[str]] = []
    hub.on_allowlist_change = lambda ids: observed_changes.append(list(ids))
    ost, _pstate, httpd = _start_server(tmp_path, "p2p_hub", relay_hub=hub)
    base_url = f"http://127.0.0.1:{httpd.server_port}"
    try:
        pid1 = "12D3KooWAllowPeerOne111111111111111111111111111111111"
        pid2 = "12D3KooWAllowPeerTwo222222222222222222222222222222222"
        addr1 = f"/ip4/127.0.0.1/udp/4001/quic-v1/p2p/{pid1}"
        addr2 = f"/ip4/127.0.0.1/udp/4002/quic-v1/p2p/{pid2}"

        # 1) /_p2p/peers 自動登録と取得
        reg_res = register_p2p_peer(base_url, pid1, node_id="n1", p2p_addrs=[addr1], role="seeder")
        assert pid1 in reg_res["peer_ids"]
        assert hub.is_peer_id_allowed(pid1)
        assert not hub.is_peer_id_allowed(pid2)

        # 2) /_ice/announce で peer_id / p2p_addrs も自動登録される
        assert announce_ice_peer(
            base_url,
            node_id="n2",
            direct_endpoints=[],
            role="seeder",
            peer_id=pid2,
            p2p_addrs=[addr2],
        )
        fetched = fetch_p2p_peers(base_url)
        assert set(fetched["peer_ids"]) == {pid1, pid2}
        cands = discover_ice_candidates(base_url, node_id="n2")
        assert any(c.get("type") == "libp2p" and c.get("peer_id") == pid2 and c.get("endpoint") == addr2 for c in cands)

        # 3) revoke で許可リストから外れる
        req = urllib.request.Request(
            f"{base_url}/_p2p/peers/revoke",
            data=json.dumps({"peer_id": pid1}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            revoked_body = json.loads(resp.read().decode("utf-8"))
        assert revoked_body["revoked"] is True
        assert pid1 not in revoked_body["peer_ids"]
        assert not hub.is_peer_id_allowed(pid1)
        assert len(observed_changes) >= 3
    finally:
        httpd.shutdown()
        httpd.server_close()
        ost.close()


def test_open_remote_preserves_relay_ost_fallback(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from dfs.cli_main import open_remote
    from dfs.remotes import Remote

    hub = RelayHub(token="tok-fb")
    hub_ost, _hub_state, hub_httpd = _start_server(tmp_path, "hub_fb", relay_hub=hub)
    peer_ost, peer_state, peer_httpd = _start_server(tmp_path, "peer_fb")
    hub_url = f"http://127.0.0.1:{hub_httpd.server_port}"
    # NAT 配下ノードが死んだ L3 ポート (127.0.0.1:1) を広告し、Relay 経由で L2/OST を受ける想定
    peer_state.ost_endpoint = "tls://127.0.0.1:1"
    peer_state.ost_alternates = [f"{hub_url}/relay/natnode"]

    agent = RelayAgent(relay_url=hub_url, node_id="natnode", local_port=peer_httpd.server_port, token="tok-fb")
    agent.start()
    try:
        _wait_node_connected(hub_url, "tok-fb", "natnode")
        fake_home = tmp_path / "home"
        fake_home.mkdir()
        monkeypatch.setenv("HOME", str(fake_home))
        monkeypatch.setenv("DFS_LIBP2P", "0")
        writer_priv, _writer_pub = _gen_ed25519(tmp_path / "writer")

        remote = Remote(
            name="natnode",
            registry=f"{hub_url}/relay/natnode",
            workdir=str(tmp_path / "mnt"),
            key=str(writer_priv),
            path="/example.com/nat",
            secret="sec-nat",
        )
        node = open_remote(remote, create=True)
        relay_ep = f"{hub_url}/relay/natnode"
        assert relay_ep in node.ost_endpoints
        assert any(getattr(c, "endpoint_uri", "") == relay_ep for c in node.read_ost.clients)

        # 書き込み/読み取りが 127.0.0.1:1 から Relay HTTP OST へ自動フェイルオーバすること
        import hashlib
        blob = b"relay-fallback-ok"
        wid = hashlib.sha256(blob).hexdigest()
        assert node.ost.put_if_absent(wid, blob)
        assert node.read_ost.get(wid) == blob
    finally:
        agent.close()
        for h in (peer_httpd, hub_httpd):
            h.shutdown()
            h.server_close()
        for o in (peer_ost, hub_ost):
            o.close()
