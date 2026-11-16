#!/usr/bin/env python3
"""L3 OST over HTTP/HTTPS (HttpOSTClient + /v1/ost/batch_* ハンドラ) の試験。"""

from __future__ import annotations

import subprocess
import socket
import threading
from http.server import BaseHTTPRequestHandler
from pathlib import Path

import pytest

from dfs.cli import (
    BoundedThreadingHTTPServer,
    PersistentRegistryState,
    make_registry_http_handler,
)
from dfs.crypto import ChunkIntegrityError, sha256_hex
from dfs.l2_registry import ServiceUnavailableError
from dfs.l3_ost_adapter import (
    ChunkStoreServer,
    FailoverOSTClient,
    HttpOSTClient,
    OSTClient,
    make_ost_client,
    parse_ost_endpoint,
)
from dfs.remotes import Remote


def _start_http_ost_server(tmp_path: Path):
    root_key = tmp_path / "root"
    subprocess.run(
        ["ssh-keygen", "-t", "ed25519", "-N", "", "-f", str(root_key)],
        capture_output=True,
        text=True,
        check=True,
    )
    pub_text = Path(f"{root_key}.pub").read_text(encoding="utf-8").strip()
    state_dir = tmp_path / "state"
    state_dir.mkdir(parents=True, exist_ok=True)
    pstate = PersistentRegistryState(state_dir, "/example.com", pub_text)
    cert = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
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
            "/CN=127.0.0.1",
        ],
        check=True,
        capture_output=True,
    )
    ost = ChunkStoreServer(certfile=cert, keyfile=key, host="127.0.0.1", port=0)
    handler = make_registry_http_handler(pstate, ost)
    httpd = BoundedThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return ost, httpd


def test_parse_and_normalize_ost_endpoints() -> None:
    assert parse_ost_endpoint("127.0.0.1:19441") == ("127.0.0.1", 19441, "tls://127.0.0.1:19441")
    assert parse_ost_endpoint("tls://ost.dfs.example.com:443") == (
        "ost.dfs.example.com",
        443,
        "tls://ost.dfs.example.com:443",
    )
    assert parse_ost_endpoint("https://dfs.example.com/") == (
        "dfs.example.com",
        443,
        "https://dfs.example.com",
    )
    assert parse_ost_endpoint("http://127.0.0.1:19440/sub/") == (
        "127.0.0.1",
        19440,
        "http://127.0.0.1:19440/sub",
    )
    assert isinstance(make_ost_client("https://dfs.example.com"), HttpOSTClient)
    assert isinstance(make_ost_client("tls://dfs.example.com:443"), OSTClient)
    assert Remote.normalize_ost("https://dfs.example.com/") == "https://dfs.example.com"
    assert Remote.normalize_ost("tls://127.0.0.1:19441") == "127.0.0.1:19441"


def test_bounded_http_server_does_not_reverse_resolve(monkeypatch) -> None:
    def fail_getfqdn(_host):
        raise AssertionError("server_bind must not call socket.getfqdn")

    monkeypatch.setattr(socket, "getfqdn", fail_getfqdn)
    httpd = BoundedThreadingHTTPServer(("127.0.0.1", 0), BaseHTTPRequestHandler)
    try:
        assert httpd.server_name == "127.0.0.1"
        assert httpd.server_port > 0
    finally:
        httpd.server_close()


def test_http_ost_roundtrip_and_session(tmp_path: Path) -> None:
    ost, httpd = _start_http_ost_server(tmp_path)
    try:
        base_url = f"http://127.0.0.1:{httpd.server_port}"
        client = HttpOSTClient(base_url)

        blob1 = b"hello-http-ost-1"
        blob2 = b"hello-http-ost-2" * 100
        wid1 = sha256_hex(blob1)
        wid2 = sha256_hex(blob2)

        with client.session():
            assert client.batch_has([wid1, wid2]) == {wid1: False, wid2: False}
            put_n = client.batch_put_if_absent({wid1: blob1, wid2: blob2})
            assert put_n == 2
            assert client.batch_has([wid1, wid2]) == {wid1: True, wid2: True}
            # 既にあるチャンクは再送しない
            assert client.batch_put_if_absent({wid1: blob1}) == 0
            fetched = client.batch_get([wid1, wid2])
            assert fetched == {wid1: blob1, wid2: blob2}

        assert client.put_count == 2
        assert client.get_count == 2
        assert client.bytes_sent > 0
        assert client.bytes_received > 0
    finally:
        httpd.shutdown()
        httpd.server_close()
        ost.close()


def test_http_ost_integrity_and_offline(tmp_path: Path) -> None:
    ost, httpd = _start_http_ost_server(tmp_path)
    try:
        client = HttpOSTClient(f"http://127.0.0.1:{httpd.server_port}")
        bad_wid = "a" * 64
        with pytest.raises(ChunkIntegrityError):
            client.batch_put_if_absent({bad_wid: b"tampered"}, assume_absent=True)

        ost.online = False
        with pytest.raises(ServiceUnavailableError):
            client.batch_has([bad_wid])
    finally:
        httpd.shutdown()
        httpd.server_close()
        ost.close()


def test_failover_from_tls_to_http_ost(tmp_path: Path) -> None:
    ost, httpd = _start_http_ost_server(tmp_path)
    try:
        blob = b"failover-over-http"
        wid = sha256_hex(blob)
        http_client = HttpOSTClient(f"http://127.0.0.1:{httpd.server_port}")
        assert http_client.put_if_absent(wid, blob) is True

        # 先頭は到達不能な TLS OST、代替が HTTP OST
        dead_tls = OSTClient(host="127.0.0.1", port=1)
        failover = FailoverOSTClient([dead_tls, http_client])
        assert failover.batch_has([wid]) == {wid: True}
        assert failover.batch_get([wid]) == {wid: blob}
    finally:
        httpd.shutdown()
        httpd.server_close()
        ost.close()
