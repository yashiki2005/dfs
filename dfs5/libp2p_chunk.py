#!/usr/bin/env python3
"""libp2p/QUIC 上の読み取り専用 dfs5 chunk source。

プロトコル ``/dfs5/chunk/1.0.0``:

  request    = op(1) + count(4, BE) + wire_id[count](64 bytes)
  H response = "O" + flags[count](1 byte each)
  G response = "O" + (length(4, BE) + blob)[count]

libp2p は TCP ではなく QUIC を使う。OST の TLS/TCP 経路は残し、読み取り時の
追加 ChunkSource としてだけ使う。書き込みは行わない。
"""

from __future__ import annotations

import hashlib
import struct
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Sequence

from .crypto import ChunkIntegrityError
from .l2_registry import ServiceUnavailableError

PROTOCOL_ID = "/dfs5/chunk/1.0.0"
MAX_BATCH_ITEMS = 65_536
MAX_BLOB_BYTES = 256 * 1024 * 1024
MAX_FRAME_BYTES = 512 * 1024 * 1024

try:  # pragma: no cover - 依存環境で分岐
    import trio
    from libp2p import new_host
    from libp2p.peer.id import ID
    from libp2p.peer.peerinfo import PeerInfo
    from multiaddr import Multiaddr

    _LIBP2P_AVAILABLE = True
except ImportError:  # pragma: no cover
    trio = None  # type: ignore[assignment]
    new_host = None  # type: ignore[assignment]
    ID = None  # type: ignore[assignment]
    PeerInfo = None  # type: ignore[assignment]
    Multiaddr = None  # type: ignore[assignment]
    _LIBP2P_AVAILABLE = False


def _require_libp2p() -> None:
    if not _LIBP2P_AVAILABLE:
        raise ServiceUnavailableError(
            "libp2p chunk source is not available (pip install libp2p)"
        )


async def _read_exact(stream: Any, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = await stream.read(n - len(buf))
        if not chunk:
            raise ConnectionError("libp2p stream closed")
        buf.extend(chunk)
    return bytes(buf)


def _pack_request(op: bytes, wire_ids: Sequence[str]) -> bytes:
    if len(wire_ids) > MAX_BATCH_ITEMS:
        raise ValueError("Too many wire_ids")
    encoded = []
    for wid in wire_ids:
        if len(wid) != 64:
            raise ValueError(f"Invalid wire_id length: {wid!r}")
        encoded.append(wid.encode("ascii"))
    return op + struct.pack(">I", len(wire_ids)) + b"".join(encoded)


def _parse_wire_ids(raw: bytes, count: int) -> List[str]:
    if count > MAX_BATCH_ITEMS or len(raw) != count * 64:
        raise ValueError("Invalid wire_id frame")
    return [raw[i * 64 : (i + 1) * 64].decode("ascii") for i in range(count)]


class Libp2pChunkServer:
    """ローカルの chunk 辞書を libp2p/QUIC で配布する読み取り専用サーバ。

    py-libp2p のホストはプロセスごとの Trio ループで動かす必要があるため、
    このサーバは専用プロセス（``python -m dfs5.libp2p_chunk``）で起動する。
    """

    def __init__(
        self,
        store: Dict[str, bytes],
        *,
        listen: Optional[Sequence[str]] = None,
        psk: Optional[str] = None,
    ):
        _require_libp2p()
        self.store = store
        self.listen = list(listen or ["/ip4/0.0.0.0/udp/0/quic-v1"])
        self.psk = psk
        self.addrs: List[str] = []
        self.error: Optional[BaseException] = None
        self._stop = threading.Event()
        self._on_ready: Optional[Any] = None

    def serve_forever(self, on_ready: Optional[Any] = None) -> None:
        """専用プロセスのメインスレッドで QUIC サーバを動かす。"""
        self._on_ready = on_ready
        trio.run(self._run)

    async def _run(self) -> None:
        host = new_host(psk=self.psk, auto_persist=False, enable_quic=True)
        host.set_stream_handler(PROTOCOL_ID, self._handle_stream)
        async with host.run([Multiaddr(addr) for addr in self.listen]):
            self.addrs = [str(addr) for addr in host.get_addrs()]
            if self._on_ready is not None:
                self._on_ready(self.addrs)
            while not self._stop.is_set():
                await trio.sleep(0.1)

    async def _handle_stream(self, stream: Any) -> None:
        try:
            frame_len = struct.unpack(">I", await _read_exact(stream, 4))[0]
            if frame_len > MAX_FRAME_BYTES:
                raise ValueError("Request frame too large")
            frame = await _read_exact(stream, frame_len)
            if not frame:
                raise ValueError("Empty request frame")
            op = frame[:1]
            count = struct.unpack(">I", frame[1:5])[0]
            if count > MAX_BATCH_ITEMS:
                raise ValueError("Too many wire_ids")
            wire_ids = _parse_wire_ids(frame[5:], count)
            if op == b"H":
                body = b"O" + bytes(1 if wid in self.store else 0 for wid in wire_ids)
            elif op == b"G":
                parts = [b"O"]
                for wid in wire_ids:
                    blob = self.store.get(wid, b"")
                    if len(blob) > MAX_BLOB_BYTES:
                        raise ValueError("Chunk too large")
                    parts.append(struct.pack(">I", len(blob)))
                    parts.append(blob)
                body = b"".join(parts)
            else:
                raise ValueError(f"Unknown opcode: {op!r}")
            await stream.write(struct.pack(">I", len(body)) + body)
        except Exception:
            try:
                await stream.reset()
            except Exception:
                pass
        finally:
            try:
                await stream.close()
            except Exception:
                pass

    def close(self) -> None:
        self._stop.set()


def load_chunks_dir(path: Path | str) -> Dict[str, bytes]:
    """``ChunkStoreServer.save_ost_chunks`` が作った *.blk を読み込む。"""
    store: Dict[str, bytes] = {}
    for item in sorted(Path(path).glob("*.blk")):
        blob = item.read_bytes()
        wid = item.stem
        if hashlib.sha256(blob).hexdigest() != wid:
            raise ValueError(f"Invalid chunk file: {item}")
        store[wid] = blob
    return store


class Libp2pChunkClient:
    """libp2p/QUIC peer から chunk を取得する読み取り専用クライアント。"""

    def __init__(self, peers: Sequence[str], *, psk: Optional[str] = None):
        _require_libp2p()
        self.peers = [str(p) for p in peers if str(p).strip()]
        if not self.peers:
            raise ValueError("At least one libp2p peer is required")
        self.psk = psk
        self.host = "libp2p"
        self.port = 0
        self.bytes_sent = 0
        self.bytes_received = 0
        self.blob_bytes_sent = 0
        self.round_trips = 0
        self.tls_handshakes = 0
        self.put_count = 0
        self.get_count = 0

    def start(self) -> "Libp2pChunkClient":
        return self

    def reset_metrics(self) -> None:
        self.bytes_sent = 0
        self.bytes_received = 0
        self.blob_bytes_sent = 0
        self.round_trips = 0
        self.tls_handshakes = 0
        self.put_count = 0
        self.get_count = 0

    @contextmanager
    def session(self) -> Iterator["Libp2pChunkClient"]:
        self.start()
        yield self

    def _request(self, op: bytes, wire_ids: Sequence[str]) -> bytes:
        # libp2p のホストは Trio 上で動く。QUIC の最小実装として 1 バッチごとに
        # Trio ループを起動する。常駐ループ化は後の最適化。
        return trio.run(self._request_once, op, wire_ids)

    async def _request_once(self, op: bytes, wire_ids: Sequence[str]) -> bytes:
        last_error: Optional[BaseException] = None
        host = new_host(psk=self.psk, auto_persist=False, enable_quic=True)
        async with host.run([Multiaddr("/ip4/127.0.0.1/udp/0/quic-v1")]):
            for peer in self.peers:
                try:
                    peer_info = _peer_info(peer)
                    await host.connect(peer_info)
                    stream = await host.new_stream(peer_info.peer_id, [PROTOCOL_ID])
                    try:
                        request = _pack_request(op, wire_ids)
                        await stream.write(struct.pack(">I", len(request)) + request)
                        frame_len = struct.unpack(
                            ">I", await _read_exact(stream, 4)
                        )[0]
                        if frame_len > MAX_FRAME_BYTES:
                            raise ChunkIntegrityError("libp2p response frame too large")
                        return await _read_exact(stream, frame_len)
                    finally:
                        try:
                            await stream.close()
                        except Exception:
                            pass
                except (
                    ServiceUnavailableError,
                    ChunkIntegrityError,
                    OSError,
                    ConnectionError,
                ) as e:
                    last_error = e
                    continue
        raise ServiceUnavailableError(
            f"All libp2p peers failed: {last_error}"
        ) from last_error

    def batch_has(self, wire_ids: Sequence[str]) -> Dict[str, bool]:
        unique = list(dict.fromkeys(wire_ids))
        if not unique:
            return {}
        body = self._request(b"H", unique)
        if not body or body[:1] != b"O" or len(body) != 1 + len(unique):
            raise ChunkIntegrityError("Invalid libp2p HAS response")
        self.round_trips += 1
        return {wid: body[i + 1] == 1 for i, wid in enumerate(unique)}

    def batch_get(self, wire_ids: Sequence[str]) -> Dict[str, bytes]:
        unique = list(dict.fromkeys(wire_ids))
        if not unique:
            return {}
        body = self._request(b"G", unique)
        if not body or body[:1] != b"O":
            raise ChunkIntegrityError("Invalid libp2p GET response")
        pos = 1
        result: Dict[str, bytes] = {}
        for wid in unique:
            if pos + 4 > len(body):
                raise ChunkIntegrityError("Truncated libp2p GET response")
            size = struct.unpack(">I", body[pos : pos + 4])[0]
            pos += 4
            if size > MAX_BLOB_BYTES or pos + size > len(body):
                raise ChunkIntegrityError("Invalid libp2p blob length")
            blob = body[pos : pos + size]
            pos += size
            if not blob or hashlib.sha256(blob).hexdigest() != wid:
                raise ChunkIntegrityError(f"Invalid or missing libp2p chunk: {wid}")
            result[wid] = blob
            self.bytes_received += size
            self.get_count += 1
        if pos != len(body):
            raise ChunkIntegrityError("Trailing bytes in libp2p GET response")
        self.round_trips += 1
        return result

    def get(self, wire_id: str) -> bytes:
        return self.batch_get([wire_id])[wire_id]

    def batch_put_if_absent(self, chunks: Dict[str, bytes], assume_absent: bool = False) -> int:
        raise ServiceUnavailableError("libp2p chunk source is read-only")

    def put_if_absent(self, wire_id: str, blob: bytes) -> bool:
        raise ServiceUnavailableError("libp2p chunk source is read-only")

    def close(self) -> None:
        pass


def _peer_info(value: str) -> Any:
    maddr = Multiaddr(value)
    peer_id = maddr.value_for_protocol("p2p")
    if not peer_id:
        raise ServiceUnavailableError(f"libp2p multiaddr has no /p2p id: {value}")
    return PeerInfo(ID.from_base58(peer_id), [maddr])


def _main() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        prog="python -m dfs5.libp2p_chunk",
        description="Serve a dfs5 chunk directory over libp2p/QUIC",
    )
    parser.add_argument("--chunks-dir", required=True)
    parser.add_argument(
        "--listen",
        action="append",
        default=[],
        help="QUIC multiaddr (default: /ip4/0.0.0.0/udp/0/quic-v1)",
    )
    parser.add_argument("--psk", help="private swarm pre-shared key")
    args = parser.parse_args()
    store = load_chunks_dir(args.chunks_dir)
    server = Libp2pChunkServer(
        store,
        listen=args.listen or ["/ip4/0.0.0.0/udp/0/quic-v1"],
        psk=args.psk,
    )

    def ready(addrs: List[str]) -> None:
        for addr in addrs:
            print(f"READY {addr}", flush=True)

    server.serve_forever(ready)


if __name__ == "__main__":
    _main()
