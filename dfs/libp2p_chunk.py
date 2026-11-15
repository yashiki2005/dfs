#!/usr/bin/env python3
"""libp2p/QUIC 上の読み取り専用 dfs chunk source。

プロトコル ``/dfs/chunk/1.0.0``:

  request    = op(1) + count(4, BE) + wire_id[count](64 bytes)
  H response = "O" + flags[count](1 byte each)
  G response = "O" + (length(4, BE) + blob)[count]

libp2p は TCP ではなく QUIC を使う。OST の TLS/TCP 経路は残し、読み取り時の
追加 ChunkSource としてだけ使う。書き込みは行わない。
"""

from __future__ import annotations

import hashlib
import os
import random
import struct
import threading
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait as futures_wait
from contextlib import AsyncExitStack, contextmanager
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional, Sequence, Set, Tuple

from .crypto import ChunkIntegrityError
from .l2_registry import ServiceUnavailableError
from .nat import UPnPPortMapper

PROTOCOL_ID = "/dfs/chunk/1.0.0"
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

try:  # pragma: no cover - DHT / Circuit Relay v2 / DCUtR は optional submodule
    from cid import make_cid
    from libp2p.kad_dht.kad_dht import DHTMode, KadDHT
    from libp2p.tools.anyio_service import background_trio_service
    from multihash import digest as mh_digest

    _DHT_AVAILABLE = True
except ImportError:  # pragma: no cover
    make_cid = None  # type: ignore[assignment]
    KadDHT = None  # type: ignore[assignment]
    DHTMode = None  # type: ignore[assignment]
    background_trio_service = None  # type: ignore[assignment]
    mh_digest = None  # type: ignore[assignment]
    _DHT_AVAILABLE = False

try:  # pragma: no cover
    from libp2p.relay.circuit_v2.config import RelayConfig, RelayRole
    from libp2p.relay.circuit_v2.dcutr import DCUtRProtocol
    from libp2p.relay.circuit_v2.discovery import RelayDiscovery
    from libp2p.relay.circuit_v2.protocol import CircuitV2Protocol
    from libp2p.relay.circuit_v2.resources import RelayLimits
    from libp2p.relay.circuit_v2.transport import CircuitV2Transport

    _RELAY_V2_AVAILABLE = True
except ImportError:  # pragma: no cover
    RelayConfig = None  # type: ignore[assignment]
    RelayRole = None  # type: ignore[assignment]
    CircuitV2Protocol = None  # type: ignore[assignment]
    RelayLimits = None  # type: ignore[assignment]
    CircuitV2Transport = None  # type: ignore[assignment]
    DCUtRProtocol = None  # type: ignore[assignment]
    RelayDiscovery = None  # type: ignore[assignment]
    _RELAY_V2_AVAILABLE = False


def is_libp2p_available() -> bool:
    return _LIBP2P_AVAILABLE


def domain_cid(domain_key: str) -> str:
    """root/domain 名または pubkey から決定論的な Kademlia DHT 用 CIDv1 を生成する。"""
    key_bytes = f"dfs:domain:{domain_key}".encode("utf-8")
    if _DHT_AVAILABLE and mh_digest is not None and make_cid is not None:
        mh = mh_digest(key_bytes, "sha2-256").encode()
        return str(make_cid(1, "raw", mh))
    return hashlib.sha256(key_bytes).hexdigest()


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
    if op == b"L":
        offset = 0
        limit = MAX_BATCH_ITEMS
        if wire_ids:
            parts_spec = wire_ids[0].split(":", 1)
            offset = max(0, int(parts_spec[0] or 0))
            if len(parts_spec) > 1 and parts_spec[1]:
                limit = max(1, min(MAX_BATCH_ITEMS, int(parts_spec[1])))
        return b"L" + struct.pack(">II", offset, limit)
    if len(wire_ids) > MAX_BATCH_ITEMS:
        raise ValueError("Too many wire_ids")
    encoded = []
    for wid in wire_ids:
        if len(wid) != 64:
            raise ValueError(f"Invalid wire_id length: {wid!r}")
        encoded.append(wid.encode("ascii"))
    return op + struct.pack(">I", len(wire_ids)) + b"".join(encoded)


def _handle_list_frame(frame: bytes, store: Any) -> bytes:
    """Handle a ``b'L'`` (LIST_CHUNKS) request frame and return the response body."""
    if len(frame) != 9:
        raise ValueError("Invalid LIST frame")
    offset, limit = struct.unpack(">II", frame[1:9])
    limit = max(1, min(MAX_BATCH_ITEMS, limit))
    all_ids = _store_list(store)
    total = len(all_ids)
    page = all_ids[offset : offset + limit]
    out_parts = [b"O", struct.pack(">II", total, len(page))]
    for wid in page:
        wb = wid.encode("utf-8")
        out_parts.append(struct.pack(">H", len(wb)))
        out_parts.append(wb)
    return b"".join(out_parts)


def _parse_wire_ids(raw: bytes, count: int) -> List[str]:
    if count > MAX_BATCH_ITEMS or len(raw) != count * 64:
        raise ValueError("Invalid wire_id frame")
    return [raw[i * 64 : (i + 1) * 64].decode("ascii") for i in range(count)]


class Libp2pChunkServer:
    """ローカルの chunk 辞書を libp2p/QUIC で配布する読み取り専用サーバ。

    py-libp2p のホストはプロセスごとの Trio ループで動かす必要があるため、
    このサーバは専用プロセス（``python -m dfs.libp2p_chunk``）で起動する。
    """

    def __init__(
        self,
        store: Dict[str, bytes],
        *,
        listen: Optional[Sequence[str]] = None,
        psk: Optional[str] = None,
        allowed_peer_ids: Optional[Iterable[str]] = None,
    ):
        _require_libp2p()
        self.store = store
        self.listen = list(listen or ["/ip4/0.0.0.0/udp/0/quic-v1"])
        self.psk = psk
        self.peer_id: str = ""
        self.addrs: List[str] = []
        self.error: Optional[BaseException] = None
        self._stop = threading.Event()
        self._on_ready: Optional[Any] = None
        self._lock = threading.RLock()
        self._allowed_peer_ids: Optional[Set[str]] = (
            {str(p).strip() for p in allowed_peer_ids if str(p).strip()}
            if allowed_peer_ids is not None
            else None
        )

    def set_allowed_peer_ids(self, peer_ids: Optional[Iterable[str]]) -> None:
        with self._lock:
            if peer_ids is None:
                self._allowed_peer_ids = None
            else:
                self._allowed_peer_ids = {str(p).strip() for p in peer_ids if str(p).strip()}

    def _is_peer_allowed(self, peer_id: str) -> bool:
        pid = str(peer_id or "").strip()
        with self._lock:
            if self._allowed_peer_ids is None:
                return True
            return bool(pid and pid in self._allowed_peer_ids)

    def serve_forever(self, on_ready: Optional[Any] = None) -> None:
        """専用プロセスのメインスレッドで QUIC サーバを動かす。"""
        self._on_ready = on_ready
        trio.run(self._run)

    async def _run(self) -> None:
        host = new_host(psk=self.psk, auto_persist=False, enable_quic=True)
        host.set_stream_handler(PROTOCOL_ID, self._handle_stream)
        async with host.run([Multiaddr(addr) for addr in self.listen]):
            self.peer_id = str(host.get_id())
            self.addrs = [str(addr) for addr in host.get_addrs()]
            if self._on_ready is not None:
                self._on_ready(self.addrs)
            while not self._stop.is_set():
                await trio.sleep(0.1)

    async def _handle_stream(self, stream: Any) -> None:
        remote_peer = str(getattr(getattr(stream, "muxed_conn", None), "peer_id", "") or "")
        if not self._is_peer_allowed(remote_peer):
            try:
                await stream.reset()
            except Exception:
                pass
            try:
                await stream.close()
            except Exception:
                pass
            return
        try:
            frame_len = struct.unpack(">I", await _read_exact(stream, 4))[0]
            if frame_len > MAX_FRAME_BYTES:
                raise ValueError("Request frame too large")
            frame = await _read_exact(stream, frame_len)
            if not frame:
                raise ValueError("Empty request frame")
            op = frame[:1]
            if op == b"L":
                body = _handle_list_frame(frame, self.store)
                await stream.write(struct.pack(">I", len(body)) + body)
                return
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


def _store_contains(store: Any, wid: str) -> bool:
    if store is None:
        return False
    for attr in ("has_chunk", "_has_chunk"):
        fn = getattr(store, attr, None)
        if callable(fn):
            return bool(fn(wid))
    return wid in store


def _store_get(store: Any, wid: str) -> bytes:
    if store is None:
        return b""
    for attr in ("get_chunk", "_get_chunk"):
        fn = getattr(store, attr, None)
        if callable(fn):
            data = fn(wid)
            return data if data is not None else b""
    return store.get(wid, b"")


def _store_put(store: Any, wid: str, blob: bytes) -> bool:
    if store is None:
        return False
    for attr in ("put_chunk", "_put_chunk"):
        fn = getattr(store, attr, None)
        if callable(fn):
            return bool(fn(wid, blob))
    store[wid] = blob
    return True


def _store_list(store: Any) -> List[str]:
    if store is None:
        return []
    fn = getattr(store, "list_chunks", None)
    if callable(fn):
        return [str(k) for k in fn()]
    if isinstance(store, dict):
        return sorted(str(k) for k in store.keys())
    return []


def _extract_peer_id(value: str) -> str:
    maddr = Multiaddr(value)
    peer_id = maddr.value_for_protocol("p2p")
    if not peer_id:
        raise ServiceUnavailableError(f"libp2p multiaddr has no /p2p id: {value}")
    return str(peer_id)


def _split_p2p_addrs(addrs: Sequence[str]) -> Tuple[List[str], List[str]]:
    direct: List[str] = []
    relay: List[str] = []
    for a in addrs:
        s = str(a).strip()
        if not s:
            continue
        if "/p2p-circuit" in s:
            relay.append(s)
        else:
            direct.append(s)
    return direct, relay


def _local_non_loopback_ipv4s() -> List[str]:
    """ホストの非ループバック IPv4 アドレス一覧を返す（0.0.0.0 展開用）。"""
    ips: List[str] = []
    try:
        import ifaddr  # type: ignore[import-not-found]

        for adapter in ifaddr.get_adapters():
            for ip in adapter.ips:
                addr = ip.ip
                if isinstance(addr, str) and "." in addr and not addr.startswith("127.") and not addr.startswith("169.254."):
                    if addr not in ips:
                        ips.append(addr)
    except Exception:
        pass
    if not ips:
        import socket

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("1.1.1.1", 80))
                local_ip = s.getsockname()[0]
                if local_ip and not local_ip.startswith("127."):
                    ips.append(local_ip)
        except Exception:
            pass
    return ips


def _local_non_loopback_ipv6s() -> List[str]:
    """ホストの非ループバック・非リンクローカル IPv6 アドレス一覧を返す（:: 展開用）。"""
    import ipaddress

    ips: List[str] = []
    try:
        import ifaddr  # type: ignore[import-not-found]

        for adapter in ifaddr.get_adapters():
            for ip in adapter.ips:
                raw = ip.ip[0] if isinstance(ip.ip, tuple) else ip.ip
                if not isinstance(raw, str) or ":" not in raw:
                    continue
                addr_str = raw.split("%", 1)[0]
                try:
                    addr_obj = ipaddress.ip_address(addr_str)
                except ValueError:
                    continue
                if addr_obj.version == 6 and not addr_obj.is_loopback and not addr_obj.is_link_local:
                    norm = str(addr_obj)
                    if norm not in ips:
                        ips.append(norm)
    except Exception:
        pass
    return ips


def _supports_ipv6_bind() -> bool:
    """ホストが IPv6 ワイルドカードソケット (::) をバインドできるか返す。"""
    import socket

    if not getattr(socket, "has_ipv6", False):
        return False
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as s:
            s.bind(("::", 0))
        return True
    except OSError:
        return False


def _is_private_multiaddr(addr: str) -> bool:
    """multiaddr の先頭 IP がプライベート/ループバック/リンクローカルなら True。"""
    import ipaddress

    parts = [p for p in str(addr or "").split("/") if p]
    if len(parts) >= 2 and parts[0] in ("ip4", "ip6"):
        try:
            ip_obj = ipaddress.ip_address(parts[1].split("%", 1)[0])
            return bool(ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local)
        except ValueError:
            return False
    return False


class Libp2pHostManager:
    """常駐 Trio ループ上で単一 libp2p Host（QUIC/TCP + DHT + Circuit Relay v2/DCUtR）を管理する。"""

    def __init__(
        self,
        *,
        store: Optional[Any] = None,
        listen: Optional[Sequence[str]] = None,
        psk: Optional[str] = None,
        key_pair: Optional[Any] = None,
        allowed_peer_ids: Optional[Iterable[str]] = None,
        enable_dht: bool = True,
        dht_mode: str = "server",
        enable_relay: bool = True,
        relay_hop: bool = False,
        enable_dcutr: bool = True,
        bootstrap_peers: Sequence[str] = (),
        enable_upnp: Optional[bool] = None,
    ) -> None:
        _require_libp2p()
        self.store = store
        if listen:
            self.listen = list(listen)
        else:
            default_listen = ["/ip4/0.0.0.0/udp/0/quic-v1", "/ip4/0.0.0.0/tcp/0"]
            if _supports_ipv6_bind():
                default_listen.extend(["/ip6/::/udp/0/quic-v1", "/ip6/::/tcp/0"])
            self.listen = default_listen
        self.psk = psk
        self.key_pair = key_pair
        self.enable_dht = bool(enable_dht and _DHT_AVAILABLE)
        self.dht_mode = str(dht_mode or "server").lower()
        if enable_upnp is None:
            self.enable_upnp = os.environ.get("DFS_P2P_UPNP", "1").strip() != "0"
        else:
            self.enable_upnp = bool(enable_upnp)
        self._upnp_mapper: Optional[UPnPPortMapper] = None
        self.upnp_external_addrs: List[str] = []
        self.enable_relay = bool(enable_relay and _RELAY_V2_AVAILABLE)
        self.relay_hop = bool(relay_hop)
        self.enable_dcutr = bool(enable_dcutr and _RELAY_V2_AVAILABLE)
        self.bootstrap_peers = [str(p).strip() for p in bootstrap_peers if str(p).strip()]

        self._lock = threading.RLock()
        self._allowed_peer_ids: Optional[Set[str]] = (
            {str(p).strip() for p in allowed_peer_ids if str(p).strip()}
            if allowed_peer_ids is not None
            else None
        )
        self.peer_id: str = ""
        self.addrs: List[str] = []
        self._relay_addrs: List[str] = []
        self.dht_active: bool = False
        self.relay_active: bool = False
        self.dcutr_active: bool = False
        self.error: Optional[BaseException] = None

        self._thread: Optional[threading.Thread] = None
        self._ready = threading.Event()
        self._trio_token: Optional[Any] = None
        self._stop_event: Optional[Any] = None
        self._host: Optional[Any] = None
        self._dht: Optional[Any] = None
        self._relay_proto: Optional[Any] = None
        self._dcutr_proto: Optional[Any] = None
        self._relay_discovery: Optional[Any] = None
        self._relay_transport: Optional[Any] = None
        self._bg_nursery: Optional[Any] = None

    def set_allowed_peer_ids(self, peer_ids: Optional[Iterable[str]]) -> None:
        with self._lock:
            if peer_ids is None:
                self._allowed_peer_ids = None
            else:
                self._allowed_peer_ids = {str(p).strip() for p in peer_ids if str(p).strip()}

    def allow_peer_id(self, peer_id: str) -> None:
        pid = str(peer_id or "").strip()
        if not pid:
            return
        with self._lock:
            if self._allowed_peer_ids is None:
                self._allowed_peer_ids = set()
            self._allowed_peer_ids.add(pid)

    def revoke_peer_id(self, peer_id: str) -> None:
        pid = str(peer_id or "").strip()
        with self._lock:
            if self._allowed_peer_ids is not None:
                self._allowed_peer_ids.discard(pid)

    def is_peer_allowed(self, peer_id: str) -> bool:
        pid = str(peer_id or "").strip()
        with self._lock:
            if self._allowed_peer_ids is None:
                return True
            return bool(pid and pid in self._allowed_peer_ids)

    def start(self, timeout: float = 10.0) -> "Libp2pHostManager":
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return self
            self._ready.clear()
            self.error = None
            self._thread = threading.Thread(
                target=self._thread_main,
                name="dfs-libp2p-host",
                daemon=True,
            )
            self._thread.start()
        if not self._ready.wait(timeout=timeout):
            raise ServiceUnavailableError("Timed out starting libp2p host")
        if self.error is not None:
            raise ServiceUnavailableError(f"Failed to start libp2p host: {self.error}") from self.error
        if self.enable_upnp and any(
            "/ip4/127." not in a and "/ip6/::1/" not in a for a in self.addrs
        ):
            threading.Thread(
                target=self._try_upnp_mappings,
                name="dfs-libp2p-upnp",
                daemon=True,
            ).start()
        return self

    def _thread_main(self) -> None:
        try:
            trio.run(self._serve_loop)
        except BaseException as exc:  # pragma: no cover - startup diagnostics
            self.error = exc
            self._ready.set()

    async def _serve_loop(self) -> None:
        enable_upnp = os.environ.get("DFS_LIBP2P_UPNP", "0").strip() == "1"
        host = new_host(
            key_pair=self.key_pair,
            psk=self.psk,
            auto_persist=False,
            enable_quic=True,
            enable_tcp=True,
            enable_upnp=enable_upnp,
        )
        self._host = host
        if self.store is not None:
            host.set_stream_handler(PROTOCOL_ID, self._handle_stream)

        if self.enable_relay and CircuitV2Protocol is not None:
            try:
                relay_limits = (
                    RelayLimits(
                        duration=3600,
                        data=1 << 30,
                        max_circuit_conns=128,
                        max_reservations=128,
                    )
                    if RelayLimits is not None
                    else None
                )
                self._relay_proto = CircuitV2Protocol(
                    host,
                    limits=relay_limits,
                    allow_hop=self.relay_hop,
                )
                if CircuitV2Transport is not None and RelayConfig is not None and RelayRole is not None:
                    self._relay_transport = CircuitV2Transport(
                        host,
                        self._relay_proto,
                        RelayConfig(roles=RelayRole.STOP | RelayRole.CLIENT),
                    )
                if RelayDiscovery is not None and not self.relay_hop:
                    self._relay_discovery = RelayDiscovery(host, auto_reserve=True)
            except Exception:
                self._relay_proto = None
                self._relay_transport = None
                self._relay_discovery = None
        if self.enable_dcutr and DCUtRProtocol is not None:
            try:
                self._dcutr_proto = DCUtRProtocol(host)
            except Exception:
                self._dcutr_proto = None

        async with host.run([Multiaddr(addr) for addr in self.listen]):
            self.peer_id = str(host.get_id())
            self.addrs = [str(addr) for addr in host.get_addrs()]
            self._trio_token = trio.lowlevel.current_trio_token()
            self._stop_event = trio.Event()

            async with AsyncExitStack() as stack:
                if self._relay_proto is not None and background_trio_service is not None:
                    try:
                        await stack.enter_async_context(background_trio_service(self._relay_proto))
                        self.relay_active = True
                    except Exception:
                        self.relay_active = False
                if self._dcutr_proto is not None and background_trio_service is not None:
                    try:
                        await stack.enter_async_context(background_trio_service(self._dcutr_proto))
                        self.dcutr_active = True
                    except Exception:
                        self.dcutr_active = False
                if self._relay_discovery is not None and background_trio_service is not None:
                    try:
                        await stack.enter_async_context(background_trio_service(self._relay_discovery))
                    except Exception:
                        self._relay_discovery = None
                if self.enable_dht and KadDHT is not None and background_trio_service is not None:
                    try:
                        mode = DHTMode.SERVER if self.dht_mode == "server" else DHTMode.CLIENT
                        self._dht = KadDHT(host, mode)
                        await stack.enter_async_context(background_trio_service(self._dht))
                        self.dht_active = True
                    except Exception:
                        self._dht = None
                        self.dht_active = False

                async with trio.open_nursery() as bg_nursery:
                    self._bg_nursery = bg_nursery
                    await self._connect_bootstrap_peers()
                    self._ready.set()
                    await self._stop_event.wait()
                    bg_nursery.cancel_scope.cancel()
                self._bg_nursery = None
            self.dht_active = False
            self.relay_active = False
            self.dcutr_active = False

    async def _connect_bootstrap_peers(self) -> None:
        for bp in self.bootstrap_peers:
            try:
                await self._connect_multiaddr_async(bp)
            except Exception:
                continue

    async def _connect_multiaddr_async(self, addr_str: str) -> str:
        assert self._host is not None
        pinfo = _peer_info(addr_str)
        conns = getattr(self._host.get_network(), "connections", {}) or {}
        if pinfo.peer_id not in conns:
            await self._host.connect(pinfo)
        if self._dht is not None:
            try:
                await self._dht.add_peer(pinfo.peer_id)
            except Exception:
                pass
        return str(pinfo.peer_id)

    def build_circuit_addrs(self, relay_addrs: Sequence[str]) -> List[str]:
        """リレー（hub/root）のマルチアドレスから自身の `/p2p-circuit` アドレスを組み立てる。"""
        if not self.peer_id:
            return []
        non_loopback: List[str] = []
        loopback: List[str] = []
        seen: Set[str] = set()
        for raw in relay_addrs:
            addr = str(raw or "").strip().rstrip("/")
            if not addr or "/p2p-circuit" in addr or "/p2p/" not in addr:
                continue
            if addr.endswith(f"/p2p/{self.peer_id}"):
                continue
            circuit = f"{addr}/p2p-circuit/p2p/{self.peer_id}"
            if circuit in seen:
                continue
            seen.add(circuit)
            if "/ip4/127." in addr or "/ip6/::1" in addr:
                loopback.append(circuit)
            else:
                non_loopback.append(circuit)
        return non_loopback if non_loopback else loopback

    def _try_upnp_mappings(self) -> None:
        mapper = UPnPPortMapper(timeout=1.5)
        self._upnp_mapper = mapper
        mapped_addrs: List[str] = []
        seen: Set[Tuple[int, str]] = set()
        for addr in list(self.addrs):
            if "/ip4/" not in addr or "/ip4/127." in addr or "/p2p-circuit" in addr:
                continue
            parts = addr.split("/")
            port = 0
            proto = ""
            is_quic = "quic-v1" in parts
            for idx, tok in enumerate(parts):
                if tok in ("udp", "tcp") and idx + 1 < len(parts) and parts[idx + 1].isdigit():
                    proto = tok.upper()
                    port = int(parts[idx + 1])
                    break
            if not port or (port, proto) in seen:
                continue
            seen.add((port, proto))
            res = mapper.map_port(port, protocol=proto)
            if res is not None:
                ext_ip, ext_port = res
                if proto == "UDP" and is_quic:
                    mapped_addrs.append(f"/ip4/{ext_ip}/udp/{ext_port}/quic-v1/p2p/{self.peer_id}")
                elif proto == "TCP":
                    mapped_addrs.append(f"/ip4/{ext_ip}/tcp/{ext_port}/p2p/{self.peer_id}")
        if mapped_addrs:
            self.upnp_external_addrs = mapped_addrs

    def effective_addrs(self, relay_addrs: Sequence[str] = ()) -> List[str]:
        """自身の直接アドレス（0.0.0.0 はローカル IP へ展開）と接続済みリレー経由の `/p2p-circuit` アドレスを返す。"""
        combined: List[str] = []
        lan_ips: Optional[List[str]] = None
        lan_ip6s: Optional[List[str]] = None
        for a in self.addrs:
            if a.startswith("/ip4/0.0.0.0/"):
                if lan_ips is None:
                    lan_ips = _local_non_loopback_ipv4s()
                suffix = a[len("/ip4/0.0.0.0"):]
                for ip in lan_ips:
                    expanded = f"/ip4/{ip}{suffix}"
                    if expanded not in combined:
                        combined.append(expanded)
            elif a.startswith("/ip6/::/"):
                if lan_ip6s is None:
                    lan_ip6s = _local_non_loopback_ipv6s()
                suffix = a[len("/ip6/::"):]
                for ip6 in lan_ip6s:
                    expanded = f"/ip6/{ip6}{suffix}"
                    if expanded not in combined:
                        combined.append(expanded)
            else:
                if a not in combined:
                    combined.append(a)
        for addr in self.upnp_external_addrs:
            if addr not in combined:
                combined.append(addr)
        source_relays = list(relay_addrs) if relay_addrs else list(self._relay_addrs)
        for addr in self.build_circuit_addrs(source_relays):
            if addr not in combined:
                combined.append(addr)
        return combined if combined else list(self.addrs)

    def bootstrap_from_peers(
        self,
        peers: Sequence[Any],
        *,
        max_peers: int = 8,
        timeout: float = 2.0,
    ) -> int:
        """ハブ等から得たピア情報（dict または multiaddr 文字列）へ接続し、DHT ルーティング表を初期化する。"""
        if not peers or self._trio_token is None:
            return 0
        prioritized: List[str] = []
        secondary: List[str] = []
        discovered_relays: List[str] = []
        for item in peers:
            if isinstance(item, str):
                s = item.strip()
                if s and "/p2p/" in s and (not self.peer_id or not s.endswith(f"/p2p/{self.peer_id}")):
                    if "/p2p-circuit" not in s:
                        secondary.append(s)
                continue
            if not isinstance(item, dict):
                continue
            pid = str(item.get("peer_id") or "").strip()
            if pid and pid == self.peer_id:
                continue
            role = str(item.get("role") or "").strip().lower()
            is_hub = role in ("hub", "root", "writer")
            for raw in item.get("addrs") or []:
                s = str(raw or "").strip()
                if not s or "/p2p/" not in s or "/p2p-circuit" in s:
                    continue
                if is_hub and s not in discovered_relays:
                    discovered_relays.append(s)
                target_list = prioritized if is_hub else secondary
                if s not in target_list:
                    target_list.append(s)

        if discovered_relays:
            with self._lock:
                for ra in discovered_relays:
                    if ra not in self._relay_addrs:
                        self._relay_addrs.append(ra)

        candidates: List[str] = []
        seen_c: Set[str] = set()
        for addr in sorted(prioritized, key=_is_private_multiaddr) + sorted(secondary, key=_is_private_multiaddr):
            if addr not in seen_c:
                seen_c.add(addr)
                candidates.append(addr)
        if not candidates:
            return 0

        async def _go() -> int:
            connected = 0
            tried_peers: Set[str] = set()
            hub_peer_ids: Set[str] = {
                ra.rsplit("/p2p/", 1)[-1].split("/", 1)[0]
                for ra in discovered_relays
                if "/p2p/" in ra
            }
            reserved_any = False
            with trio.move_on_after(timeout):
                for addr in candidates:
                    if connected >= max_peers:
                        break
                    pid_part = addr.rsplit("/p2p/", 1)[-1].split("/", 1)[0]
                    if pid_part in tried_peers:
                        continue
                    try:
                        await self._connect_multiaddr_async(addr)
                        tried_peers.add(pid_part)
                        connected += 1
                        if (
                            pid_part in hub_peer_ids
                            and self._relay_discovery is not None
                            and not self.relay_hop
                        ):
                            relay_id = ID.from_base58(pid_part)
                            try:
                                discovered = getattr(self._relay_discovery, "_discovered_relays", {})
                                if relay_id not in discovered:
                                    add_relay = getattr(self._relay_discovery, "_add_relay", None)
                                    if callable(add_relay):
                                        await add_relay(relay_id)
                                    else:
                                        await self._relay_discovery.discover_relays()
                                if await self._relay_discovery.make_reservation(relay_id):
                                    reserved_any = True
                            except Exception:
                                pass
                    except Exception:
                        continue
            return connected

        try:
            return int(self._run_sync(_go))
        except Exception:
            return 0

    async def _handle_stream(self, stream: Any) -> None:
        remote_peer = str(getattr(getattr(stream, "muxed_conn", None), "peer_id", "") or "")
        if not self.is_peer_allowed(remote_peer):
            try:
                await stream.reset()
            except Exception:
                pass
            try:
                await stream.close()
            except Exception:
                pass
            return
        try:
            frame_len = struct.unpack(">I", await _read_exact(stream, 4))[0]
            if frame_len > MAX_FRAME_BYTES:
                raise ValueError("Request frame too large")
            frame = await _read_exact(stream, frame_len)
            if not frame:
                raise ValueError("Empty request frame")
            op = frame[:1]
            if op == b"L":
                body = _handle_list_frame(frame, self.store)
                await stream.write(struct.pack(">I", len(body)) + body)
                return
            count = struct.unpack(">I", frame[1:5])[0]
            if count > MAX_BATCH_ITEMS:
                raise ValueError("Too many wire_ids")
            wire_ids = _parse_wire_ids(frame[5:], count)
            if op == b"H":
                body = b"O" + bytes(1 if _store_contains(self.store, wid) else 0 for wid in wire_ids)
            elif op == b"G":
                parts = [b"O"]
                for wid in wire_ids:
                    blob = _store_get(self.store, wid)
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

    def _run_sync(self, afn: Any, *args: Any) -> Any:
        self.start()
        if self._trio_token is None:
            raise ServiceUnavailableError("libp2p host is not running")
        try:
            return trio.from_thread.run(afn, *args, trio_token=self._trio_token)
        except RuntimeError as e:
            raise ServiceUnavailableError(f"libp2p host stopped: {e}") from e

    async def _ensure_connected_async(
        self,
        peer_id_str: str,
        addrs: Sequence[str],
        relay_addrs: Sequence[str] = (),
        timeout: float = 10.0,
    ) -> Any:
        assert self._host is not None
        pid = ID.from_base58(peer_id_str)
        net = self._host.get_network()
        conns = getattr(net, "connections", {}) or {}
        if pid in conns:
            return pid

        direct_list, embedded_relay = _split_p2p_addrs(addrs)
        raw_relays: List[str] = list(embedded_relay)
        for ra in relay_addrs:
            s = str(ra or "").strip().rstrip("/")
            if not s or ("/p2p-circuit" not in s and s.endswith(f"/p2p/{peer_id_str}")):
                continue
            if "/p2p-circuit" not in s:
                s = f"{s}/p2p-circuit/p2p/{peer_id_str}"
            if s not in raw_relays:
                raw_relays.append(s)
        all_relay = sorted(raw_relays, key=_is_private_multiaddr)
        last_err: Optional[BaseException] = None

        if direct_list:
            direct_timeout = min(timeout, 2.5) if all_relay else timeout
            won = False

            async def _race_direct(addr_str: str, cancel_scope: Any) -> None:
                nonlocal won, last_err
                try:
                    await self._connect_multiaddr_async(addr_str)
                    won = True
                    cancel_scope.cancel()
                except Exception as e:
                    last_err = e

            with trio.move_on_after(direct_timeout) as cs:
                async with trio.open_nursery() as nursery:
                    for a in direct_list:
                        nursery.start_soon(_race_direct, a, nursery.cancel_scope)
            if won:
                return pid
            if cs.cancelled_caught and last_err is None:
                last_err = TimeoutError(f"Timeout dialing peer {peer_id_str}")

        if all_relay:
            relay_won = False

            async def _dial_relay(ca: str, cancel_scope: Any) -> None:
                nonlocal relay_won, last_err
                try:
                    if "/p2p-circuit" in ca and self._relay_transport is not None:
                        relay_base = ca.split("/p2p-circuit", 1)[0].rstrip("/")
                        if "/p2p/" in relay_base:
                            with trio.fail_after(min(timeout, 3.0)):
                                await self._connect_multiaddr_async(relay_base)
                        await self._relay_transport.dial(Multiaddr(ca))
                    else:
                        await self._host.connect(PeerInfo(pid, [Multiaddr(ca)]))
                    relay_won = True
                    cancel_scope.cancel()
                except Exception as e:
                    last_err = e

            with trio.move_on_after(timeout) as cs:
                async with trio.open_nursery() as nursery:
                    for ca in all_relay:
                        nursery.start_soon(_dial_relay, ca, nursery.cancel_scope)
            if relay_won:
                return pid
            if cs.cancelled_caught and last_err is None:
                last_err = TimeoutError(f"Timeout dialing relayed peer {peer_id_str}")
        raise ServiceUnavailableError(f"Failed to dial libp2p peer {peer_id_str}: {last_err}") from last_err

    async def _request_peer_async(
        self,
        peer_id_str: str,
        addrs: Sequence[str],
        op: bytes,
        wire_ids: Sequence[str],
        relay_addrs: Sequence[str] = (),
        timeout: float = 10.0,
    ) -> bytes:
        assert self._host is not None
        pid = await self._ensure_connected_async(
            peer_id_str, addrs, relay_addrs=relay_addrs, timeout=timeout
        )
        with trio.move_on_after(timeout) as cs:
            stream = await self._host.new_stream(pid, [PROTOCOL_ID])
            try:
                request = _pack_request(op, wire_ids)
                await stream.write(struct.pack(">I", len(request)) + request)
                frame_len = struct.unpack(">I", await _read_exact(stream, 4))[0]
                if frame_len > MAX_FRAME_BYTES:
                    raise ChunkIntegrityError("libp2p response frame too large")
                return await _read_exact(stream, frame_len)
            finally:
                try:
                    await stream.close()
                except Exception:
                    pass
        if cs.cancelled_caught:
            raise ServiceUnavailableError(f"libp2p stream timed out to {peer_id_str}")
        raise ServiceUnavailableError(f"libp2p stream failed to {peer_id_str}")

    def request_peer(
        self,
        peer_id_str: str,
        addrs: Sequence[str],
        op: bytes,
        wire_ids: Sequence[str],
        *,
        relay_addrs: Sequence[str] = (),
        timeout: float = 10.0,
    ) -> bytes:
        return self._run_sync(
            self._request_peer_async,
            peer_id_str,
            list(addrs),
            op,
            list(wire_ids),
            list(relay_addrs),
            float(timeout),
        )

    def connect_peer(self, multiaddr_str: str, timeout: float = 5.0) -> str:
        async def _go() -> str:
            with trio.move_on_after(timeout):
                return await self._connect_multiaddr_async(multiaddr_str)
            raise ServiceUnavailableError(f"Timeout connecting to {multiaddr_str}")

        return self._run_sync(_go)

    def provide_domain(
        self,
        domain_key: str,
        timeout: float = 5.0,
        *,
        background: bool = False,
    ) -> bool:
        if not self.dht_active or self._dht is None:
            return False
        cid_str = domain_cid(domain_key)

        async def _go() -> bool:
            with trio.move_on_after(timeout):
                try:
                    return bool(await self._dht.provide(cid_str))
                except Exception:
                    return False
            return False

        if background:
            token = self._trio_token
            nursery = self._bg_nursery
            if token is None or nursery is None:
                return False
            try:
                trio.from_thread.run_sync(nursery.start_soon, _go, trio_token=token)
                return True
            except Exception:
                return False

        try:
            return bool(self._run_sync(_go))
        except Exception:
            return False

    def find_domain_providers(
        self,
        domain_key: str,
        count: int = 20,
        timeout: float = 5.0,
    ) -> List[Dict[str, Any]]:
        if not self.dht_active or self._dht is None:
            return []
        cid_str = domain_cid(domain_key)

        async def _go() -> List[Dict[str, Any]]:
            with trio.move_on_after(timeout):
                try:
                    provs = await self._dht.find_providers(cid_str, count=count)
                    out: List[Dict[str, Any]] = []
                    for p in provs:
                        out.append({
                            "peer_id": str(p.peer_id),
                            "addrs": [str(a) for a in getattr(p, "addrs", ())],
                        })
                    return out
                except Exception:
                    return []
            return []

        try:
            return self._run_sync(_go)
        except Exception:
            return []

    def close(self) -> None:
        token = self._trio_token
        stop_ev = self._stop_event
        if token is not None and stop_ev is not None:
            try:
                trio.from_thread.run_sync(stop_ev.set, trio_token=token)
            except Exception:
                pass
        if self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout=3.0)
        self._thread = None
        if self._upnp_mapper is not None:
            try:
                self._upnp_mapper.close()
            except Exception:
                pass
            self._upnp_mapper = None
        self._trio_token = None
        self._stop_event = None


class Libp2pPeerClient:
    """単一の libp2p peer を指す読み取り専用 OST 互換クライアント（SwarmOSTClient 用）。"""

    def __init__(
        self,
        manager: Libp2pHostManager,
        peer_id: str,
        addrs: Sequence[str],
        *,
        relay_addrs: Sequence[str] = (),
        owns_manager: bool = False,
        timeout: float = 10.0,
    ) -> None:
        _require_libp2p()
        self.manager = manager
        self.peer_id = str(peer_id).strip()
        self.addrs = [str(a).strip() for a in addrs if str(a).strip()]
        self.relay_addrs = [str(a).strip() for a in relay_addrs if str(a).strip()]
        self.owns_manager = bool(owns_manager)
        self.timeout = float(timeout)
        self.endpoint_uri = f"libp2p://{self.peer_id}"
        self.host = "libp2p"
        self.port = 0
        self.bytes_sent = 0
        self.bytes_received = 0
        self.blob_bytes_sent = 0
        self.round_trips = 0
        self.tls_handshakes = 0
        self.put_count = 0
        self.get_count = 0

    def start(self) -> "Libp2pPeerClient":
        self.manager.start()
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
    def session(self) -> Iterator["Libp2pPeerClient"]:
        self.start()
        yield self

    def list_chunks(self, offset: int = 0, limit: int = 4096) -> Tuple[int, List[str]]:
        """Return ``(total_count, page_of_wire_ids)`` from the remote peer."""
        safe_offset = max(0, int(offset))
        safe_limit = max(1, min(MAX_BATCH_ITEMS, int(limit)))
        body = self.manager.request_peer(
            self.peer_id,
            self.addrs,
            b"L",
            [f"{safe_offset}:{safe_limit}"],
            relay_addrs=self.relay_addrs,
            timeout=self.timeout,
        )
        if not body or body[:1] != b"O" or len(body) < 9:
            raise ChunkIntegrityError("Invalid libp2p LIST response")
        total, count = struct.unpack(">II", body[1:9])
        pos = 9
        out: List[str] = []
        for _ in range(count):
            if pos + 2 > len(body):
                raise ChunkIntegrityError("Truncated libp2p LIST response")
            n = struct.unpack(">H", body[pos : pos + 2])[0]
            pos += 2
            if pos + n > len(body):
                raise ChunkIntegrityError("Truncated libp2p LIST entry")
            out.append(body[pos : pos + n].decode("utf-8"))
            pos += n
        self.round_trips += 1
        return total, out

    def batch_has(self, wire_ids: Sequence[str]) -> Dict[str, bool]:
        unique = list(dict.fromkeys(wire_ids))
        body = self.manager.request_peer(
            self.peer_id,
            self.addrs,
            b"H",
            unique,
            relay_addrs=self.relay_addrs,
            timeout=self.timeout,
        )
        if not body or body[:1] != b"O" or len(body) != 1 + len(unique):
            raise ChunkIntegrityError("Invalid libp2p HAS response")
        self.round_trips += 1
        return {wid: body[i + 1] == 1 for i, wid in enumerate(unique)}

    def batch_get(self, wire_ids: Sequence[str]) -> Dict[str, bytes]:
        unique = list(dict.fromkeys(wire_ids))
        if not unique:
            return {}
        body = self.manager.request_peer(
            self.peer_id,
            self.addrs,
            b"G",
            unique,
            relay_addrs=self.relay_addrs,
            timeout=self.timeout,
        )
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
        if self.owns_manager:
            self.manager.close()


class Libp2pChunkClient:
    """libp2p/QUIC peer から chunk を取得する読み取り専用クライアント。"""

    def __init__(self, peers: Sequence[str], *, psk: Optional[str] = None, manager: Optional[Libp2pHostManager] = None):
        _require_libp2p()
        self.peers = [str(p) for p in peers if str(p).strip()]
        if not self.peers:
            raise ValueError("At least one libp2p peer is required")
        self.psk = psk
        self._owns_manager = manager is None
        self._manager = manager or Libp2pHostManager(
            listen=["/ip4/127.0.0.1/udp/0/quic-v1", "/ip4/127.0.0.1/tcp/0"],
            psk=psk,
            enable_dht=False,
            enable_relay=False,
            enable_dcutr=False,
        )
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
        self._manager.start()
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
        last_error: Optional[BaseException] = None
        for peer in self.peers:
            try:
                pid = _extract_peer_id(peer)
                return self._manager.request_peer(pid, [peer], op, wire_ids)
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
        if self._owns_manager and self._manager is not None:
            self._manager.close()


def _peer_info(value: str) -> Any:
    maddr = Multiaddr(value)
    peer_id = maddr.value_for_protocol("p2p")
    if not peer_id:
        raise ServiceUnavailableError(f"libp2p multiaddr has no /p2p id: {value}")
    return PeerInfo(ID.from_base58(peer_id), [maddr])


def sync_from_peer(
    manager: Libp2pHostManager,
    store: Any,
    peer_id: str,
    addrs: Sequence[str],
    *,
    relay_addrs: Sequence[str] = (),
    batch_size: int = 4,
    timeout: float = 30.0,
) -> Dict[str, int]:
    """Pull all missing encrypted chunks from *peer_id* into *store* via libp2p."""
    client = Libp2pPeerClient(
        manager,
        peer_id,
        addrs,
        relay_addrs=relay_addrs,
        owns_manager=False,
        timeout=timeout,
    )
    remote_wids: List[str] = []
    offset = 0
    total = 0
    while True:
        total, page = client.list_chunks(offset=offset, limit=4096)
        if not page:
            break
        remote_wids.extend(page)
        offset += len(page)
        if offset >= total:
            break
    missing = [wid for wid in remote_wids if not _store_contains(store, wid)]
    fetched = 0
    fetched_bytes = 0
    step = max(1, int(batch_size))
    for i in range(0, len(missing), step):
        batch = missing[i : i + step]
        blobs = client.batch_get(batch)
        for wid, blob in blobs.items():
            if _store_put(store, wid, blob):
                fetched += 1
                fetched_bytes += len(blob)
    return {
        "remote_total": total,
        "missing": len(missing),
        "fetched": fetched,
        "bytes": fetched_bytes,
    }


def _adapt_batch_size(current: int, elapsed_s: float, *, failed: bool = False, max_step: int = 16) -> int:
    """直近のバッチ取得所要時間・成否に応じて次回バッチサイズを動的調整する。"""
    if failed:
        return max(1, current // 2)
    if elapsed_s < 0.4 and current < max_step:
        return min(max_step, current * 2)
    if elapsed_s > 2.5 and current > 1:
        return max(1, current // 2)
    return current


def sync_from_peers(
    manager: Libp2pHostManager,
    store: Any,
    peers: Sequence[Tuple[str, Sequence[str]]],
    *,
    relay_addrs: Optional[Sequence[str]] = None,
    batch_size: int = 4,
    timeout: float = 30.0,
    streams_per_peer: Optional[int] = None,
    peer_provider: Optional[Callable[[], Sequence[Tuple[str, Sequence[str]]]]] = None,
    refresh_interval: float = 5.0,
    adaptive_batch: bool = True,
) -> Dict[str, Any]:
    """Pull missing encrypted chunks in parallel across multiple *peers* via libp2p."""
    if streams_per_peer is None:
        raw_streams = os.environ.get("DFS_P2P_STREAMS_PER_PEER", "2").strip()
        try:
            streams_per_peer = max(1, min(4, int(raw_streams)))
        except ValueError:
            streams_per_peer = 2
    else:
        streams_per_peer = max(1, min(4, int(streams_per_peer)))

    merged: Dict[str, List[str]] = {}
    for raw_pid, raw_addrs in peers:
        pid = str(raw_pid or "").strip()
        if not pid or pid == manager.peer_id:
            continue
        cur = merged.setdefault(pid, [])
        for a in raw_addrs or ():
            s = str(a).strip()
            if s and s not in cur:
                cur.append(s)

    if not merged:
        return {"remote_total": 0, "missing": 0, "fetched": 0, "bytes": 0, "per_peer": {}}

    if len(merged) == 1 and streams_per_peer <= 1 and peer_provider is None:
        pid, addrs = next(iter(merged.items()))
        stats = sync_from_peer(
            manager,
            store,
            pid,
            addrs,
            relay_addrs=relay_addrs,
            batch_size=batch_size,
            timeout=timeout,
        )
        per_peer = {pid: stats["fetched"]} if stats.get("fetched", 0) > 0 else {}
        return {**stats, "per_peer": per_peer}

    def _probe_peer(item: Tuple[str, List[str]]) -> Optional[Tuple[str, Libp2pPeerClient, Set[str], List[str]]]:
        pid, addrs = item
        client = Libp2pPeerClient(
            manager,
            pid,
            addrs,
            relay_addrs=relay_addrs or (),
            owns_manager=False,
            timeout=timeout,
        )
        wids: List[str] = []
        offset = 0
        try:
            while True:
                total, page = client.list_chunks(offset=offset, limit=4096)
                if not page:
                    break
                wids.extend(page)
                offset += len(page)
                if offset >= total:
                    break
        except Exception:
            return None
        if not wids:
            return None
        return pid, client, set(wids), wids

    active_peers_map: Dict[str, Tuple[Libp2pPeerClient, Set[str]]] = {}
    all_wids_ordered: Dict[str, None] = {}
    remaining: Dict[str, None] = {}
    inflight: Dict[str, int] = {}
    completed: Set[str] = set()
    missing_total = 0
    lock = threading.Lock()
    step = max(1, int(batch_size))
    fetched = 0
    fetched_bytes = 0
    per_peer: Dict[str, int] = {}
    write_sem = threading.Semaphore(8)
    write_futs: List[Any] = []
    writer_pool = ThreadPoolExecutor(max_workers=2)
    rng = random.Random()

    def _register_probe_result(
        res: Optional[Tuple[str, Libp2pPeerClient, Set[str], List[str]]],
    ) -> Optional[str]:
        nonlocal missing_total
        if res is None:
            return None
        pid, client, wid_set, wid_list = res
        new_missing: List[str] = []
        with lock:
            if pid in active_peers_map:
                return None
            active_peers_map[pid] = (client, wid_set)
            for wid in wid_list:
                is_new = wid not in all_wids_ordered
                all_wids_ordered.setdefault(wid, None)
                if is_new and wid not in completed and not _store_contains(store, wid):
                    new_missing.append(wid)
            if new_missing:
                missing_total += len(new_missing)
                new_missing.sort(
                    key=lambda w: (
                        sum(1 for _, (_, ws) in active_peers_map.items() if w in ws),
                        rng.random(),
                    )
                )
                for w in new_missing:
                    remaining.setdefault(w, None)
            elif remaining:
                # Re-sort remaining with updated rarest-first counts
                cur_rem = list(remaining)
                cur_rem.sort(
                    key=lambda w: (
                        sum(1 for _, (_, ws) in active_peers_map.items() if w in ws),
                        rng.random(),
                    )
                )
                remaining.clear()
                for w in cur_rem:
                    remaining[w] = None
        return pid

    def _persist_batch(
        pid: str,
        batch: List[str],
        blobs: Dict[str, bytes],
        is_endgame: bool,
    ) -> None:
        nonlocal fetched, fetched_bytes
        try:
            newly_put: List[Tuple[str, int]] = []
            for wid, blob in blobs.items():
                with lock:
                    already = wid in completed
                if already:
                    continue
                if _store_put(store, wid, blob):
                    newly_put.append((wid, len(blob)))
            with lock:
                for wid in batch:
                    cnt = inflight.get(wid, 0)
                    if cnt <= 1:
                        inflight.pop(wid, None)
                    else:
                        inflight[wid] = cnt - 1
                for wid, blen in newly_put:
                    if wid not in completed:
                        completed.add(wid)
                        fetched += 1
                        fetched_bytes += blen
                        per_peer[pid] = per_peer.get(pid, 0) + 1
                for wid in batch:
                    if wid not in completed and not _store_contains(store, wid):
                        if not is_endgame:
                            remaining.setdefault(wid, None)
        finally:
            write_sem.release()

    def _worker(pid: str) -> None:
        with lock:
            entry = active_peers_map.get(pid)
        if entry is None:
            return
        client, wid_set = entry
        consec_err = 0
        cur_step = step
        tried_endgame: Set[str] = set()
        while True:
            batch: List[str] = []
            is_endgame = False
            with lock:
                for wid in list(remaining):
                    if wid in wid_set and wid not in completed:
                        remaining.pop(wid, None)
                        inflight[wid] = inflight.get(wid, 0) + 1
                        batch.append(wid)
                        if len(batch) >= cur_step:
                            break
                if not batch and not remaining and inflight:
                    for wid, dup_cnt in list(inflight.items()):
                        if (
                            wid in wid_set
                            and wid not in completed
                            and wid not in tried_endgame
                            and dup_cnt < 2
                        ):
                            inflight[wid] = dup_cnt + 1
                            tried_endgame.add(wid)
                            batch.append(wid)
                            is_endgame = True
                            if len(batch) >= cur_step:
                                break
            if not batch:
                return
            t_req = time.monotonic()
            try:
                blobs = client.batch_get(batch)
            except Exception:
                if adaptive_batch:
                    cur_step = _adapt_batch_size(cur_step, time.monotonic() - t_req, failed=True)
                with lock:
                    for wid in batch:
                        cnt = inflight.get(wid, 0)
                        if cnt <= 1:
                            inflight.pop(wid, None)
                        else:
                            inflight[wid] = cnt - 1
                        if not is_endgame and wid not in completed and not _store_contains(store, wid):
                            remaining.setdefault(wid, None)
                consec_err += 1
                if consec_err >= 2:
                    return
                continue

            if adaptive_batch:
                cur_step = _adapt_batch_size(cur_step, time.monotonic() - t_req, failed=False)
            consec_err = 0
            write_sem.acquire()
            wf = writer_pool.submit(_persist_batch, pid, batch, blobs, is_endgame)
            with lock:
                write_futs.append(wf)

    probe_pool = ThreadPoolExecutor(max_workers=min(8, len(merged)))
    probe_futs = {probe_pool.submit(_probe_peer, item) for item in merged.items()}
    done_probes, pending_probes = futures_wait(probe_futs, return_when=FIRST_COMPLETED)
    if pending_probes:
        more_done, pending_probes = futures_wait(pending_probes, timeout=0.15)
        done_probes = done_probes | more_done

    with ThreadPoolExecutor(max_workers=16) as pool:
        futs: List[Any] = []
        ready_pids: List[str] = []
        for pf in done_probes:
            try:
                pid = _register_probe_result(pf.result())
            except Exception:
                pid = None
            if pid is not None:
                ready_pids.append(pid)
        for pid in ready_pids:
            for _ in range(streams_per_peer):
                futs.append(pool.submit(_worker, pid))

        last_refresh = time.monotonic()
        interval = max(0.2, float(refresh_interval))
        while pending_probes or any(not f.done() for f in futs):
            if pending_probes:
                more_done, pending_probes = futures_wait(pending_probes, timeout=0.1)
                for pf in more_done:
                    try:
                        pid = _register_probe_result(pf.result())
                    except Exception:
                        pid = None
                    if pid is not None:
                        for _ in range(streams_per_peer):
                            futs.append(pool.submit(_worker, pid))
            else:
                time.sleep(0.1)

            if peer_provider is not None and time.monotonic() - last_refresh >= interval:
                last_refresh = time.monotonic()
                with lock:
                    done_all = not pending_probes and not remaining and not inflight
                if done_all:
                    break
                try:
                    new_specs = peer_provider() or ()
                except Exception:
                    new_specs = ()
                for raw_pid, raw_addrs in new_specs:
                    npid = str(raw_pid or "").strip()
                    if not npid or npid == manager.peer_id:
                        continue
                    with lock:
                        already_active = npid in active_peers_map
                    if already_active:
                        continue
                    res = _probe_peer((npid, [str(a).strip() for a in (raw_addrs or ()) if str(a).strip()]))
                    pid = _register_probe_result(res)
                    if pid is not None:
                        for _ in range(streams_per_peer):
                            futs.append(pool.submit(_worker, pid))
        for f in futs:
            f.result()
    probe_pool.shutdown(wait=False)
    for wf in write_futs:
        wf.result()
    writer_pool.shutdown(wait=True)

    return {
        "remote_total": len(all_wids_ordered),
        "missing": missing_total,
        "fetched": fetched,
        "bytes": fetched_bytes,
        "per_peer": per_peer,
    }


def _main() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        prog="python -m dfs.libp2p_chunk",
        description="Serve a dfs chunk directory over libp2p/QUIC",
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
