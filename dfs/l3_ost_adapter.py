#!/usr/bin/env python3
"""
dfs/l3_ost_adapter.py
macOS / Linux 両対応・デッドロック完全排除版 L3 OST サーバ & クライアント。
明示的切断オペコード ('Q') により、サーバ側の recv ブロッキング待ちを確実に終了させる。
"""

from __future__ import annotations

import ctypes
import ctypes.util
import http.client
import json
import os
import shutil
import socket
import ssl
import struct
import sys
import tempfile
import threading
import time
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import ExitStack, contextmanager
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Sequence, Tuple, Union, Protocol
from urllib.parse import urlsplit, urlunsplit

from .crypto import ChunkIntegrityError, sha256_hex
from .l2_registry import ServiceUnavailableError


class OSTClientProtocol(Protocol):
    """L3 OST client protocol definition.
    
    Common interface implemented by OSTClient, HttpOSTClient, 
    FailoverOSTClient, SwarmOSTClient.
    """
    
    @property
    def endpoint_uri(self) -> str: ...
    
    @property
    def host(self) -> str: ...
    
    @property
    def port(self) -> int: ...
    
    @property
    def expected_cert_sha256(self) -> Optional[str]: ...
    
    @property
    def bytes_sent(self) -> int: ...
    
    @property
    def bytes_received(self) -> int: ...
    
    @property
    def blob_bytes_sent(self) -> int: ...
    
    @property
    def put_count(self) -> int: ...
    
    @property
    def get_count(self) -> int: ...
    
    @property
    def tls_handshakes(self) -> int: ...
    
    @property
    def round_trips(self) -> int: ...
    
    @property
    def last_overloaded(self) -> bool: ...
    
    def probe(self, timeout: Optional[float] = None) -> float: ...
    
    def reset_metrics(self) -> None: ...
    
    def batch_has(self, wire_ids: Sequence[str]) -> Dict[str, bool]: ...
    
    def batch_put_if_absent(self, chunks: Dict[str, bytes], assume_absent: bool = False) -> int: ...
    
    def batch_get(self, wire_ids: Sequence[str]) -> Dict[str, bytes]: ...
    
    def put_if_absent(self, wire_id: str, blob: bytes) -> bool: ...
    
    def close(self) -> None: ...
    
    @contextmanager
    def session(self) -> Iterator["OSTClientProtocol"]: ...

ZERO_WIRE_ID = b"0" * 64
QUIT_FRAME = b"Q" + ZERO_WIRE_ID + struct.pack(">I", 0)
WIRE_ID_HEX = frozenset(b"0123456789abcdef")
VALID_OPCODES = frozenset(b"HGPBMFQ")


class OSTProtocolError(Exception):
    """DFS の L3 フレームではないデータを受け取った。"""


def _decode_wire_id(raw: bytes) -> str:
    if len(raw) != 64 or any(ch not in WIRE_ID_HEX for ch in raw):
        raise OSTProtocolError("invalid wire_id")
    return raw.decode("ascii")


def _get_available_memory_bytes() -> Optional[int]:
    """OS の空きメモリ（バイト数）を取得する。取得できない場合は None。"""
    try:
        if sys.platform.startswith("linux"):
            meminfo: Dict[str, int] = {}
            with open("/proc/meminfo", "r", encoding="utf-8") as fh:
                for line in fh:
                    if ":" not in line:
                        continue
                    key, rest = line.split(":", 1)
                    parts = rest.strip().split()
                    if parts and parts[0].isdigit():
                        meminfo[key] = int(parts[0]) * 1024
            if "MemAvailable" in meminfo:
                return meminfo["MemAvailable"]
            if "MemFree" in meminfo:
                return (
                    meminfo["MemFree"]
                    + meminfo.get("Buffers", 0)
                    + meminfo.get("Cached", 0)
                )
        elif sys.platform == "darwin":
            libc_path = ctypes.util.find_library("c")
            if not libc_path:
                return None
            libc = ctypes.CDLL(libc_path)

            class _VMStats64(ctypes.Structure):
                _fields_ = [
                    ("free_count", ctypes.c_uint32),
                    ("active_count", ctypes.c_uint32),
                    ("inactive_count", ctypes.c_uint32),
                    ("wire_count", ctypes.c_uint32),
                    ("zero_fill_count", ctypes.c_uint64),
                    ("reactivations", ctypes.c_uint64),
                    ("pageins", ctypes.c_uint64),
                    ("pageouts", ctypes.c_uint64),
                    ("faults", ctypes.c_uint64),
                    ("cow_faults", ctypes.c_uint64),
                    ("lookups", ctypes.c_uint64),
                    ("hits", ctypes.c_uint64),
                    ("purges", ctypes.c_uint64),
                    ("purgeable_count", ctypes.c_uint32),
                    ("speculative_count", ctypes.c_uint32),
                    ("decompressions", ctypes.c_uint64),
                    ("compressions", ctypes.c_uint64),
                    ("swapins", ctypes.c_uint64),
                    ("swapouts", ctypes.c_uint64),
                    ("compressor_page_count", ctypes.c_uint32),
                    ("throttled_count", ctypes.c_uint32),
                    ("external_page_count", ctypes.c_uint32),
                    ("internal_page_count", ctypes.c_uint32),
                    ("total_uncompressed_pages_in_compressor", ctypes.c_uint64),
                ]

            stats = _VMStats64()
            count = ctypes.c_uint32(ctypes.sizeof(_VMStats64) // 4)
            if libc.host_statistics64(libc.mach_host_self(), 4, ctypes.byref(stats), ctypes.byref(count)) == 0:
                psize = os.sysconf("SC_PAGE_SIZE")
                return int(stats.free_count + stats.inactive_count + stats.purgeable_count) * int(psize)
        elif os.name == "nt":
            class _MemoryStatusEx(ctypes.Structure):
                _fields_ = [
                    ("dwLength", ctypes.c_uint32),
                    ("dwMemoryLoad", ctypes.c_uint32),
                    ("ullTotalPhys", ctypes.c_uint64),
                    ("ullAvailPhys", ctypes.c_uint64),
                    ("ullTotalPageFile", ctypes.c_uint64),
                    ("ullAvailPageFile", ctypes.c_uint64),
                    ("ullTotalVirtual", ctypes.c_uint64),
                    ("ullAvailVirtual", ctypes.c_uint64),
                    ("ullAvailExtendedVirtual", ctypes.c_uint64),
                ]

            status = _MemoryStatusEx()
            status.dwLength = ctypes.sizeof(_MemoryStatusEx)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):  # type: ignore[attr-defined]
                return int(status.ullAvailPhys)
    except Exception:
        return None
    return None


def _default_ost_max_ram_bytes(chunks_dir: Optional[Path]) -> int:
    """OST RAM キャッシュ上限を空きメモリに応じて安全に決定する。"""
    raw = os.environ.get("DFS_OST_MAX_RAM_BYTES", "").strip()
    if raw:
        try:
            return max(0, int(raw))
        except ValueError:
            pass
    avail = _get_available_memory_bytes()
    if chunks_dir is not None:
        if avail is None or avail <= 0:
            return 16 * 1024 * 1024
        if avail < 256 * 1024 * 1024:
            return 0
        return min(64 * 1024 * 1024, avail // 16)
    if avail is None or avail <= 0:
        return 256 * 1024 * 1024
    return max(16 * 1024 * 1024, min(256 * 1024 * 1024, avail // 4))


def _is_tmpfs_path(path: Path) -> bool:
    """Linux の /proc/mounts から指定パスが tmpfs / ramfs 上にあるか判定する。"""
    if not sys.platform.startswith("linux"):
        return False
    try:
        resolved = str(path.resolve())
        best_mount = ""
        best_fstype = ""
        with open("/proc/mounts", "r", encoding="utf-8") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) < 3:
                    continue
                mnt, fstype = parts[1], parts[2]
                if resolved == mnt or (mnt == "/" and resolved.startswith("/")) or resolved.startswith(mnt.rstrip("/") + "/"):
                    if len(mnt) > len(best_mount):
                        best_mount = mnt
                        best_fstype = fstype
        return best_fstype in ("tmpfs", "ramfs")
    except OSError:
        return False


def check_storage_health(
    path: Path, min_free_bytes: int = 64 * 1024 * 1024
) -> Dict[str, Any]:
    """指定ディレクトリの空き容量と tmpfs 判定を返す。"""
    usage = shutil.disk_usage(str(path))
    is_tmpfs = _is_tmpfs_path(path)
    return {
        "path": str(path),
        "free_bytes": int(usage.free),
        "total_bytes": int(usage.total),
        "is_tmpfs": is_tmpfs,
        "low_space": int(usage.free) < max(0, int(min_free_bytes)),
    }


def _decode_wire_ids(raw: bytes, count: int) -> List[str]:
    if len(raw) != count * 64:
        raise OSTProtocolError("invalid wire_id batch length")
    return [_decode_wire_id(raw[i * 64 : (i + 1) * 64]) for i in range(count)]

# 1 フレームで受け付ける上限。クライアント側の実装（batch_has / batch_put /
# batch_get）は十分小さい単位に分割しているので、通常運用では引っかからない。
MAX_BATCH_ITEMS = 65_536
MAX_BLOB_BYTES = 256 * 1024 * 1024
MAX_OST_HTTP_BODY_BYTES = MAX_BLOB_BYTES + 4 * 1024 * 1024
# クライアント側ではサーバ上限より小さく区切り、1 回の送受信が
# メモリ上で無制限に膨らまないようにする。
CLIENT_BATCH_ITEMS = 1024
CLIENT_BATCH_BYTES = 64 * 1024 * 1024


def parse_ost_endpoint(value: str) -> Tuple[str, int, str]:
    """OST エンドポイントを ``(host, port, canonical_endpoint)`` に正規化する。

    ``http://`` / ``https://`` は HTTP 経由の OST としてスキームとパスを保持し、
    ``tls://host:port`` や ``host:port`` は ``tls://host:port`` に揃える。
    """
    text = str(value).strip()
    if text.startswith("http://") or text.startswith("https://"):
        parts = urlsplit(text)
        if not parts.hostname:
            raise ValueError(f"Invalid OST endpoint: {value!r}")
        host = parts.hostname
        port = parts.port or (443 if parts.scheme == "https" else 80)
        host_fmt = f"[{host}]" if ":" in host and not host.startswith("[") else host
        netloc = f"{host_fmt}:{parts.port}" if parts.port is not None else host_fmt
        canonical = urlunsplit((parts.scheme, netloc, parts.path.rstrip("/"), "", ""))
        return host, int(port), canonical
    if text.startswith("tls://"):
        text = text[len("tls://"):]
    host, sep, port_text = text.rpartition(":")
    if not sep or not host or not port_text.isdigit():
        raise ValueError(f"Invalid OST endpoint: {value!r}")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    port = int(port_text)
    host_fmt = f"[{host}]" if ":" in host and not host.startswith("[") else host
    return host, port, f"tls://{host_fmt}:{port}"


def _group_put_chunks(chunks: Dict[str, bytes], missing_ids: Sequence[str]) -> List[List[str]]:
    """PUT 対象チャンクを ``CLIENT_BATCH_ITEMS`` / ``CLIENT_BATCH_BYTES`` で分割する。"""
    groups: List[List[str]] = []
    group: List[str] = []
    group_bytes = 0
    for wid in missing_ids:
        blob = chunks[wid]
        if len(blob) > MAX_BLOB_BYTES:
            raise ChunkIntegrityError(
                f"Chunk {wid[:12]}... exceeds L3 limit: {len(blob)} > {MAX_BLOB_BYTES}"
            )
        encoded_size = 68 + len(blob)
        if group and (
            len(group) >= CLIENT_BATCH_ITEMS
            or group_bytes + encoded_size > CLIENT_BATCH_BYTES
        ):
            groups.append(group)
            group = []
            group_bytes = 0
        group.append(wid)
        group_bytes += encoded_size
    if group:
        groups.append(group)
    return groups


# ---------------------------------------------------------------------------
# WAN（高遅延）向けタイムアウト。環境変数で上書きできる。
#   DFS_OST_SOCKET_TIMEOUT  : サーバ側ソケットの 1 操作あたりのタイムアウト秒
#   DFS_OST_CONNECT_TIMEOUT : クライアント側の TCP 接続タイムアウト秒
# 既定はどちらも WAN（RTT 300ms 級）の直列処理に耐える値にしてある。
# ---------------------------------------------------------------------------
DEFAULT_OST_SOCKET_TIMEOUT = 30.0
DEFAULT_OST_CONNECT_TIMEOUT = 10.0
DEFAULT_PROBE_TIMEOUT = 1.5
DEFAULT_TRANSPORT_CACHE_TTL = 300.0


def ost_probe_timeout() -> float:
    """適応プローブの接続タイムアウト秒（既定 1.5 秒、``DFS_PROBE_TIMEOUT`` で変更）"""
    return _env_positive_float("DFS_PROBE_TIMEOUT", DEFAULT_PROBE_TIMEOUT)


def _env_positive_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        value = float(raw)
    except ValueError:
        return default
    return value if value > 0 else default


def ost_socket_timeout() -> float:
    """サーバ側ソケットタイムアウト秒（既定 30 秒、``DFS_OST_SOCKET_TIMEOUT`` で変更）"""
    return _env_positive_float("DFS_OST_SOCKET_TIMEOUT", DEFAULT_OST_SOCKET_TIMEOUT)


def ost_connect_timeout() -> float:
    """クライアント側 TCP 接続タイムアウト秒（既定 10 秒、``DFS_OST_CONNECT_TIMEOUT`` で変更）"""
    return _env_positive_float("DFS_OST_CONNECT_TIMEOUT", DEFAULT_OST_CONNECT_TIMEOUT)


class ChunkStoreServer:
    """
    内容アドレス (wire_id) でチャンクを保管する TLS/TCP サーバ (L3 OST)。

    DFS が自前で実装したものであり、mini_lustre の OST とは
    フレーム形式も塊の識別子も異なる（同一のポート上で TLS/TCP を使う点のみ共通）。

    クライアントごとのソケットタイムアウトは ``DFS_OST_SOCKET_TIMEOUT``（既定 30 秒）で
    上書きできる。WAN では 1 往復が数百 ms になるため、LAN 時代の 2 秒固定から引き上げた。
    """

    def __init__(
        self,
        certfile: Path | str,
        keyfile: Path | str,
        host: str = "127.0.0.1",
        port: int = 0,
        *,
        chunks_dir: Optional[Path | str] = None,
        max_store_bytes: Optional[int] = None,
        max_ram_bytes: Optional[int] = None,
        chunk_ttl_seconds: Optional[float] = None,
        evict_on_full: Optional[bool] = None,
    ):
        self.store: Dict[str, bytes] = OrderedDict()
        self._dirty_wire_ids: set[str] = set()
        self._store_lock = threading.RLock()
        self._put_cond = threading.Condition(self._store_lock)
        self._reserved_bytes: int = 0
        self._inflight_puts: set[str] = set()
        self.chunks_dir: Optional[Path] = (
            Path(chunks_dir).expanduser() if chunks_dir else None
        )
        if self.chunks_dir is not None:
            self.chunks_dir.mkdir(parents=True, exist_ok=True)
        env_min_free = os.environ.get("DFS_OST_MIN_FREE_BYTES", "").strip()
        self._storage_min_free_bytes: int = (
            max(0, int(env_min_free)) if env_min_free else 16 * 1024 * 1024
        )
        if self.chunks_dir is not None:
            try:
                health = check_storage_health(
                    self.chunks_dir,
                    min_free_bytes=max(self._storage_min_free_bytes, 64 * 1024 * 1024),
                )
                if health["is_tmpfs"]:
                    print(
                        f"[dfs ost] WARNING: chunks_dir {self.chunks_dir} is on tmpfs (RAM-backed); "
                        f"free={health['free_bytes'] // (1024 * 1024)} MiB",
                        file=sys.stderr,
                        flush=True,
                    )
                elif health["low_space"]:
                    print(
                        f"[dfs ost] WARNING: low disk space on {self.chunks_dir}: "
                        f"free={health['free_bytes'] // (1024 * 1024)} MiB",
                        file=sys.stderr,
                        flush=True,
                    )
            except OSError:
                pass
        env_max_store = os.environ.get("DFS_OST_MAX_BYTES", "").strip()
        self.max_store_bytes: Optional[int] = (
            max_store_bytes
            if max_store_bytes is not None
            else (int(env_max_store) if env_max_store else None)
        )
        self._explicit_max_ram_bytes: bool = (
            max_ram_bytes is not None
            or bool(os.environ.get("DFS_OST_MAX_RAM_BYTES", "").strip())
        )
        self.max_ram_bytes: int = (
            max(0, max_ram_bytes)
            if max_ram_bytes is not None
            else _default_ost_max_ram_bytes(self.chunks_dir)
        )
        self._last_mem_check: float = 0.0
        env_ttl = os.environ.get("DFS_OST_CHUNK_TTL", "").strip()
        self.chunk_ttl_seconds: Optional[float] = (
            float(chunk_ttl_seconds)
            if chunk_ttl_seconds is not None
            else (float(env_ttl) if env_ttl else None)
        )
        env_evict = os.environ.get("DFS_OST_EVICT_ON_FULL", "").strip()
        self.evict_on_full: bool = (
            bool(evict_on_full)
            if evict_on_full is not None
            else (env_evict == "1")
        )
        self._ram_bytes: int = 0
        self._disk_bytes: int = 0
        if self.chunks_dir is not None:
            self._disk_bytes = sum(
                p.stat().st_size for p in self.chunks_dir.glob("*.blk") if p.is_file()
            )
        max_conns = max(1, int(os.environ.get("DFS_OST_MAX_CONNS", "64")))
        self._conn_sem = threading.BoundedSemaphore(max_conns)
        self.online: bool = True
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(certfile=str(certfile), keyfile=str(keyfile))
        self.cert_sha256: str = ""
        try:
            pem_text = Path(certfile).read_text(encoding="utf-8")
            der = ssl.PEM_cert_to_DER_cert(pem_text)
            self.cert_sha256 = sha256_hex(der)
        except (OSError, ValueError):
            self.cert_sha256 = ""

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host, port))
        self.sock.listen(32)
        self.host, self.port = self.sock.getsockname()
        self.running = True
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()

    @property
    def endpoint_uri(self) -> str:
        return f"tls://{self.host}:{self.port}"

    def _gc_ram_locked(
        self,
        *,
        now: float,
        max_bytes: Optional[int],
        ttl_seconds: Optional[float],
    ) -> Tuple[int, int]:
        """RAM ストアを FIFO/LRU 順でサイズ上限まで解放する（ロック保持下で呼ぶ）。"""
        evicted = 0
        freed = 0
        if max_bytes is not None and max_bytes >= 0:
            while self.store and self._ram_bytes > max_bytes:
                _wid, old_blob = self.store.popitem(last=False)
                self._ram_bytes -= len(old_blob)
                evicted += 1
                freed += len(old_blob)
        return evicted, freed

    def _gc_disk_locked(
        self,
        *,
        now: float,
        max_bytes: Optional[int],
        ttl_seconds: Optional[float],
    ) -> Tuple[int, int]:
        """ディスク上の .blk チャンクを TTL 超過 → 古い順（mtime 昇順）で削除する。"""
        if self.chunks_dir is None:
            return 0, 0
        entries: List[Tuple[float, int, str, Path]] = []
        total_disk = 0
        for p in self.chunks_dir.glob("*.blk"):
            if not p.is_file():
                continue
            try:
                st = p.stat()
            except OSError:
                continue
            wid = p.stem
            if wid in self._inflight_puts:
                continue
            total_disk += st.st_size
            entries.append((st.st_mtime, st.st_size, wid, p))
        self._disk_bytes = total_disk

        evicted = 0
        freed = 0
        remaining: List[Tuple[float, int, str, Path]] = []
        if ttl_seconds is not None and ttl_seconds > 0:
            cutoff = now - ttl_seconds
            for mtime, size, wid, p in entries:
                if mtime < cutoff:
                    try:
                        p.unlink()
                    except OSError:
                        remaining.append((mtime, size, wid, p))
                        continue
                    self._disk_bytes = max(0, self._disk_bytes - size)
                    old = self.store.pop(wid, None)
                    if old is not None:
                        self._ram_bytes -= len(old)
                    evicted += 1
                    freed += size
                else:
                    remaining.append((mtime, size, wid, p))
        else:
            remaining = entries

        if max_bytes is not None and max_bytes >= 0 and self._disk_bytes > max_bytes:
            remaining.sort(key=lambda item: item[0])
            for _mtime, size, wid, p in remaining:
                if self._disk_bytes <= max_bytes:
                    break
                try:
                    p.unlink()
                except OSError:
                    continue
                self._disk_bytes = max(0, self._disk_bytes - size)
                old = self.store.pop(wid, None)
                if old is not None:
                    self._ram_bytes -= len(old)
                evicted += 1
                freed += size
        return evicted, freed

    def gc(
        self,
        *,
        now: Optional[float] = None,
        max_bytes: Optional[int] = None,
        ttl_seconds: Optional[float] = None,
    ) -> Dict[str, int]:
        """TTL 超過およびサイズ上限超過のチャンクを回収する。"""
        ts = time.time() if now is None else float(now)
        eff_max = self.max_store_bytes if max_bytes is None else max_bytes
        eff_ttl = self.chunk_ttl_seconds if ttl_seconds is None else ttl_seconds
        with self._store_lock:
            if self.chunks_dir is None:
                evicted, freed = self._gc_ram_locked(
                    now=ts, max_bytes=eff_max, ttl_seconds=eff_ttl
                )
            else:
                evicted, freed = self._gc_disk_locked(
                    now=ts, max_bytes=eff_max, ttl_seconds=eff_ttl
                )
        return {"evicted": evicted, "freed_bytes": freed}

    def _accept_loop(self) -> None:
        while self.running:
            try:
                conn, _ = self.sock.accept()
                if not self._conn_sem.acquire(blocking=False):
                    try:
                        conn.close()
                    except Exception:
                        pass
                    continue
                try:
                    conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    conn.settimeout(ost_socket_timeout())
                    threading.Thread(
                        target=self._handle_client_guarded, args=(conn,), daemon=True
                    ).start()
                except Exception:
                    try:
                        conn.close()
                    finally:
                        self._conn_sem.release()
                    raise
            except Exception:
                break

    def _handle_client_guarded(self, conn: socket.socket) -> None:
        try:
            self._handle_client(conn)
        finally:
            self._conn_sem.release()

    @staticmethod
    def _recv_exact(conn: ssl.SSLSocket, n: int) -> bytes:
        buf = bytearray()
        while len(buf) < n:
            chunk = conn.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("EOF")
            buf.extend(chunk)
        return bytes(buf)

    def _cache_ram(self, wid: str, blob: bytes) -> None:
        if self.chunks_dir is not None and not self._explicit_max_ram_bytes:
            now = time.monotonic()
            if now - self._last_mem_check >= 5.0:
                self._last_mem_check = now
                avail = _get_available_memory_bytes()
                if avail is not None and avail < 128 * 1024 * 1024:
                    self.store.clear()
                    self._ram_bytes = 0
                    return
        if wid in self.store:
            if isinstance(self.store, OrderedDict):
                self.store.move_to_end(wid)
            return
        if self.chunks_dir is not None and (
            self.max_ram_bytes <= 0 or len(blob) > self.max_ram_bytes
        ):
            return
        self.store[wid] = blob
        self._ram_bytes += len(blob)
        if self.chunks_dir is not None:
            while self._ram_bytes > self.max_ram_bytes and self.store:
                if isinstance(self.store, OrderedDict):
                    _old_wid, old_blob = self.store.popitem(last=False)
                else:
                    old_wid = next(iter(self.store))
                    old_blob = self.store.pop(old_wid)
                self._ram_bytes -= len(old_blob)

    def _chunk_size(self, wid: str) -> int:
        with self._store_lock:
            blob = self.store.get(wid)
            if blob is not None:
                return len(blob)
        if self.chunks_dir is not None:
            try:
                return (self.chunks_dir / f"{wid}.blk").stat().st_size
            except FileNotFoundError:
                return 0
        return 0

    def has_chunk(self, wid: str) -> bool:
        """Return whether *wid* is present in memory or on disk."""
        return self._has_chunk(wid)

    def get_chunk(self, wid: str) -> Optional[bytes]:
        """Return encrypted chunk bytes for *wid*, or ``None`` if absent."""
        return self._get_chunk(wid)

    def put_chunk(self, wid: str, blob: bytes) -> bool:
        """Store encrypted chunk bytes for *wid*."""
        return self._put_chunk(wid, blob)

    def list_chunks(self) -> List[str]:
        """Return sorted unique chunk ``wire_id`` values stored on this server."""
        with self._store_lock:
            ids = set(self.store.keys())
        if self.chunks_dir is not None:
            try:
                for p in self.chunks_dir.glob("*.blk"):
                    if p.is_file():
                        ids.add(p.stem)
            except OSError:
                pass
        return sorted(ids)

    def _has_chunk(self, wid: str) -> bool:
        with self._store_lock:
            if wid in self.store:
                return True
        if self.chunks_dir is not None:
            return (self.chunks_dir / f"{wid}.blk").is_file()
        return False

    def _get_chunk(self, wid: str) -> Optional[bytes]:
        with self._store_lock:
            blob = self.store.get(wid)
            if blob is not None:
                if isinstance(self.store, OrderedDict):
                    self.store.move_to_end(wid)
                return blob
        if self.chunks_dir is not None:
            p = self.chunks_dir / f"{wid}.blk"
            try:
                blob = p.read_bytes()
            except FileNotFoundError:
                return None
            with self._store_lock:
                self._cache_ram(wid, blob)
            return blob
        return None

    def _put_chunk(self, wid: str, blob: bytes) -> bool:
        if self.chunks_dir is None:
            with self._store_lock:
                if wid in self.store:
                    return True
                if self.max_store_bytes is not None and self._ram_bytes + len(blob) > self.max_store_bytes:
                    if self.evict_on_full or (self.chunk_ttl_seconds and self.chunk_ttl_seconds > 0):
                        target_cap = (
                            max(0, self.max_store_bytes - len(blob))
                            if self.evict_on_full
                            else self.max_store_bytes
                        )
                        self._gc_ram_locked(
                            now=time.time(),
                            max_bytes=target_cap if self.evict_on_full else None,
                            ttl_seconds=self.chunk_ttl_seconds,
                        )
                    if self._ram_bytes + len(blob) > self.max_store_bytes:
                        return False
                self.store[wid] = blob
                self._ram_bytes += len(blob)
                self._dirty_wire_ids.add(wid)
                return True

        dest = self.chunks_dir / f"{wid}.blk"
        with self._store_lock:
            while wid in self._inflight_puts:
                self._put_cond.wait()
            if wid in self.store:
                return True
            if dest.is_file():
                self._cache_ram(wid, blob)
                return True
            if self._storage_min_free_bytes > 0:
                try:
                    free_bytes = shutil.disk_usage(str(self.chunks_dir)).free
                    if free_bytes < len(blob) + self._storage_min_free_bytes:
                        return False
                except OSError:
                    pass
            if (
                self.max_store_bytes is not None
                and self._disk_bytes + self._reserved_bytes + len(blob) > self.max_store_bytes
            ):
                if self.evict_on_full or (self.chunk_ttl_seconds and self.chunk_ttl_seconds > 0):
                    target_cap = (
                        max(0, self.max_store_bytes - self._reserved_bytes - len(blob))
                        if self.evict_on_full
                        else self.max_store_bytes
                    )
                    self._gc_disk_locked(
                        now=time.time(),
                        max_bytes=target_cap if self.evict_on_full else None,
                        ttl_seconds=self.chunk_ttl_seconds,
                    )
                if self._disk_bytes + self._reserved_bytes + len(blob) > self.max_store_bytes:
                    return False
            self._reserved_bytes += len(blob)
            self._inflight_puts.add(wid)

        wrote_new = False
        try:
            if not dest.exists():
                fd, tmp_name = tempfile.mkstemp(
                    prefix=f".{wid}.", suffix=".tmp", dir=str(self.chunks_dir)
                )
                tmp = Path(tmp_name)
                try:
                    with os.fdopen(fd, "wb") as f:
                        f.write(blob)
                        f.flush()
                        os.fsync(f.fileno())
                    os.replace(tmp, dest)
                    try:
                        dir_fd = os.open(str(self.chunks_dir), os.O_RDONLY)
                        try:
                            os.fsync(dir_fd)
                        finally:
                            os.close(dir_fd)
                    except OSError:
                        pass
                    wrote_new = True
                finally:
                    try:
                        tmp.unlink()
                    except FileNotFoundError:
                        pass
            with self._store_lock:
                if wrote_new:
                    self._disk_bytes += len(blob)
                self._cache_ram(wid, blob)
            return True
        finally:
            with self._store_lock:
                self._reserved_bytes -= len(blob)
                self._inflight_puts.discard(wid)
                self._put_cond.notify_all()

    def _handle_client(self, raw_conn: socket.socket) -> None:
        ssl_conn: Optional[ssl.SSLSocket] = None
        try:
            ssl_conn = self.ctx.wrap_socket(raw_conn, server_side=True)
            while self.running:
                hdr = self._recv_exact(ssl_conn, 69)
                if hdr[0] not in VALID_OPCODES:
                    raise OSTProtocolError(f"unknown opcode: {hdr[0]:#04x}")
                op = chr(hdr[0])

                # クライアントからの明示的切断要求 ('Q') で即座にループを抜ける
                if op == "Q":
                    break

                if not self.online:
                    ssl_conn.sendall(b"U")
                    break

                wire_id = _decode_wire_id(hdr[1:65])
                val = struct.unpack(">I", hdr[65:69])[0]

                if op == "H":
                    exists = self._has_chunk(wire_id)
                    ssl_conn.sendall(b"1" if exists else b"0")
                elif op == "P":
                    if val > MAX_BLOB_BYTES:
                        ssl_conn.sendall(b"E")
                        break
                    data = self._recv_exact(ssl_conn, val)
                    if sha256_hex(data) != wire_id:
                        ssl_conn.sendall(b"E")
                    elif not self._put_chunk(wire_id, data):
                        ssl_conn.sendall(b"E")
                    else:
                        ssl_conn.sendall(b"O")
                elif op == "G":
                    blob = self._get_chunk(wire_id)
                    if blob is None:
                        ssl_conn.sendall(struct.pack(">I", 0))
                    else:
                        ssl_conn.sendall(struct.pack(">I", len(blob)) + blob)

                # --- バッチオペコード ---
                elif op == "B":  # Batch HAS
                    if val > MAX_BATCH_ITEMS:
                        ssl_conn.sendall(b"E")
                        break
                    raw_ids = self._recv_exact(ssl_conn, val * 64)
                    decoded_ids = _decode_wire_ids(raw_ids, val)
                    bitmap = bytearray(b"O")
                    for wid in decoded_ids:
                        bitmap.extend(b"1" if self._has_chunk(wid) else b"0")
                    ssl_conn.sendall(bytes(bitmap))

                elif op == "M":  # Multi-PUT
                    if val > MAX_BATCH_ITEMS:
                        ssl_conn.sendall(b"E")
                        break
                    ok = True
                    staged: Dict[str, bytes] = {}
                    for _ in range(val):
                        item_hdr = self._recv_exact(ssl_conn, 68)
                        wid = _decode_wire_id(item_hdr[:64])
                        blen = struct.unpack(">I", item_hdr[64:68])[0]
                        if blen > MAX_BLOB_BYTES:
                            ssl_conn.sendall(b"E")
                            return
                        blob = self._recv_exact(ssl_conn, blen)
                        if sha256_hex(blob) != wid:
                            ok = False
                        else:
                            staged[wid] = blob
                    if ok:
                        for wid, blob in staged.items():
                            if not self._put_chunk(wid, blob):
                                ok = False
                                break
                    ssl_conn.sendall(b"O" if ok else b"E")

                elif op == "F":  # Batch GET
                    if val > MAX_BATCH_ITEMS:
                        ssl_conn.sendall(b"E")
                        break
                    raw_ids = self._recv_exact(ssl_conn, val * 64)
                    decoded_ids = _decode_wire_ids(raw_ids, val)
                    sizes = [self._chunk_size(wid) for wid in decoded_ids]
                    total_bytes = 1 + sum(4 + sz for sz in sizes)
                    if total_bytes > MAX_OST_HTTP_BODY_BYTES:
                        ssl_conn.sendall(b"E")
                        break
                    ssl_conn.sendall(b"O")
                    for wid in decoded_ids:
                        blob = self._get_chunk(wid) or b""
                        ssl_conn.sendall(struct.pack(">I", len(blob)) + blob)
                else:
                    break
        except OSError:
            pass
        except OSTProtocolError:
            # 公開 L3 には DFS 以外の TLS クライアントやスキャンも届く。
            # フレームとして解釈できない接続は、エラーログを出さずに閉じる。
            pass
        except Exception as e:
            print(
                f"[L3-OST] client handler error: {type(e).__name__}: {e}",
                file=sys.stderr,
            )
        finally:
            if ssl_conn is not None:
                try:
                    ssl_conn.close()
                except Exception:
                    pass
            try:
                raw_conn.close()
            except Exception:
                pass

    def batch_has_raw(self, raw_ids: bytes) -> bytes:
        """HTTP / バイナリ共通の Batch HAS 処理。"""
        if not self.online:
            raise ServiceUnavailableError("L3 OST is offline")
        if len(raw_ids) % 64 != 0:
            raise OSTProtocolError("invalid wire_id batch length")
        count = len(raw_ids) // 64
        if count > MAX_BATCH_ITEMS:
            raise OSTProtocolError(f"batch_has exceeds MAX_BATCH_ITEMS ({count})")
        decoded_ids = _decode_wire_ids(raw_ids, count)
        bitmap = bytearray(b"O")
        for wid in decoded_ids:
            bitmap.extend(b"1" if self._has_chunk(wid) else b"0")
        return bytes(bitmap)

    def batch_get_raw(self, raw_ids: bytes) -> bytes:
        """HTTP / バイナリ共通の Batch GET 処理。"""
        if not self.online:
            raise ServiceUnavailableError("L3 OST is offline")
        if len(raw_ids) % 64 != 0:
            raise OSTProtocolError("invalid wire_id batch length")
        count = len(raw_ids) // 64
        if count > MAX_BATCH_ITEMS:
            raise OSTProtocolError(f"batch_get exceeds MAX_BATCH_ITEMS ({count})")
        decoded_ids = _decode_wire_ids(raw_ids, count)
        unique_ids = list(dict.fromkeys(decoded_ids))
        sizes = [self._chunk_size(wid) for wid in unique_ids]
        total_bytes = 1 + sum(4 + sz for sz in sizes)
        if total_bytes > MAX_OST_HTTP_BODY_BYTES:
            raise OSTProtocolError(
                f"batch_get response exceeds MAX_OST_HTTP_BODY_BYTES ({total_bytes} > {MAX_OST_HTTP_BODY_BYTES})"
            )
        out = bytearray(b"O")
        for wid in unique_ids:
            blob = self._get_chunk(wid) or b""
            out.extend(struct.pack(">I", len(blob)) + blob)
        return bytes(out)

    def batch_put_raw(self, raw_payload: bytes) -> None:
        """HTTP / バイナリ共通の Multi-PUT 処理。"""
        if not self.online:
            raise ServiceUnavailableError("L3 OST is offline")
        if len(raw_payload) < 4:
            raise OSTProtocolError("truncated batch_put payload")
        count = struct.unpack(">I", raw_payload[:4])[0]
        if count > MAX_BATCH_ITEMS:
            raise OSTProtocolError(f"batch_put exceeds MAX_BATCH_ITEMS ({count})")
        offset = 4
        staged: Dict[str, bytes] = {}
        for _ in range(count):
            if offset + 68 > len(raw_payload):
                raise OSTProtocolError("truncated batch_put item header")
            wid = _decode_wire_id(raw_payload[offset : offset + 64])
            blen = struct.unpack(">I", raw_payload[offset + 64 : offset + 68])[0]
            offset += 68
            if blen > MAX_BLOB_BYTES or offset + blen > len(raw_payload):
                raise OSTProtocolError("invalid batch_put blob length")
            blob = raw_payload[offset : offset + blen]
            offset += blen
            if sha256_hex(blob) != wid:
                raise ChunkIntegrityError(f"wire_id hash mismatch for {wid}")
            staged[wid] = blob
        if offset != len(raw_payload):
            raise OSTProtocolError("trailing bytes in batch_put payload")
        for wid, blob in staged.items():
            if not self._put_chunk(wid, blob):
                raise OSTProtocolError("L3 OST storage quota exceeded")

    def close(self) -> None:
        self.running = False
        try:
            self.sock.close()
        except Exception:
            pass


class OSTClient:
    """
    L3 OST クライアントアダプタ。
    切断時は必ず QUIT_FRAME ('Q') を送ってから close() するため、サーバ側スレッドが一切残留しない。

    接続タイムアウトは ``DFS_OST_CONNECT_TIMEOUT``（既定 10 秒）で上書きできる。
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 0,
        *,
        expected_cert_sha256: Optional[str] = None,
    ):
        self.host = host
        self.port = port
        self.expected_cert_sha256 = (
            (expected_cert_sha256 or "").strip().lower() or None
        )
        self.bytes_sent: int = 0
        self.blob_bytes_sent: int = 0  # 暗号文本体の送信量（HAS などの固定費を除く）
        self.bytes_received: int = 0
        self.put_count: int = 0
        self.get_count: int = 0
        self.tls_handshakes: int = 0
        self.round_trips: int = 0
        self.last_inflight: int = 0
        self.last_overloaded: bool = False

        self._ssl_ctx = ssl.create_default_context()
        self._ssl_ctx.check_hostname = False
        self._ssl_ctx.verify_mode = ssl.CERT_NONE

        self._pooled_conn: Optional[ssl.SSLSocket] = None
        self._session_depth: int = 0

    @property
    def endpoint_uri(self) -> str:
        host = f"[{self.host}]" if ":" in self.host and not self.host.startswith("[") else self.host
        return f"tls://{host}:{self.port}"

    def probe(self, timeout: Optional[float] = None) -> float:
        """疎通確認して RTT (秒) を返す。失敗時は ServiceUnavailableError。"""
        t0 = time.monotonic()
        conn = self._open_new_conn(timeout=timeout if timeout is not None else ost_probe_timeout())
        normal_exit = False
        try:
            hdr = b"B" + ZERO_WIRE_ID + struct.pack(">I", 0)
            self._send_all(conn, hdr)
            status = self._recv_exact(conn, 1)
            if status == b"U":
                raise ServiceUnavailableError("L3 OST is offline")
            if status != b"O":
                raise ServiceUnavailableError(f"Unexpected probe status {status!r}")
            normal_exit = True
        finally:
            self._graceful_close(conn, send_quit=normal_exit)
        return time.monotonic() - t0

    def reset_metrics(self) -> None:
        self.bytes_sent = 0
        self.blob_bytes_sent = 0
        self.bytes_received = 0
        self.put_count = 0
        self.get_count = 0
        self.tls_handshakes = 0
        self.round_trips = 0
        self.last_inflight = 0
        self.last_overloaded = False

    def _open_new_conn(self, timeout: Optional[float] = None) -> ssl.SSLSocket:
        """接続を張る。到達不能・タイムアウトは ServiceUnavailableError に正規化する。

        WAN では経路断（WireGuard の一時停止など）で生の OSError や socket.timeout が
        飛ぶ。呼び出し側が「サーバ停止」と同じ扱いにできるよう例外をそろえる。
        """
        eff_timeout = timeout if timeout is not None else ost_connect_timeout()
        try:
            raw = socket.create_connection((self.host, self.port), timeout=eff_timeout)
        except (OSError, TimeoutError) as e:
            raise ServiceUnavailableError(
                f"Cannot reach L3 OST at {self.host}:{self.port}: {e}"
            ) from e
        raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        try:
            ssl_conn = self._ssl_ctx.wrap_socket(raw, server_hostname=self.host)
        except (OSError, TimeoutError, ssl.SSLError) as e:
            try:
                raw.close()
            except Exception:
                pass
            raise ServiceUnavailableError(
                f"TLS handshake with L3 OST at {self.host}:{self.port} failed: {e}"
            ) from e
        if self.expected_cert_sha256:
            peer_der = ssl_conn.getpeercert(binary_form=True) or b""
            actual_sha = sha256_hex(peer_der).lower()
            if actual_sha != self.expected_cert_sha256:
                try:
                    ssl_conn.close()
                except Exception:
                    pass
                raise ServiceUnavailableError(
                    f"L3 OST TLS certificate pin mismatch at {self.host}:{self.port}"
                )
        if timeout is None:
            ssl_conn.settimeout(ost_socket_timeout())
        self.tls_handshakes += 1
        return ssl_conn

    @staticmethod
    def _graceful_close(conn: ssl.SSLSocket, send_quit: bool = True) -> None:
        if send_quit:
            try:
                conn.sendall(QUIT_FRAME)
            except Exception:
                pass
        try:
            conn.close()
        except Exception:
            pass

    def _close_pooled_conn(self, send_quit: bool = True) -> None:
        if self._pooled_conn is not None:
            conn = self._pooled_conn
            self._pooled_conn = None
            self._graceful_close(conn, send_quit=send_quit)

    @contextmanager
    def session(self) -> Iterator["OSTClient"]:
        self._session_depth += 1
        try:
            if self._pooled_conn is None:
                self._pooled_conn = self._open_new_conn()
            yield self
        finally:
            self._session_depth -= 1
            if self._session_depth == 0:
                self._close_pooled_conn(send_quit=True)

    @contextmanager
    def _acquire_conn(self) -> Iterator[ssl.SSLSocket]:
        if self._session_depth > 0:
            if self._pooled_conn is None:
                self._pooled_conn = self._open_new_conn()
            try:
                yield self._pooled_conn
            except Exception:
                self._close_pooled_conn(send_quit=False)
                raise
        else:
            conn = self._open_new_conn()
            normal_exit = False
            try:
                yield conn
                normal_exit = True
            finally:
                self._graceful_close(conn, send_quit=normal_exit)

    @staticmethod
    def _send_all(conn: ssl.SSLSocket, data: bytes) -> None:
        try:
            conn.sendall(data)
        except (OSError, TimeoutError, ssl.SSLError) as e:
            raise ServiceUnavailableError(f"L3 OST write failed or timed out: {e}") from e

    @staticmethod
    def _recv_exact(conn: ssl.SSLSocket, n: int) -> bytes:
        buf = bytearray()
        while len(buf) < n:
            try:
                chunk = conn.recv(n - len(buf))
            except (OSError, TimeoutError, ssl.SSLError) as e:
                # 読み取り中のタイムアウト・切断は「サーバが応答しない」と同じ扱い
                raise ServiceUnavailableError(f"L3 OST read failed or timed out: {e}") from e
            if not chunk:
                raise ServiceUnavailableError("Unexpected EOF from OST (server closed the connection)")
            buf.extend(chunk)
        return bytes(buf)

    # ------------------------------------------
    # バッチ操作メソッド
    # ------------------------------------------
    def batch_has(self, wire_ids: Sequence[str]) -> Dict[str, bool]:
        unique_ids = list(dict.fromkeys(wire_ids))
        if not unique_ids:
            return {}

        with self._acquire_conn() as conn:
            result: Dict[str, bool] = {}
            for start in range(0, len(unique_ids), CLIENT_BATCH_ITEMS):
                group = unique_ids[start : start + CLIENT_BATCH_ITEMS]
                hdr = b"B" + ZERO_WIRE_ID + struct.pack(">I", len(group))
                body = "".join(group).encode("ascii")
                self._send_all(conn, hdr + body)
                self.bytes_sent += len(hdr) + len(body)
                self.round_trips += 1

                status = self._recv_exact(conn, 1)
                self.bytes_received += 1
                if status == b"U":
                    raise ServiceUnavailableError("L3 OST is offline")
                if status != b"O":
                    raise ChunkIntegrityError(f"Batch HAS failed with status {status!r}")

                flags = self._recv_exact(conn, len(group))
                self.bytes_received += len(flags)
                result.update(
                    {wid: flags[i : i + 1] == b"1" for i, wid in enumerate(group)}
                )
            return result

    def batch_put_if_absent(self, chunks: Dict[str, bytes], assume_absent: bool = False) -> int:
        """未送信の塊をまとめて PUT する。

        ``assume_absent=True`` のときは内部の ``batch_has`` を省略し、1 往復で送る。
        呼び出し側が「それらの wire_id はサーバに存在しない」と確信できる場合
        （暗号化直後の新しい塊など）にだけ使う。
        """
        if not chunks:
            return 0

        if assume_absent:
            missing_ids = list(chunks.keys())
        else:
            presence = self.batch_has(list(chunks.keys()))
            missing_ids = [wid for wid, exists in presence.items() if not exists]
            if not missing_ids:
                return 0

        groups = _group_put_chunks(chunks, missing_ids)

        with self._acquire_conn() as conn:
            sent_count = 0
            for current in groups:
                payload_parts = [
                    b"M" + ZERO_WIRE_ID + struct.pack(">I", len(current))
                ]
                for wid in current:
                    blob = chunks[wid]
                    payload_parts.append(
                        wid.encode("ascii") + struct.pack(">I", len(blob)) + blob
                    )

                full_payload = b"".join(payload_parts)
                self._send_all(conn, full_payload)
                self.bytes_sent += len(full_payload)
                self.blob_bytes_sent += sum(len(chunks[wid]) for wid in current)
                self.round_trips += 1

                resp = self._recv_exact(conn, 1)
                self.bytes_received += 1
                if resp == b"U":
                    raise ServiceUnavailableError("L3 OST is offline")
                if resp != b"O":
                    raise ChunkIntegrityError("Multi-PUT rejected by OST")
                self.put_count += len(current)
                sent_count += len(current)
            return sent_count

    def batch_get(self, wire_ids: Sequence[str]) -> Dict[str, bytes]:
        unique_ids = list(dict.fromkeys(wire_ids))
        if not unique_ids:
            return {}

        with self._acquire_conn() as conn:
            result: Dict[str, bytes] = {}
            for start in range(0, len(unique_ids), CLIENT_BATCH_ITEMS):
                group = unique_ids[start : start + CLIENT_BATCH_ITEMS]
                hdr = b"F" + ZERO_WIRE_ID + struct.pack(">I", len(group))
                body = "".join(group).encode("ascii")
                self._send_all(conn, hdr + body)
                self.bytes_sent += len(hdr) + len(body)
                self.round_trips += 1

                status = self._recv_exact(conn, 1)
                self.bytes_received += 1
                if status == b"U":
                    raise ServiceUnavailableError("L3 OST is offline")
                if status != b"O":
                    raise ChunkIntegrityError(f"Batch GET failed with status {status!r}")

                for wid in group:
                    raw_len = self._recv_exact(conn, 4)
                    self.bytes_received += 4
                    blen = struct.unpack(">I", raw_len)[0]
                    if blen == 0:
                        raise ChunkIntegrityError(
                            f"Missing chunk on OST during batch_get: {wid}"
                        )
                    if blen > MAX_BLOB_BYTES:
                        raise ChunkIntegrityError(
                            f"L3 response chunk is too large: {blen} > {MAX_BLOB_BYTES}"
                        )
                    blob = self._recv_exact(conn, blen)
                    self.bytes_received += blen
                    self.get_count += 1
                    result[wid] = blob

            return result

    # ------------------------------------------
    # 単発操作メソッド
    # ------------------------------------------
    def put_if_absent(self, wire_id: str, blob: bytes) -> bool:
        return self.batch_put_if_absent({wire_id: blob}) > 0


    def get(self, wire_id: str) -> bytes:
        return self.batch_get([wire_id])[wire_id]


class HttpOSTClient:
    """HTTP / HTTPS 経由の L3 OST クライアント。

    ``OSTClient`` と同じバッチ単位・メトリクス・例外契約を持ち、
    ``session()`` 中は HTTP keep-alive で接続を再利用する。
    """

    def __init__(
        self,
        base_url: str,
        *,
        expected_cert_sha256: Optional[str] = None,
    ):
        host, port, canonical = parse_ost_endpoint(base_url)
        parts = urlsplit(canonical)
        if parts.scheme not in ("http", "https"):
            raise ValueError(f"HttpOSTClient requires http:// or https:// URL: {base_url!r}")
        pin = (expected_cert_sha256 or "").strip().lower() or None
        if pin and parts.scheme != "https":
            raise ValueError("expected_cert_sha256 requires https:// endpoint")
        self.base_url: str = canonical
        self.scheme: str = parts.scheme
        self.host: str = host
        self.port: int = port
        self.base_path: str = parts.path.rstrip("/")
        self.expected_cert_sha256: Optional[str] = pin

        self.bytes_sent: int = 0
        self.blob_bytes_sent: int = 0
        self.bytes_received: int = 0
        self.put_count: int = 0
        self.get_count: int = 0
        self.tls_handshakes: int = 0
        self.round_trips: int = 0
        self.last_inflight: int = 0
        self.last_overloaded: bool = False

        self._pooled_conn: Optional[http.client.HTTPConnection] = None
        self._session_depth: int = 0

    @property
    def endpoint_uri(self) -> str:
        return self.base_url

    def probe(self, timeout: Optional[float] = None) -> float:
        """疎通確認して RTT (秒) を返す。失敗時は ServiceUnavailableError。"""
        t0 = time.monotonic()
        eff = timeout if timeout is not None else ost_probe_timeout()
        conn = self._open_new_conn(timeout=eff)
        try:
            target = (
                f"{self.base_url}/v1/ost/batch_has"
                if self.scheme == "http" and self._resolve_proxy()
                else f"{self.base_path}/v1/ost/batch_has"
            )
            conn.request(
                "POST",
                target,
                body=b"",
                headers={"Content-Type": "application/octet-stream", "Content-Length": "0", "Connection": "close"},
            )
            resp = conn.getresponse()
            resp_body = resp.read()
            if resp.status != 200 or resp_body != b"O":
                raise ServiceUnavailableError(f"HTTP probe failed ({resp.status})")
        except ServiceUnavailableError:
            raise
        except (OSError, TimeoutError, ssl.SSLError, http.client.HTTPException) as e:
            raise ServiceUnavailableError(f"HTTP probe failed: {e}") from e
        finally:
            try:
                conn.close()
            except Exception:
                pass
        return time.monotonic() - t0

    def reset_metrics(self) -> None:
        self.bytes_sent = 0
        self.blob_bytes_sent = 0
        self.bytes_received = 0
        self.put_count = 0
        self.get_count = 0
        self.tls_handshakes = 0
        self.round_trips = 0
        self.last_inflight = 0
        self.last_overloaded = False

    def _resolve_proxy(self) -> Optional[str]:
        import urllib.request

        if urllib.request.proxy_bypass(self.host):
            return None
        proxies = urllib.request.getproxies()
        return proxies.get(self.scheme) or proxies.get("all")

    def _open_new_conn(self, timeout: Optional[float] = None) -> http.client.HTTPConnection:
        eff_timeout = timeout if timeout is not None else ost_connect_timeout()
        proxy_url = self._resolve_proxy()
        ssl_ctx: Optional[ssl.SSLContext] = None
        if self.scheme == "https" and self.expected_cert_sha256:
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE
        try:
            if proxy_url:
                p = urlsplit(proxy_url if "://" in proxy_url else f"http://{proxy_url}")
                if not p.hostname:
                    raise ServiceUnavailableError(f"Invalid proxy URL: {proxy_url!r}")
                p_port = p.port or (443 if p.scheme == "https" else 80)
                if self.scheme == "https":
                    conn: http.client.HTTPConnection = http.client.HTTPSConnection(
                        p.hostname, p_port, timeout=eff_timeout, context=ssl_ctx
                    )
                    conn.set_tunnel(self.host, self.port)
                else:
                    conn = http.client.HTTPConnection(p.hostname, p_port, timeout=eff_timeout)
            elif self.scheme == "https":
                conn = http.client.HTTPSConnection(
                    self.host, self.port, timeout=eff_timeout, context=ssl_ctx
                )
            else:
                conn = http.client.HTTPConnection(self.host, self.port, timeout=eff_timeout)
            conn.connect()
            if self.scheme == "https" and self.expected_cert_sha256:
                sock = conn.sock
                peer_der = sock.getpeercert(binary_form=True) if sock is not None else None
                actual_sha = sha256_hex(peer_der or b"").lower()
                if actual_sha != self.expected_cert_sha256:
                    try:
                        conn.close()
                    except Exception:
                        pass
                    raise ServiceUnavailableError(
                        f"L3 HTTP OST TLS certificate pin mismatch at {self.base_url}"
                    )
        except ServiceUnavailableError:
            raise
        except (OSError, TimeoutError, ssl.SSLError, http.client.HTTPException) as e:
            raise ServiceUnavailableError(
                f"Cannot reach L3 OST over HTTP at {self.base_url}: {e}"
            ) from e
        if self.scheme == "https":
            self.tls_handshakes += 1
        return conn

    def _close_pooled_conn(self) -> None:
        if self._pooled_conn is not None:
            try:
                self._pooled_conn.close()
            except Exception:
                pass
            self._pooled_conn = None

    @contextmanager
    def session(self) -> Iterator["HttpOSTClient"]:
        self._session_depth += 1
        try:
            if self._pooled_conn is None:
                self._pooled_conn = self._open_new_conn()
            yield self
        finally:
            self._session_depth -= 1
            if self._session_depth == 0:
                self._close_pooled_conn()

    def _request_once(
        self, conn: http.client.HTTPConnection, path: str, body: bytes
    ) -> Tuple[int, bytes]:
        if self.scheme == "http" and self._resolve_proxy():
            target = f"{self.base_url}{path}"
        else:
            target = f"{self.base_path}{path}"
        headers = {
            "Content-Type": "application/octet-stream",
            "Content-Length": str(len(body)),
            "Connection": "keep-alive" if self._session_depth > 0 else "close",
        }
        # 転送フェーズは接続確立より長いソケットタイムアウトを使う
        if conn.sock is not None:
            conn.sock.settimeout(ost_socket_timeout())
        conn.request("POST", target, body=body, headers=headers)
        resp = conn.getresponse()
        raw_cl = resp.getheader("Content-Length")
        if raw_cl is not None:
            try:
                cl = int(raw_cl)
            except ValueError as e:
                conn.close()
                raise ChunkIntegrityError(f"Invalid Content-Length from OST: {raw_cl!r}") from e
            if cl < 0 or cl > MAX_OST_HTTP_BODY_BYTES:
                conn.close()
                raise ChunkIntegrityError(
                    f"OST response Content-Length exceeds limit: {cl} > {MAX_OST_HTTP_BODY_BYTES}"
                )
        resp_body = resp.read(MAX_OST_HTTP_BODY_BYTES + 1)
        if len(resp_body) > MAX_OST_HTTP_BODY_BYTES:
            conn.close()
            raise ChunkIntegrityError(
                f"OST response body exceeds MAX_OST_HTTP_BODY_BYTES ({MAX_OST_HTTP_BODY_BYTES})"
            )
        raw_inflight = resp.getheader("X-DFS-Inflight")
        if raw_inflight is not None:
            try:
                self.last_inflight = int(raw_inflight)
            except ValueError:
                pass
        self.last_overloaded = (resp.getheader("X-DFS-Overloaded") or "").strip() == "1" or resp.status == 503
        return resp.status, resp_body

    def _post_binary(self, path: str, body: bytes) -> bytes:
        self.bytes_sent += len(body)
        self.round_trips += 1
        if self._session_depth > 0:
            for attempt in range(2):
                if self._pooled_conn is None:
                    self._pooled_conn = self._open_new_conn()
                try:
                    status, resp_body = self._request_once(self._pooled_conn, path, body)
                    break
                except (
                    http.client.RemoteDisconnected,
                    http.client.BadStatusLine,
                    ConnectionResetError,
                    BrokenPipeError,
                ) as e:
                    self._close_pooled_conn()
                    if attempt == 0:
                        continue
                    raise ServiceUnavailableError(
                        f"L3 HTTP OST connection failed at {self.base_url}: {e}"
                    ) from e
                except ChunkIntegrityError:
                    self._close_pooled_conn()
                    raise
                except (OSError, TimeoutError, ssl.SSLError, http.client.HTTPException) as e:
                    self._close_pooled_conn()
                    raise ServiceUnavailableError(
                        f"L3 HTTP OST request failed at {self.base_url}: {e}"
                    ) from e
        else:
            conn = self._open_new_conn()
            try:
                status, resp_body = self._request_once(conn, path, body)
            except (OSError, TimeoutError, ssl.SSLError, http.client.HTTPException) as e:
                raise ServiceUnavailableError(
                    f"L3 HTTP OST request failed at {self.base_url}: {e}"
                ) from e
            finally:
                try:
                    conn.close()
                except Exception:
                    pass

        self.bytes_received += len(resp_body)
        if status == 503 or resp_body == b"U":
            raise ServiceUnavailableError("L3 OST is offline")
        if status >= 500:
            raise ServiceUnavailableError(f"L3 HTTP OST returned {status}")
        if status != 200:
            raise ChunkIntegrityError(
                f"L3 HTTP OST rejected request ({status}): {resp_body[:120]!r}"
            )
        return resp_body

    def batch_has(self, wire_ids: Sequence[str]) -> Dict[str, bool]:
        unique_ids = list(dict.fromkeys(wire_ids))
        if not unique_ids:
            return {}
        result: Dict[str, bool] = {}
        for start in range(0, len(unique_ids), CLIENT_BATCH_ITEMS):
            group = unique_ids[start : start + CLIENT_BATCH_ITEMS]
            body = "".join(group).encode("ascii")
            resp = self._post_binary("/v1/ost/batch_has", body)
            if not resp.startswith(b"O") or len(resp) != 1 + len(group):
                raise ChunkIntegrityError("Batch HAS over HTTP returned malformed response")
            flags = resp[1:]
            result.update(
                {wid: flags[i : i + 1] == b"1" for i, wid in enumerate(group)}
            )
        return result

    def batch_put_if_absent(self, chunks: Dict[str, bytes], assume_absent: bool = False) -> int:
        if not chunks:
            return 0
        if assume_absent:
            missing_ids = list(chunks.keys())
        else:
            presence = self.batch_has(list(chunks.keys()))
            missing_ids = [wid for wid, exists in presence.items() if not exists]
            if not missing_ids:
                return 0

        groups = _group_put_chunks(chunks, missing_ids)
        sent_count = 0
        for current in groups:
            parts = [struct.pack(">I", len(current))]
            for wid in current:
                blob = chunks[wid]
                parts.append(wid.encode("ascii") + struct.pack(">I", len(blob)) + blob)
            full_payload = b"".join(parts)
            self.blob_bytes_sent += sum(len(chunks[wid]) for wid in current)
            resp = self._post_binary("/v1/ost/batch_put", full_payload)
            if resp != b"O":
                raise ChunkIntegrityError("Multi-PUT over HTTP rejected by OST")
            self.put_count += len(current)
            sent_count += len(current)
        return sent_count

    def batch_get(self, wire_ids: Sequence[str]) -> Dict[str, bytes]:
        unique_ids = list(dict.fromkeys(wire_ids))
        if not unique_ids:
            return {}
        result: Dict[str, bytes] = {}
        for start in range(0, len(unique_ids), CLIENT_BATCH_ITEMS):
            group = unique_ids[start : start + CLIENT_BATCH_ITEMS]
            body = "".join(group).encode("ascii")
            resp = self._post_binary("/v1/ost/batch_get", body)
            if not resp.startswith(b"O"):
                raise ChunkIntegrityError("Batch GET over HTTP returned malformed response")
            offset = 1
            for wid in group:
                if offset + 4 > len(resp):
                    raise ChunkIntegrityError("Truncated batch_get length over HTTP")
                blen = struct.unpack(">I", resp[offset : offset + 4])[0]
                offset += 4
                if blen == 0:
                    raise ChunkIntegrityError(
                        f"Missing chunk on OST during batch_get: {wid}"
                    )
                if blen > MAX_BLOB_BYTES or offset + blen > len(resp):
                    raise ChunkIntegrityError(
                        f"L3 HTTP response chunk is invalid: {blen}"
                    )
                blob = resp[offset : offset + blen]
                offset += blen
                self.get_count += 1
                result[wid] = blob
            if offset != len(resp):
                raise ChunkIntegrityError("Trailing bytes in batch_get HTTP response")
        return result

    def put_if_absent(self, wire_id: str, blob: bytes) -> bool:
        return self.batch_put_if_absent({wire_id: blob}) > 0


    def get(self, wire_id: str) -> bytes:
        return self.batch_get([wire_id])[wire_id]


def make_ost_client(
    endpoint: str, *, expected_cert_sha256: Optional[str] = None
) -> Union[OSTClient, HttpOSTClient]:
    """エンドポイント文字列から ``OSTClient`` または ``HttpOSTClient`` を生成する。"""
    host, port, canonical = parse_ost_endpoint(endpoint)
    if canonical.startswith("http://") or canonical.startswith("https://"):
        return HttpOSTClient(canonical, expected_cert_sha256=expected_cert_sha256)
    return OSTClient(host=host, port=port, expected_cert_sha256=expected_cert_sha256)


class FailoverOSTClient:
    """複数の OST endpoint を読み取り時に順番に試すクライアント。

    書き込みは先頭（主 OST）だけに送る。読み取りは主 OST が停止・欠損なら
    代替 OST を試す。主 OST は書き手のローカル OST、代替は読み取りレプリカを
    想定している。
    """

    def __init__(
        self,
        clients: Sequence[Union[OSTClient, HttpOSTClient]],
        allow_write_failover: bool = False,
        cache_file: Optional[Path | str] = None,
        probe_ttl: float = DEFAULT_TRANSPORT_CACHE_TTL,
    ):
        if not clients:
            raise ValueError("At least one OST client is required")
        self.clients: List[OSTClientProtocol] = list(clients)
        self.primary = self.clients[0]  # type: OSTClientProtocol
        self._active: Optional[OSTClientProtocol] = None
        self.allow_write_failover = bool(allow_write_failover)
        self.cache_file: Optional[Path] = Path(cache_file) if cache_file else None
        self.probe_ttl: float = float(probe_ttl)
        self._adapted: bool = False

    @staticmethod
    def _client_uri(client: OSTClientProtocol) -> str:
        uri = getattr(client, "endpoint_uri", None)
        if uri:
            return str(uri)
        peers = getattr(client, "peers", None)
        if peers:
            return f"libp2p://{peers[0]}"
        return f"ost://{getattr(client, 'host', '')}:{getattr(client, 'port', 0)}"

    @staticmethod
    def _is_relay_uri(uri: str) -> bool:
        return "/relay/" in uri

    @staticmethod
    def _probe_one(client: OSTClientProtocol, timeout: float) -> Tuple[bool, float]:
        t0 = time.monotonic()
        probe_fn = getattr(client, "probe", None)
        try:
            if callable(probe_fn):
                rtt = float(probe_fn(timeout=timeout))
                return True, rtt
            batch_has_fn = getattr(client, "batch_has", None)
            if callable(batch_has_fn):
                batch_has_fn([])
                return True, time.monotonic() - t0
            return True, 0.0
        except (ServiceUnavailableError, ChunkIntegrityError, OSError, TimeoutError):
            return False, float("inf")

    def _cache_key(self) -> str:
        return "|".join(sorted(self._client_uri(c) for c in self.clients))

    def _load_cached_order(self) -> Optional[List[str]]:
        if self.cache_file is None or not self.cache_file.is_file():
            return None
        try:
            data = json.loads(self.cache_file.read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError):
            return None
        if not isinstance(data, dict):
            return None
        entry = data.get(self._cache_key())
        if not isinstance(entry, dict):
            return None
        updated_at = float(entry.get("updated_at", 0) or 0)
        if time.time() - updated_at >= self.probe_ttl:
            return None
        order = entry.get("order")
        return [str(u) for u in order] if isinstance(order, list) else None

    def _save_cached_order(self, order: List[str]) -> None:
        if self.cache_file is None:
            return
        try:
            data: Dict[str, Any] = {}
            if self.cache_file.is_file():
                loaded = json.loads(self.cache_file.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    data = loaded
        except Exception:
            data = {}
        data[self._cache_key()] = {"updated_at": time.time(), "order": order}
        try:
            self.cache_file.parent.mkdir(parents=True, exist_ok=True)
            self.cache_file.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        except OSError:
            pass

    def _invalidate_cache(self) -> None:
        self._adapted = False
        if self.cache_file is None or not self.cache_file.is_file():
            return
        try:
            data = json.loads(self.cache_file.read_text(encoding="utf-8"))
            if isinstance(data, dict) and self._cache_key() in data:
                del data[self._cache_key()]
                self.cache_file.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        except Exception:
            pass

    def adapt_order(self, force: bool = False) -> List[Union[OSTClient, HttpOSTClient]]:
        """通信環境・NAT・HTTP 制限を並列プローブして最適なクライアント順に並べる。"""
        if len(self.clients) <= 1 or os.environ.get("DFS_AUTO_TRANSPORT", "1").strip() == "0":
            return self.clients
        if self._adapted and not force:
            return self.clients

        if not force:
            cached = self._load_cached_order()
            if cached:
                by_uri = {self._client_uri(c): c for c in self.clients}
                reordered = [by_uri[u] for u in cached if u in by_uri]
                for c in self.clients:  # type: OSTClientProtocol
                    if c not in reordered:
                        reordered.append(c)
                self.clients = reordered
                self._active = self.clients[0]
                self._adapted = True
                return self.clients

        timeout = ost_probe_timeout()
        direct = [c for c in self.clients if not self._is_relay_uri(self._client_uri(c))]
        relay = [c for c in self.clients if self._is_relay_uri(self._client_uri(c))]

        direct_ok: List[Tuple[int, float, Any]] = []
        direct_bad: List[Any] = []
        if direct:
            with ThreadPoolExecutor(max_workers=min(8, len(direct))) as pool:
                futs = {pool.submit(self._probe_one, c, timeout): c for c in direct}
                for fut in as_completed(futs):
                    c = futs[fut]
                    ok, rtt = fut.result()
                    if ok:
                        pref = 0 if isinstance(c, OSTClient) else 1
                        direct_ok.append((pref, rtt, c))
                    else:
                        direct_bad.append(c)
            direct_ok.sort(key=lambda item: (item[0], item[1]))

        if direct_ok:
            new_order = [item[2] for item in direct_ok] + direct_bad + relay
        else:
            relay_ok: List[Tuple[float, Any]] = []
            relay_bad: List[Any] = []
            if relay:
                with ThreadPoolExecutor(max_workers=min(8, len(relay))) as pool:
                    futs = {pool.submit(self._probe_one, c, timeout): c for c in relay}
                    for fut in as_completed(futs):
                        c = futs[fut]
                        ok, rtt = fut.result()
                        if ok:
                            relay_ok.append((rtt, c))
                        else:
                            relay_bad.append(c)
                relay_ok.sort(key=lambda item: item[0])
            new_order = [item[1] for item in relay_ok] + relay_bad + direct_bad

        if new_order:
            self.clients = new_order
            self._active = self.clients[0]
            self._save_cached_order([self._client_uri(c) for c in self.clients])
        self._adapted = True
        return self.clients

    @property
    def host(self) -> str:
        return self.primary.host

    @property
    def port(self) -> int:
        return self.primary.port

    def reset_metrics(self) -> None:
        for client in self.clients:  # type: OSTClientProtocol
            client.reset_metrics()
        self._active = None

    @property
    def bytes_sent(self) -> int:
        return sum(c.bytes_sent for c in self.clients)

    @property
    def bytes_received(self) -> int:
        return sum(c.bytes_received for c in self.clients)

    @property
    def blob_bytes_sent(self) -> int:
        return sum(c.blob_bytes_sent for c in self.clients)

    @property
    def round_trips(self) -> int:
        return sum(c.round_trips for c in self.clients)

    @property
    def tls_handshakes(self) -> int:
        return sum(c.tls_handshakes for c in self.clients)

    @property
    def put_count(self) -> int:
        return sum(c.put_count for c in self.clients)

    @property
    def get_count(self) -> int:
        return sum(c.get_count for c in self.clients)

    @contextmanager
    def session(self) -> Iterator["FailoverOSTClient"]:
        self.adapt_order()
        last_error: Optional[ServiceUnavailableError] = None
        stack = ExitStack()
        entered = False
        for idx, client in enumerate(self.clients):
            try:
                stack.enter_context(client.session())
                self._active = client
                entered = True
                break
            except ServiceUnavailableError as e:
                if idx == 0:
                    self._invalidate_cache()
                last_error = e
                continue
        if not entered:
            if last_error is not None:
                raise last_error
            raise ServiceUnavailableError("No OST endpoint is available")
        with stack:
            yield self

    def _read_candidates(self) -> List[OSTClient]:
        if self._active is None:
            return list(self.clients)
        return [self._active] + [c for c in self.clients if c is not self._active]

    def batch_has(self, wire_ids: Sequence[str]) -> Dict[str, bool]:
        last_error: Optional[BaseException] = None
        for client in self._read_candidates():
            try:
                return client.batch_has(wire_ids)
            except (ServiceUnavailableError, OSError) as e:
                last_error = e
                continue
        if last_error is not None:
            raise last_error
        return {}

    def batch_get(self, wire_ids: Sequence[str]) -> Dict[str, bytes]:
        last_error: Optional[BaseException] = None
        for client in self._read_candidates():
            try:
                result = client.batch_get(wire_ids)
                self._active = client
                return result
            except (ServiceUnavailableError, ChunkIntegrityError, OSError) as e:
                last_error = e
                continue
        if last_error is not None:
            raise last_error
        return {}

    def get(self, wire_id: str) -> bytes:
        return self.batch_get([wire_id])[wire_id]

    def batch_put_if_absent(self, chunks: Dict[str, bytes], assume_absent: bool = False) -> int:
        if not self.allow_write_failover:
            # 書き込みは主 OST のみ。レプリカへ直接書かない。
            return self.primary.batch_put_if_absent(chunks, assume_absent=assume_absent)
        last_error: Optional[BaseException] = None
        for client in self._read_candidates():
            try:
                sent = client.batch_put_if_absent(chunks, assume_absent=assume_absent)
                self._active = client
                return sent
            except (ServiceUnavailableError, OSError) as e:
                last_error = e
                continue
        if last_error is not None:
            raise last_error
        return 0

    def put_if_absent(self, wire_id: str, blob: bytes) -> bool:
        return self.batch_put_if_absent({wire_id: blob}) > 0


class SwarmOSTClient(FailoverOSTClient):
    """BitTorrent 式マルチピア並列取得 + Relay フォールバックを組み合わせた読み取りクライアント。

    - 非リレー候補（Direct TLS/HTTP, 複製 OST, libp2p/QUIC ピア）が 2 つ以上ある場合、
      ``batch_has`` で在庫を並列確認し、チャンクを複数ピアへラウンドロビンで並列分散取得する。
    - 欠損や失敗したチャンクは別ピア、さらに最後の砦である ``/relay/`` 候補へフォールバックする。
    - ``DFS_OST_SWARM=0`` で従来の単一フェイルオーバー (`FailoverOSTClient`) 挙動へ戻せる。
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.safe_mode: bool = os.environ.get("DFS_SAFE_MODE", "0").strip() == "1"
        self.safe_mode_reason: str = "env:DFS_SAFE_MODE" if self.safe_mode else ""
        self._overloaded_until: Dict[str, float] = {}
        self._slow_hosts: set[str] = set()
        self._peer_bps: Dict[str, float] = {}
        self._peer_bps_lock = threading.Lock()
        self._libp2p_disabled: bool = False
        self._libp2p_consecutive_failures: int = 0
        self._libp2p_fail_threshold: int = max(
            1, int(os.environ.get("DFS_LIBP2P_FAIL_THRESHOLD", "3") or "3")
        )
        self.overload_cooldown: float = float(
            os.environ.get("DFS_OVERLOAD_COOLDOWN", "15.0") or "15.0"
        )
        self.min_single_bps: float = float(
            os.environ.get("DFS_SWARM_MIN_SINGLE_BPS", str(3 * 1024 * 1024))
            or str(3 * 1024 * 1024)
        )

    def enter_safe_mode(self, reason: str) -> None:
        """自動発見・並列取得が機能しない環境向けに HTTP/HTTPS 単一フォールバックモードへ移行する。"""
        self.safe_mode = True
        self.safe_mode_reason = str(reason or "auto")
        # HTTP/HTTPS クライアントを優先しつつ、非リレー → リレーの順を維持する
        http_direct: List[OSTClientProtocol] = [
            c for c in self.clients
            if not self._is_relay_client(c)
            and str(getattr(c, "base_url", "")).startswith(("http://", "https://"))
        ]
        other_direct: List[OSTClientProtocol] = [
            c for c in self.clients
            if not self._is_relay_client(c) and c not in http_direct
        ]
        relay: List[OSTClientProtocol] = [c for c in self.clients if self._is_relay_client(c)]
        self.clients = http_direct + other_direct + relay

    @staticmethod
    def _is_relay_client(client: OSTClientProtocol) -> bool:
        return "/relay/" in str(getattr(client, "base_url", ""))

    @classmethod
    def _is_libp2p_client(cls, client: OSTClientProtocol) -> bool:
        return cls._client_uri(client).startswith("libp2p://")

    def disable_libp2p(self, reason: str) -> None:
        """UDP/QUIC 受信失敗が続く環境で libp2p クライアントを無効化し、TLS/HTTP/Relay へフォールバックする。"""
        with self._peer_bps_lock:
            already = self._libp2p_disabled
            self._libp2p_disabled = True
        removed: List[OSTClientProtocol] = [c for c in self.clients if self._is_libp2p_client(c)]
        if removed:
            self.clients = [c for c in self.clients if not self._is_libp2p_client(c)]  # type: List[OSTClientProtocol]
            if self._active in removed:
                self._active = self.clients[0] if self.clients else None
            for c in removed:
                try:
                    c.close()
                except Exception:
                    pass
        if not already:
            print(
                f"[dfs p2p] disabling libp2p ({reason}); falling back to TLS/HTTP/Relay",
                file=sys.stderr,
                flush=True,
            )

    def _record_libp2p_outcome(self, client: OSTClientProtocol, *, ok: bool, reason: str = "udp_receive_failures") -> None:
        if not self._is_libp2p_client(client):
            return
        should_disable = False
        with self._peer_bps_lock:
            if ok:
                self._libp2p_consecutive_failures = 0
            else:
                self._libp2p_consecutive_failures += 1
                if self._libp2p_consecutive_failures >= self._libp2p_fail_threshold:
                    should_disable = True
        if should_disable:
            self.disable_libp2p(reason)

    def _partition_tiers(self) -> Tuple[List[OSTClientProtocol], List[OSTClientProtocol]]:
        direct: List[OSTClientProtocol] = [c for c in self.clients if not self._is_relay_client(c)]
        relay: List[OSTClientProtocol] = [c for c in self.clients if self._is_relay_client(c)]
        return direct, relay

    @contextmanager
    def session(self) -> Iterator["SwarmOSTClient"]:
        with super().session():
            yield self

    def _is_overloaded(self, client: OSTClientProtocol, now: float) -> bool:
        key = self._client_uri(client)
        until = self._overloaded_until.get(key, 0.0)
        if until > now:
            return True
        if key in self._overloaded_until:
            del self._overloaded_until[key]
        return False

    def _mark_overloaded(self, client: OSTClientProtocol) -> None:
        self._overloaded_until[self._client_uri(client)] = (
            time.monotonic() + self.overload_cooldown
        )

    def _compute_peer_weights(
        self,
        active_indices: Sequence[int],
        direct_tier: Sequence[OSTClientProtocol],
        probe_rtt: Dict[int, float],
    ) -> Dict[int, float]:
        """実測スループット (EWMA) とプローブ RTT の逆数からピアごとの配分重みを決める。"""
        with self._peer_bps_lock:
            bps_snapshot = dict(self._peer_bps)

        measured_vals: List[float] = []
        measured_rtts: List[float] = []
        for idx in active_indices:
            uri = self._client_uri(direct_tier[idx])
            bps = bps_snapshot.get(uri)
            if bps is not None and bps > 0:
                measured_vals.append(bps)
                measured_rtts.append(max(0.002, probe_rtt.get(idx, 0.05)))

        if measured_vals:
            sorted_vals = sorted(measured_vals)
            sorted_rtts = sorted(measured_rtts)
            ref_bps = sorted_vals[len(sorted_vals) // 2]
            ref_rtt = sorted_rtts[len(sorted_rtts) // 2]
        else:
            ref_bps = 1.0
            ref_rtt = min(max(0.002, probe_rtt.get(idx, 0.05)) for idx in active_indices)

        weights: Dict[int, float] = {}
        for idx in active_indices:
            uri = self._client_uri(direct_tier[idx])
            measured = bps_snapshot.get(uri)
            if measured is not None and measured > 0:
                weights[idx] = measured
            else:
                rtt = max(0.002, probe_rtt.get(idx, ref_rtt))
                est = ref_bps * (ref_rtt / rtt)
                if measured_vals:
                    est = max(0.1 * ref_bps, min(10.0 * ref_bps, est))
                weights[idx] = max(1e-6, est)
        return weights

    def _record_peer_throughput(self, client: OSTClientProtocol, got_bytes: int, dt: float) -> None:
        """十分大きい応答からピアの実効帯域 (bytes/s) を EWMA 更新する。"""
        if got_bytes < 64 * 1024 or dt <= 0:
            return
        bps = got_bytes / dt
        uri = self._client_uri(client)
        with self._peer_bps_lock:
            prev = self._peer_bps.get(uri)
            self._peer_bps[uri] = bps if prev is None else (0.6 * bps + 0.4 * prev)

    def batch_get(self, wire_ids: Sequence[str]) -> Dict[str, bytes]:
        unique_ids = list(dict.fromkeys(wire_ids))
        if not unique_ids:
            return {}
        direct_tier: List[OSTClientProtocol]; relay_tier: List[OSTClientProtocol]; direct_tier, relay_tier = self._partition_tiers()
        if (
            self.safe_mode
            or len(direct_tier) <= 1
            or os.environ.get("DFS_OST_SWARM", "1").strip() == "0"
        ):
            return super().batch_get(unique_ids)

        last_error: Optional[BaseException] = None
        result: Dict[str, bytes] = {}
        remaining = list(unique_ids)

        # 1 件のみの要求は分割不要なため、過負荷でない直接ピアを順に試して必要ならリレーへフォールバックする
        if len(remaining) == 1:
            now = time.monotonic()
            active_direct = [c for c in direct_tier if not self._is_overloaded(c, now)]
            if not active_direct:
                self._overloaded_until.clear()
                active_direct = list(direct_tier)
            for client in active_direct:
                t0 = time.perf_counter()
                try:
                    fetched = client.batch_get(remaining)
                    dt = max(0.001, time.perf_counter() - t0)
                    got_bytes = sum(len(v) for v in fetched.values())
                    self._record_peer_throughput(client, got_bytes, dt)
                    self._record_libp2p_outcome(client, ok=True)
                    result.update(fetched)
                    self._active = client
                    if getattr(client, "last_overloaded", False):
                        self._mark_overloaded(client)
                    remaining = [wid for wid in remaining if wid not in result]
                    if not remaining:
                        return result
                except (ServiceUnavailableError, ChunkIntegrityError, OSError) as e:
                    self._record_libp2p_outcome(client, ok=False)
                    last_error = e
                    if bool(getattr(client, "last_overloaded", False)) or isinstance(
                        e, ServiceUnavailableError
                    ):
                        self._mark_overloaded(client)
            healthy_indices: List[int] = []
            availability: Dict[int, Dict[str, bool]] = {}
            failed_clients: set[int] = set()
            pending: List[str] = []
            unassigned: List[str] = list(remaining)
        else:
            # 全生存直接ピアから RTT/実測帯域に比例したサイズで並列取得する。
            # メインスレッドの pooled_conn を閉じて各ワーカースレッド専用の session() を張る。
            for c in direct_tier:
                close_fn = getattr(c, "_close_pooled_conn", None)
                if callable(close_fn):
                    close_fn()

            availability = {}
            probe_rtt: Dict[int, float] = {}

            def _probe_has(idx: int, client: OSTClientProtocol) -> Tuple[Dict[str, bool], float]:
                t0 = time.perf_counter()
                with client.session():
                    res = client.batch_has(remaining)
                return res, max(0.0005, time.perf_counter() - t0)

            with ThreadPoolExecutor(max_workers=min(8, len(direct_tier))) as pool:
                fut_map = {
                    pool.submit(_probe_has, idx, client): idx
                    for idx, client in enumerate(direct_tier)
                }
                for fut in as_completed(fut_map):
                    idx = fut_map[fut]
                    try:
                        availability[idx], probe_rtt[idx] = fut.result()
                    except (ServiceUnavailableError, ChunkIntegrityError, OSError) as e:
                        last_error = e

            healthy_indices = sorted(
                (i for i in availability.keys() if not self._is_overloaded(direct_tier[i], time.monotonic())),
                key=lambda i: probe_rtt.get(i, 999.0),
            )
            if not healthy_indices:
                self._overloaded_until.clear()
                healthy_indices = sorted(availability.keys(), key=lambda i: probe_rtt.get(i, 999.0))

            failed_clients = set()
            lock = threading.Lock()
            pending = []
            owner_counts: Dict[str, int] = {}
            unassigned = []
            for wid in remaining:
                cnt = sum(1 for idx in healthy_indices if availability[idx].get(wid))
                if cnt > 0:
                    owner_counts[wid] = cnt
                    pending.append(wid)
                else:
                    unassigned.append(wid)
            # BitTorrent 式 Rarest-first: 保有ピア数が少ない希少チャンクを優先して取得する
            pending.sort(key=lambda w: owner_counts.get(w, 0))

            if pending and healthy_indices:
                active_indices = [
                    idx for idx in healthy_indices
                    if any(availability[idx].get(wid) for wid in pending)
                ]
                if active_indices:
                    weights = self._compute_peer_weights(active_indices, direct_tier, probe_rtt)
                    total_weight = max(1e-9, sum(weights.values()))
                    ranked_indices = sorted(active_indices, key=lambda i: weights[i], reverse=True)
                    n_wave = min(len(pending), 24 * len(ranked_indices))
                    alloc: Dict[int, int] = {
                        idx: max(1, int(round(n_wave * (weights[idx] / total_weight))))
                        for idx in ranked_indices
                    }
                    while sum(alloc.values()) > n_wave:
                        for idx in reversed(ranked_indices):
                            if alloc[idx] > 1 and sum(alloc.values()) > n_wave:
                                alloc[idx] -= 1
                            elif sum(alloc.values()) <= n_wave:
                                break
                        else:
                            break
                    while sum(alloc.values()) < n_wave:
                        for idx in ranked_indices:
                            if sum(alloc.values()) < n_wave:
                                alloc[idx] += 1

                    initial_batches: Dict[int, List[str]] = {idx: [] for idx in ranked_indices}
                    remaining_pending: List[str] = []
                    for wid in pending:
                        placed = False
                        candidates = [
                            idx for idx in ranked_indices
                            if len(initial_batches[idx]) < alloc[idx] and availability[idx].get(wid)
                        ]
                        if candidates:
                            best_idx = max(
                                candidates,
                                key=lambda i: (alloc[i] - len(initial_batches[i])) / max(1, alloc[i]),
                            )
                            initial_batches[best_idx].append(wid)
                            placed = True
                        if not placed:
                            remaining_pending.append(wid)
                    pending[:] = remaining_pending

                    def _worker(idx: int) -> None:
                        nonlocal last_error
                        client = direct_tier[idx]
                        share = weights[idx] / total_weight
                        quantum = max(1, min(24, int(round(n_wave * share))))
                        avail = availability[idx]
                        first_batch = initial_batches.get(idx, [])
                        with client.session():
                            while True:
                                if first_batch:
                                    batch = first_batch
                                    first_batch = []
                                else:
                                    batch = []
                                    with lock:
                                        if not pending:
                                            return
                                        cur_q = min(quantum, max(1, len(pending)))
                                        keep: List[str] = []
                                        for wid in pending:
                                            if len(batch) < cur_q and avail.get(wid):
                                                batch.append(wid)
                                            else:
                                                keep.append(wid)
                                        pending[:] = keep
                                    if not batch:
                                        return
                                t0 = time.perf_counter()
                                try:
                                    fetched = client.batch_get(batch)
                                    dt = max(0.001, time.perf_counter() - t0)
                                    got_bytes = sum(len(v) for v in fetched.values())
                                    self._record_peer_throughput(client, got_bytes, dt)
                                    self._record_libp2p_outcome(client, ok=True)
                                    with lock:
                                        result.update(fetched)
                                        self._active = client
                                        missing_in_batch = [w for w in batch if w not in fetched]
                                        if missing_in_batch:
                                            unassigned.extend(missing_in_batch)
                                    if getattr(client, "last_overloaded", False):
                                        self._mark_overloaded(client)
                                    if dt < 0.15 and len(batch) == quantum:
                                        quantum = min(24, quantum * 2)
                                    elif dt > 0.6 and quantum > 1:
                                        quantum = max(1, quantum // 2)
                                except (ServiceUnavailableError, ChunkIntegrityError, OSError) as e:
                                    self._record_libp2p_outcome(client, ok=False)
                                    with lock:
                                        last_error = e
                                        failed_clients.add(idx)
                                        pending.extend(batch)
                                        if first_batch:
                                            pending.extend(first_batch)
                                    return

                    with ThreadPoolExecutor(max_workers=min(8, len(ranked_indices))) as pool:
                        futs = [pool.submit(_worker, idx) for idx in ranked_indices]
                        for fut in as_completed(futs):
                            fut.result()

        # 失敗・欠損分は未試行の健全な直接ピア → 最後にリレー層へフォールバック
        remaining = [wid for wid in (pending + unassigned) if wid not in result]
        if remaining:
            for idx in healthy_indices:
                if idx in failed_clients or not remaining:
                    continue
                can_serve = [wid for wid in remaining if availability[idx].get(wid)]
                if not can_serve:
                    continue
                try:
                    fetched = direct_tier[idx].batch_get(can_serve)
                    self._record_libp2p_outcome(direct_tier[idx], ok=True)
                    result.update(fetched)
                    remaining = [wid for wid in remaining if wid not in result]
                except (ServiceUnavailableError, ChunkIntegrityError, OSError) as e:
                    self._record_libp2p_outcome(direct_tier[idx], ok=False)
                    last_error = e

        if remaining:
            direct_got = len(result)
            for r_client in relay_tier:
                if not remaining:
                    break
                try:
                    fetched = r_client.batch_get(remaining)
                    result.update(fetched)
                    remaining = [wid for wid in remaining if wid not in result]
                except (ServiceUnavailableError, ChunkIntegrityError, OSError) as e:
                    last_error = e
            if not remaining and direct_got == 0 and relay_tier:
                self.enter_safe_mode("swarm_direct_failed")

        if remaining:
            if last_error is not None:
                raise last_error
            raise ChunkIntegrityError(
                f"Missing chunk on all OST peers during swarm batch_get: {remaining[0]}"
            )
        return result

    def discover_from_ice(
        self,
        registry_urls: Sequence[str],
        node_id: Optional[str] = None,
        timeout: float = 1.0,
    ) -> List[str]:
        """``/_ice/candidates`` から到達可能な直接ホストを発見して ``self.clients`` へ追加する。"""
        if self.safe_mode:
            return []
        from urllib.parse import urlsplit
        from .relay import discover_ice_candidates

        existing_keys = {self._client_uri(c).rstrip("/") for c in self.clients}
        raw_candidates: List[str] = []
        seen_raw: set[str] = set()
        seen_hubs: set[str] = set()
        for reg_url in registry_urls:
            base = str(reg_url or "").strip().rstrip("/")
            if not base:
                continue
            if "/relay/" in base:
                parts = urlsplit(base)
                if parts.scheme and parts.netloc:
                    base = f"{parts.scheme}://{parts.netloc}"
            if base in seen_hubs:
                continue
            seen_hubs.add(base)
            for cand in discover_ice_candidates(base, node_id=node_id, timeout=timeout):
                ctype = str(cand.get("type") or "")
                ep = str(cand.get("endpoint") or "").strip().rstrip("/")
                if not ep or ctype in ("relay", "libp2p"):
                    continue
                if ep in seen_raw:
                    continue
                seen_raw.add(ep)
                raw_candidates.append(ep)

        pending: List[Tuple[str, Any]] = []
        for ep in raw_candidates:
            try:
                client = make_ost_client(ep)
            except Exception:
                continue
            key = self._client_uri(client).rstrip("/")
            if key in existing_keys:
                try:
                    client.close()
                except Exception:
                    pass
                continue
            existing_keys.add(key)
            pending.append((ep, client))

        if not pending:
            return []

        added: List[str] = []
        with ThreadPoolExecutor(max_workers=min(8, len(pending))) as pool:
            fut_map = {
                pool.submit(self._probe_one, client, timeout): (ep, client)
                for ep, client in pending
            }
            for fut in as_completed(fut_map):
                ep, client = fut_map[fut]
                ok = False
                try:
                    ok, _rtt = fut.result()
                except Exception:
                    ok = False
                if ok:
                    self.clients.append(client)
                    added.append(ep)
                else:
                    try:
                        client.close()
                    except Exception:
                        pass

        if added:
            self.adapt_order(force=True)
        elif pending:
            self.enter_safe_mode("ice_candidates_unreachable")
        return added

    def discover_from_p2p(
        self,
        host_manager: Any,
        *,
        domain_key: str = "",
        registry_urls: Sequence[str] = (),
        relay_addrs: Sequence[str] = (),
        node_id: Optional[str] = None,
        timeout: float = 2.0,
    ) -> List[str]:
        """Kademlia DHT を優先して libp2p ピアを発見し、失敗時は既存ハブ (/_p2p/peers, /_ice/candidates) へフォールバックする。"""
        if self.safe_mode or self._libp2p_disabled or host_manager is None:
            return []
        try:
            from .libp2p_chunk import Libp2pPeerClient, is_libp2p_available
        except ImportError:
            return []
        if not is_libp2p_available():
            return []

        from urllib.parse import urlsplit
        from .relay import discover_ice_candidates, fetch_p2p_peers

        existing_keys = {self._client_uri(c).rstrip("/") for c in self.clients}
        self_peer_id = str(getattr(host_manager, "peer_id", "") or "")
        peer_addrs: Dict[str, List[str]] = {}
        allowed_ids: set[str] = set()
        hub_entries: List[Dict[str, Any]] = []
        auto_relay_addrs: List[str] = [str(r).strip() for r in relay_addrs if str(r).strip()]

        # 1) ハブ (/_p2p/peers & /_ice/candidates) で許可リスト・ピア一覧を取得し DHT へブートストラップ
        seen_hubs: set[str] = set()
        for reg_url in registry_urls:
            base = str(reg_url or "").strip().rstrip("/")
            if not base:
                continue
            if "/relay/" in base:
                parts = urlsplit(base)
                if parts.scheme and parts.netloc:
                    base = f"{parts.scheme}://{parts.netloc}"
            if base in seen_hubs:
                continue
            seen_hubs.add(base)

            p2p_info = fetch_p2p_peers(base, timeout=timeout)
            for pid in p2p_info.get("peer_ids") or []:
                s = str(pid).strip()
                if s:
                    allowed_ids.add(s)
            for entry in p2p_info.get("peers") or []:
                if not isinstance(entry, dict):
                    continue
                pid = str(entry.get("peer_id") or "").strip()
                if not pid:
                    continue
                allowed_ids.add(pid)
                if pid == self_peer_id:
                    continue
                hub_entries.append(entry)
                is_relay_role = str(entry.get("role") or "").strip().lower() in ("hub", "root", "writer")
                for a in entry.get("addrs") or []:
                    sa = str(a).strip()
                    if sa:
                        lst = peer_addrs.setdefault(pid, [])
                        if sa not in lst:
                            lst.append(sa)
                        if is_relay_role and "/p2p-circuit" not in sa and sa not in auto_relay_addrs:
                            auto_relay_addrs.append(sa)

            for cand in discover_ice_candidates(base, node_id=node_id, timeout=timeout):
                if str(cand.get("type") or "") != "libp2p":
                    continue
                pid = str(cand.get("peer_id") or "").strip()
                ep = str(cand.get("endpoint") or "").strip()
                if not pid or not ep or pid == self_peer_id:
                    continue
                allowed_ids.add(pid)
                lst = peer_addrs.setdefault(pid, [])
                if ep not in lst:
                    lst.append(ep)

        if allowed_ids and hasattr(host_manager, "set_allowed_peer_ids"):
            if self_peer_id:
                allowed_ids.add(self_peer_id)
            host_manager.set_allowed_peer_ids(allowed_ids)

        if hub_entries and hasattr(host_manager, "bootstrap_from_peers"):
            try:
                host_manager.bootstrap_from_peers(hub_entries, timeout=min(float(timeout), 1.5))
            except Exception:
                pass

        # 2) ブートストラップ済み Kademlia DHT からドメイン内プロバイダを検索・補完
        if domain_key:
            try:
                dht_provs = host_manager.find_domain_providers(domain_key, timeout=timeout)
                for prov in dht_provs:
                    pid = str(prov.get("peer_id") or "").strip()
                    if not pid or pid == self_peer_id:
                        continue
                    addrs = [str(a).strip() for a in (prov.get("addrs") or []) if str(a).strip()]
                    peer_addrs.setdefault(pid, [])
                    for a in addrs:
                        if a not in peer_addrs[pid]:
                            peer_addrs[pid].append(a)
            except Exception:
                pass

        pending: List[Tuple[str, Any]] = []
        for pid, addrs in peer_addrs.items():
            if allowed_ids and pid not in allowed_ids:
                continue
            uri = f"libp2p://{pid}"
            if uri in existing_keys:
                continue
            existing_keys.add(uri)
            circuit_addrs = [
                f"{r.rstrip('/')}/p2p-circuit/p2p/{pid}"
                for r in auto_relay_addrs
                if str(r).strip()
                and "/p2p/" in str(r)
                and "/p2p-circuit" not in str(r)
                and not str(r).rstrip("/").endswith(f"/p2p/{pid}")
            ]
            client = Libp2pPeerClient(
                host_manager,
                pid,
                addrs,
                relay_addrs=circuit_addrs,
                timeout=timeout,
            )
            pending.append((uri, client))

        if not pending:
            return []

        added: List[str] = []
        with ThreadPoolExecutor(max_workers=min(8, len(pending))) as pool:
            fut_map = {
                pool.submit(self._probe_one, client, timeout): (uri, client)
                for uri, client in pending
            }
            for fut in as_completed(fut_map):
                uri, client = fut_map[fut]
                ok = False
                try:
                    ok, _rtt = fut.result()
                except Exception:
                    ok = False
                if ok:
                    self.clients.append(client)
                    added.append(uri)
                else:
                    try:
                        client.close()
                    except Exception:
                        pass

        if added:
            with self._peer_bps_lock:
                self._libp2p_consecutive_failures = 0
            self.adapt_order(force=True)
        elif pending:
            should_disable = False
            with self._peer_bps_lock:
                self._libp2p_consecutive_failures += 1
                if self._libp2p_consecutive_failures >= self._libp2p_fail_threshold:
                    should_disable = True
            if should_disable:
                self.disable_libp2p("p2p_peers_unreachable")
        return added


# 後方互換: 旧名。実体は ChunkStoreServer（mini_lustre の API ではない）。
MiniLustreOSTServer = ChunkStoreServer
