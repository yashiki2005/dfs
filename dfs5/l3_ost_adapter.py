#!/usr/bin/env python3
"""
dfs5/l3_ost_adapter.py
macOS / Linux 両対応・デッドロック完全排除版 L3 OST サーバ & クライアント。
明示的切断オペコード ('Q') により、サーバ側の recv ブロッキング待ちを確実に終了させる。
"""

from __future__ import annotations

import os
import socket
import ssl
import struct
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Dict, Iterator, Optional, Sequence

from .crypto import ChunkIntegrityError, sha256_hex
from .l2_registry import ServiceUnavailableError

ZERO_WIRE_ID = b"0" * 64
QUIT_FRAME = b"Q" + ZERO_WIRE_ID + struct.pack(">I", 0)


# ---------------------------------------------------------------------------
# WAN（高遅延）向けタイムアウト。環境変数で上書きできる。
#   DFS5_OST_SOCKET_TIMEOUT  : サーバ側ソケットの 1 操作あたりのタイムアウト秒
#   DFS5_OST_CONNECT_TIMEOUT : クライアント側の TCP 接続タイムアウト秒
# 既定はどちらも WAN（RTT 300ms 級）の直列処理に耐える値にしてある。
# ---------------------------------------------------------------------------
DEFAULT_OST_SOCKET_TIMEOUT = 30.0
DEFAULT_OST_CONNECT_TIMEOUT = 10.0


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
    """サーバ側ソケットタイムアウト秒（既定 30 秒、``DFS5_OST_SOCKET_TIMEOUT`` で変更）"""
    return _env_positive_float("DFS5_OST_SOCKET_TIMEOUT", DEFAULT_OST_SOCKET_TIMEOUT)


def ost_connect_timeout() -> float:
    """クライアント側 TCP 接続タイムアウト秒（既定 10 秒、``DFS5_OST_CONNECT_TIMEOUT`` で変更）"""
    return _env_positive_float("DFS5_OST_CONNECT_TIMEOUT", DEFAULT_OST_CONNECT_TIMEOUT)


class ChunkStoreServer:
    """
    内容アドレス (wire_id) でチャンクを保管する TLS/TCP サーバ (L3 OST)。

    DFS5 が自前で実装したものであり、mini_lustre の OST とは
    フレーム形式も塊の識別子も異なる（同一のポート上で TLS/TCP を使う点のみ共通）。

    クライアントごとのソケットタイムアウトは ``DFS5_OST_SOCKET_TIMEOUT``（既定 30 秒）で
    上書きできる。WAN では 1 往復が数百 ms になるため、LAN 時代の 2 秒固定から引き上げた。
    """

    def __init__(self, certfile: Path | str, keyfile: Path | str, host: str = "127.0.0.1", port: int = 0):
        self.store: Dict[str, bytes] = {}
        self.online: bool = True
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(certfile=str(certfile), keyfile=str(keyfile))

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

    def _accept_loop(self) -> None:
        while self.running:
            try:
                conn, _ = self.sock.accept()
                conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                conn.settimeout(ost_socket_timeout())
                threading.Thread(target=self._handle_client, args=(conn,), daemon=True).start()
            except Exception:
                break

    @staticmethod
    def _recv_exact(conn: ssl.SSLSocket, n: int) -> bytes:
        buf = bytearray()
        while len(buf) < n:
            chunk = conn.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("EOF")
            buf.extend(chunk)
        return bytes(buf)

    def _handle_client(self, raw_conn: socket.socket) -> None:
        ssl_conn: Optional[ssl.SSLSocket] = None
        try:
            ssl_conn = self.ctx.wrap_socket(raw_conn, server_side=True)
            while self.running:
                hdr = self._recv_exact(ssl_conn, 69)
                op = chr(hdr[0])

                # クライアントからの明示的切断要求 ('Q') で即座にループを抜ける
                if op == "Q":
                    break

                if not self.online:
                    ssl_conn.sendall(b"U")
                    break

                wire_id = hdr[1:65].decode("ascii")
                val = struct.unpack(">I", hdr[65:69])[0]

                if op == "H":
                    ssl_conn.sendall(b"1" if wire_id in self.store else b"0")
                elif op == "P":
                    data = self._recv_exact(ssl_conn, val)
                    if sha256_hex(data) != wire_id:
                        ssl_conn.sendall(b"E")
                    else:
                        self.store[wire_id] = data
                        ssl_conn.sendall(b"O")
                elif op == "G":
                    if wire_id not in self.store:
                        ssl_conn.sendall(struct.pack(">I", 0))
                    else:
                        blob = self.store[wire_id]
                        ssl_conn.sendall(struct.pack(">I", len(blob)) + blob)

                # --- バッチオペコード ---
                elif op == "B":  # Batch HAS
                    raw_ids = self._recv_exact(ssl_conn, val * 64)
                    bitmap = bytearray(b"O")
                    for i in range(val):
                        wid = raw_ids[i * 64 : (i + 1) * 64].decode("ascii")
                        bitmap.extend(b"1" if wid in self.store else b"0")
                    ssl_conn.sendall(bytes(bitmap))

                elif op == "M":  # Multi-PUT
                    ok = True
                    staged: Dict[str, bytes] = {}
                    for _ in range(val):
                        item_hdr = self._recv_exact(ssl_conn, 68)
                        wid = item_hdr[:64].decode("ascii")
                        blen = struct.unpack(">I", item_hdr[64:68])[0]
                        blob = self._recv_exact(ssl_conn, blen)
                        if sha256_hex(blob) != wid:
                            ok = False
                        else:
                            staged[wid] = blob
                    if ok:
                        self.store.update(staged)
                        ssl_conn.sendall(b"O")
                    else:
                        ssl_conn.sendall(b"E")

                elif op == "F":  # Batch GET
                    raw_ids = self._recv_exact(ssl_conn, val * 64)
                    out = bytearray(b"O")
                    for i in range(val):
                        wid = raw_ids[i * 64 : (i + 1) * 64].decode("ascii")
                        blob = self.store.get(wid, b"")
                        out.extend(struct.pack(">I", len(blob)) + blob)
                    ssl_conn.sendall(bytes(out))
                else:
                    break
        except Exception:
            pass
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

    接続タイムアウトは ``DFS5_OST_CONNECT_TIMEOUT``（既定 10 秒）で上書きできる。
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 0):
        self.host = host
        self.port = port
        self.bytes_sent: int = 0
        self.blob_bytes_sent: int = 0  # 暗号文本体の送信量（HAS などの固定費を除く）
        self.bytes_received: int = 0
        self.put_count: int = 0
        self.get_count: int = 0
        self.tls_handshakes: int = 0
        self.round_trips: int = 0

        self._ssl_ctx = ssl.create_default_context()
        self._ssl_ctx.check_hostname = False
        self._ssl_ctx.verify_mode = ssl.CERT_NONE

        self._pooled_conn: Optional[ssl.SSLSocket] = None
        self._session_depth: int = 0

    def reset_metrics(self) -> None:
        self.bytes_sent = 0
        self.blob_bytes_sent = 0
        self.bytes_received = 0
        self.put_count = 0
        self.get_count = 0
        self.tls_handshakes = 0
        self.round_trips = 0

    def _open_new_conn(self) -> ssl.SSLSocket:
        """接続を張る。到達不能・タイムアウトは ServiceUnavailableError に正規化する。

        WAN では経路断（WireGuard の一時停止など）で生の OSError や socket.timeout が
        飛ぶ。呼び出し側が「サーバ停止」と同じ扱いにできるよう例外をそろえる。
        """
        try:
            raw = socket.create_connection((self.host, self.port), timeout=ost_connect_timeout())
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
            hdr = b"B" + ZERO_WIRE_ID + struct.pack(">I", len(unique_ids))
            body = "".join(unique_ids).encode("ascii")
            conn.sendall(hdr + body)
            self.bytes_sent += len(hdr) + len(body)
            self.round_trips += 1

            status = self._recv_exact(conn, 1)
            self.bytes_received += 1
            if status == b"U":
                raise ServiceUnavailableError("L3 OST is offline")
            if status != b"O":
                raise ChunkIntegrityError(f"Batch HAS failed with status {status!r}")

            flags = self._recv_exact(conn, len(unique_ids))
            self.bytes_received += len(flags)
            return {wid: (flags[i : i + 1] == b"1") for i, wid in enumerate(unique_ids)}

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

        with self._acquire_conn() as conn:
            payload_parts = [b"M" + ZERO_WIRE_ID + struct.pack(">I", len(missing_ids))]
            for wid in missing_ids:
                blob = chunks[wid]
                payload_parts.append(wid.encode("ascii") + struct.pack(">I", len(blob)) + blob)

            full_payload = b"".join(payload_parts)
            conn.sendall(full_payload)
            self.bytes_sent += len(full_payload)
            self.blob_bytes_sent += sum(len(chunks[wid]) for wid in missing_ids)
            self.round_trips += 1

            resp = self._recv_exact(conn, 1)
            self.bytes_received += 1
            if resp == b"U":
                raise ServiceUnavailableError("L3 OST is offline")
            if resp != b"O":
                raise ChunkIntegrityError("Multi-PUT rejected by OST")

            self.put_count += len(missing_ids)
            return len(missing_ids)

    def batch_get(self, wire_ids: Sequence[str]) -> Dict[str, bytes]:
        unique_ids = list(dict.fromkeys(wire_ids))
        if not unique_ids:
            return {}

        with self._acquire_conn() as conn:
            hdr = b"F" + ZERO_WIRE_ID + struct.pack(">I", len(unique_ids))
            body = "".join(unique_ids).encode("ascii")
            conn.sendall(hdr + body)
            self.bytes_sent += len(hdr) + len(body)
            self.round_trips += 1

            status = self._recv_exact(conn, 1)
            self.bytes_received += 1
            if status == b"U":
                raise ServiceUnavailableError("L3 OST is offline")
            if status != b"O":
                raise ChunkIntegrityError(f"Batch GET failed with status {status!r}")

            result: Dict[str, bytes] = {}
            for wid in unique_ids:
                raw_len = self._recv_exact(conn, 4)
                self.bytes_received += 4
                blen = struct.unpack(">I", raw_len)[0]
                if blen == 0:
                    raise ChunkIntegrityError(f"Missing chunk on OST during batch_get: {wid}")
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


# 後方互換: 旧名。実体は ChunkStoreServer（mini_lustre の API ではない）。
MiniLustreOSTServer = ChunkStoreServer
