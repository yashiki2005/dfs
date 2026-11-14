#!/usr/bin/env python3
"""
dfs/cli.py
Mac と raspi5 のターミナルから直接実行できる dfs CLI エントリポイント。

サブコマンド:
  - serve    : L2 名簿 (HTTP JSON RPC) と L3 OST (TLS/TCP) デーモンを起動
  - delegate : L1 権威の委譲レコードを作成・署名し、L2 名簿へ登録
  - init     : ローカルのマウントディレクトリ (.clayfs / tree / config.json) を初期化
  - push     : L5 スナップショット取得 -> L3 暗号化チャンク転送 -> L4 CAS コミット & B7 照合
  - pull     : L2/L4 先頭版同期 (B6 検証) -> L3 チャンク取得・復号 -> L5 作業ツリー更新
  - status   : ローカルの HeadPin 状態とリモートの先頭版を比較表示
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from dfs.crypto import ChunkIntegrityError, normalize_path
    from dfs.l1_delegation import DelegationError, create_delegation_envelope
    from dfs.l2_registry import (
        ConflictError,
        DirectoryRegistryService,
        RegistryError,
        ServiceUnavailableError,
    )
    from dfs.l2_cache import CachedRegistryClient
    from dfs.l3_ost_adapter import (
        MAX_OST_HTTP_BODY_BYTES,
        OSTProtocolError,
        ost_socket_timeout,
    )
    from dfs.l3_store import ChunkStoreServer
    from dfs.l4_log import RollbackDetectedError, SilentDropDetectedError
    from dfs.l5_fs import DFSNode
    from dfs.paths import restrict_to_owner
    from dfs.private_io import ensure_private_dir, write_private_json
    from dfs.relay import (
        RelayAgent,
        RelayAuthError,
        RelayError,
        RelayHub,
        RelayNodeOfflineError,
        RelayTimeoutError,
        decode_relay_frame,
        encode_relay_frame,
    )
else:
    from .crypto import ChunkIntegrityError, normalize_path
    from .l1_delegation import DelegationError, create_delegation_envelope
    from .l2_registry import (
        ConflictError,
        DirectoryRegistryService,
        RegistryError,
        ServiceUnavailableError,
    )
    from .l2_cache import CachedRegistryClient
    from .l3_ost_adapter import (
        MAX_OST_HTTP_BODY_BYTES,
        OSTProtocolError,
        ost_socket_timeout,
    )
    from .l3_store import ChunkStoreServer
    from .l4_log import RollbackDetectedError, SilentDropDetectedError
    from .l5_fs import DFSNode
    from .paths import restrict_to_owner
    from .private_io import ensure_private_dir, write_private_json
    from .relay import (
        RelayAgent,
        RelayAuthError,
        RelayError,
        RelayHub,
        RelayNodeOfflineError,
        RelayTimeoutError,
        decode_relay_frame,
        encode_relay_frame,
    )


# ---------------------------------------------------------------------------
# WAN（高遅延）で L2 の 1 往復が LAN 時代の 5 秒固定で切れないよう、環境変数で
# 上書きできるようにする。既定は RTT 300ms 級を想定した 10 秒。
# ---------------------------------------------------------------------------
DEFAULT_L2_TIMEOUT = 10.0
# L2 の JSON-RPC は小さなエンベロープだけを扱う。巨大な body で
# サーバのメモリを消費させないよう、読み込み前に上限を設ける。
MAX_REGISTRY_BODY_BYTES = 8 * 1024 * 1024
MAX_REGISTRY_CONNECTIONS = 64
REGISTRY_REQUEST_TIMEOUT = 10.0


def l2_timeout() -> float:
    """L2 HTTP タイムアウト秒（既定 10 秒、``DFS_L2_TIMEOUT`` で変更）"""
    raw = os.environ.get("DFS_L2_TIMEOUT")
    if raw is None or raw.strip() == "":
        return DEFAULT_L2_TIMEOUT
    try:
        value = float(raw)
    except ValueError:
        return DEFAULT_L2_TIMEOUT
    return value if value > 0 else DEFAULT_L2_TIMEOUT


# ==========================================
# リモート L2 名簿 (HTTP JSON RPC) クライアント & サーバ
# ==========================================
class RemoteRegistryClient:
    """
    DirectoryRegistryService と同じメソッドシグネチャを持ち、
    HTTP 経由でリモート（またはローカル）の L2 名簿サーバと通信するクライアント。

    """

    def __init__(self, registry_url: str | Sequence[str]):
        raw_urls = [registry_url] if isinstance(registry_url, str) else list(registry_url)
        self.registry_urls: list[str] = []
        for raw in raw_urls:
            value = str(raw or "").strip().rstrip("/")
            if value and value not in self.registry_urls:
                self.registry_urls.append(value)
        if not self.registry_urls:
            raise ValueError("At least one L2 registry URL is required")
        # 書き込み先は先頭（主名簿）に固定する。
        self.registry_url = self.registry_urls[0]

    def _post_one(
        self,
        url: str,
        endpoint: str,
        payload: Dict[str, Any],
        timeout: Optional[float],
    ) -> Dict[str, Any]:
        """1 つの名簿へ POST する。タイムアウトは ``DFS_L2_TIMEOUT``（既定 10 秒）。

        高遅延 WAN では 1 往復だけで数百 ms かかるため、LAN 時代の 5 秒固定は
        切り詰めの原因になる。環境変数で伸ばせるようにしてある。
        """
        full_url = f"{url}{endpoint}"
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            full_url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout or l2_timeout()) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            try:
                err_body = json.loads(e.read().decode("utf-8"))
                err_type = err_body.get("error_type", "")
                err_msg = err_body.get("message", str(e))
            except Exception:
                if e.code >= 500:
                    raise ServiceUnavailableError(f"HTTP {e.code}: {e.reason}") from e
                raise RegistryError(f"HTTP {e.code}: {e.reason}") from e

            if err_type == "ConflictError":
                raise ConflictError(err_msg) from e
            if err_type == "DelegationError":
                raise DelegationError(err_msg) from e
            if err_type == "ChunkIntegrityError":
                raise ChunkIntegrityError(err_msg) from e
            if err_type == "ServiceUnavailableError":
                raise ServiceUnavailableError(err_msg) from e
            if e.code >= 500:
                raise ServiceUnavailableError(err_msg) from e
            raise RegistryError(err_msg) from e
        except urllib.error.URLError as e:
            raise ServiceUnavailableError(f"Cannot reach L2 registry at {url}: {e.reason}") from e
        except (TimeoutError, OSError) as e:
            # 高遅延 WAN でのタイムアウトや経路断。呼び出し側は「サーバ停止」と同じ扱いにする。
            raise ServiceUnavailableError(f"L2 registry timed out or is unreachable at {url}: {e}") from e

    def _post(
        self,
        endpoint: str,
        payload: Dict[str, Any],
        *,
        timeout: Optional[float] = None,
        read_failover: bool = False,
    ) -> Dict[str, Any]:
        """POST する。

        ``read_failover=True`` の読み取り API は、主名簿が接続不能・5xx のときに
        代替名簿を順に試す。書き込み API は常に主名簿だけを使う。
        """
        if not read_failover:
            try:
                return self._post_one(self.registry_url, endpoint, payload, timeout)
            except ServiceUnavailableError as primary_err:
                relay_urls = [u for u in self.registry_urls[1:] if "/relay/" in u]
                if not relay_urls:
                    raise
                last_err: ServiceUnavailableError = primary_err
                for relay_url in relay_urls:
                    try:
                        return self._post_one(relay_url, endpoint, payload, timeout)
                    except ServiceUnavailableError as e:
                        last_err = e
                raise last_err

        last_error: Optional[ServiceUnavailableError] = None
        empty_candidate: Optional[Dict[str, Any]] = None
        for url in self.registry_urls:
            try:
                result = self._post_one(url, endpoint, payload, timeout)
            except ServiceUnavailableError as e:
                last_error = e
                continue
            # resolve は主がまだ空でも、代替が先頭版を持っていることがある。
            # その場合は代替の応答を採用する。
            if endpoint == "/v1/resolve" and result.get("head_log") is None:
                if empty_candidate is None:
                    empty_candidate = result
                continue
            return result

        if empty_candidate is not None:
            return empty_candidate
        if last_error is not None:
            raise ServiceUnavailableError(
                f"All L2 registries are unreachable: {last_error}"
            ) from last_error
        raise ServiceUnavailableError("No L2 registries configured")

    def register_delegation(self, envelope: Dict[str, Any], now: int) -> Dict[str, Any]:
        # now は旧サーバとの互換用。現行サーバは認可判定に自分の時計を使う。
        res = self._post("/v1/delegate", {"envelope": envelope, "now": int(now)})
        return res["verified"]

    def announce_and_append(
        self,
        path: str,
        log_envelope: Dict[str, Any],
        locator_envelope: Dict[str, Any],
        now: int,
        role_epoch: int = 1,
    ) -> None:
        # now は旧サーバとの互換用。現行サーバは認可判定に自分の時計を使う。
        self._post(
            "/v1/announce",
            {
                "locator_envelope": locator_envelope,
                "log_envelope": log_envelope,
                "now": int(now),
                "path": path,
                "role_epoch": int(role_epoch),
            },
        )

    def resolve(
        self, path: str, version: Optional[int] = None
    ) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
        payload: Dict[str, Any] = {"path": path}
        if version is not None:
            payload["version"] = int(version)
        res = self._post("/v1/resolve", payload, read_failover=True)
        return res.get("delegation"), res.get("locator"), res.get("head_log")

    def history(self, path: str, limit: int = 50) -> List[Dict[str, Any]]:
        """署名済み L4 ログ履歴を新しい順に取得する。"""
        res = self._post(
            "/v1/history",
            {"path": path, "limit": int(limit)},
            read_failover=True,
        )
        rows = res.get("history", [])
        return rows if isinstance(rows, list) else []

    def list_paths(self) -> Dict[str, Any]:
        """登録済みのサブツリーと書き手公開鍵の一覧（``/v1/paths``）。"""
        return self._post("/v1/paths", {}, read_failover=True)

    def ost_info(self) -> Dict[str, Any]:
        """L3 OST の場所（``/v1/ost``）。ロケータが無い初回でも引ける。"""
        return self._post("/v1/ost", {}, read_failover=True)

    def root_anchor_info(self) -> Dict[str, Any]:
        """root アンカーのパスと公開鍵（``/v1/paths`` の一部）。

        クライアントは初回だけここから取り（TOFU）、以降は記録した値を信頼する。
        名簿が違う値を返しても、記録と食い違えば拒否する。
        """
        res = self._post("/v1/paths", {}, read_failover=True)
        return {"root_anchor": res.get("root_anchor", ""), "root_pubkey": res.get("root_pubkey", "")}

    def publish_archive(
        self, envelope: Dict[str, Any], role_epoch: int = 1
    ) -> Dict[str, Any]:
        """署名済みarchive descriptorを主名簿へ登録する。"""
        res = self._post(
            "/v1/archive",
            {"envelope": envelope, "role_epoch": int(role_epoch)},
        )
        return res.get("verified", {})

    def archives(
        self, path: str, version: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """署名済みarchive descriptor一覧を取得する。"""
        payload: Dict[str, Any] = {"path": path}
        if version is not None:
            payload["version"] = int(version)
        res = self._post("/v1/archives", payload, read_failover=True)
        rows = res.get("archives", [])
        return rows if isinstance(rows, list) else []

    def replicate_bundle(self, bundle: Dict[str, Any]) -> None:
        """主名簿から複製名簿へ、署名済みバンドルを送る。"""
        self._post("/v1/replicate", {"bundle": bundle}, timeout=3.0)

    def candidacy(self) -> Optional[Dict[str, Any]]:
        """署名付き立候補エンベロープ (``/v1/candidacy``) を取得する。"""
        res = self._post("/v1/candidacy", {}, read_failover=True)
        return res.get("candidacy")

    def announce_candidacy(self, envelope: Dict[str, Any]) -> Dict[str, Any]:
        """署名付き立候補エンベロープを主名簿へ登録する。"""
        res = self._post("/v1/candidacy/announce", {"envelope": envelope})
        return res.get("verified", {})

    def find_path_for_writer(self, writer_pubkey: str) -> Optional[str]:
        """書き手公開鍵に一致するサブツリーを探す（複数あれば最短のもの）。"""
        want = " ".join(writer_pubkey.split())
        found = [
            row["path"]
            for row in self.list_paths().get("paths", [])
            if " ".join(str(row.get("writer", "")).split()) == want
        ]
        if not found:
            return None
        return sorted(found, key=lambda p: (len(p), p))[0]


class BoundedThreadingHTTPServer(ThreadingHTTPServer):
    """接続ごとのスレッド数を制限し、過負荷時は明示的に 503 を返す。"""

    daemon_threads = True

    def __init__(
        self,
        server_address: tuple[str, int],
        handler: type[BaseHTTPRequestHandler],
        *,
        max_workers: int = MAX_REGISTRY_CONNECTIONS,
    ):
        if max_workers < 1:
            raise ValueError("max_workers must be >= 1")
        self._worker_slots = threading.BoundedSemaphore(max_workers)
        super().__init__(server_address, handler)

    def process_request(self, request, client_address) -> None:
        if not self._worker_slots.acquire(blocking=False):
            try:
                request.sendall(
                    b"HTTP/1.1 503 Service Unavailable\r\n"
                    b"Content-Length: 0\r\n"
                    b"Connection: close\r\n\r\n"
                )
            except OSError:
                pass
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._worker_slots.release()
            raise

    def process_request_thread(self, request, client_address) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._worker_slots.release()


class PersistentRegistryState:
    """サー再起動時にも L1 委譲・L2 ロケータ・L4 ログ・L3 チャンクを保持する永続化ラッパー"""

    def __init__(
        self,
        state_dir: Path,
        root_anchor: str,
        root_pubkey: str,
        chunks_dir: Optional[Path] = None,
    ):
        self.state_dir = state_dir
        self.state_file = state_dir / "registry_state.json"
        self.chunks_dir = Path(chunks_dir) if chunks_dir is not None else state_dir / "ost_chunks"
        self.chunks_dir = self.chunks_dir.expanduser()
        ensure_private_dir(self.chunks_dir)
        self.service = DirectoryRegistryService(root_anchor, root_pubkey)
        # L3 OST の広告用。`serve` の起動時に埋める（ロケータが無い初回でも引けるように）。
        self.ost_endpoint: str = ""
        self.ost_alternates: list[str] = []
        self.relay_endpoint: str = ""
        self.relay_endpoints: list[str] = []
        self.root_anchor = root_anchor
        # root アンカーの公開鍵。クライアントの初回（TOFU）が取得する。
        # ここから取った値をクライアントが記録し、以降は記録した値だけを信頼する。
        self.root_pubkey = root_pubkey.strip()
        self.role: str = "primary"
        self.role_epoch: int = 1
        # 書き込み系 API は「サービス更新 -> state 保存」まで同じ排他区間に入れる。
        self.lock = threading.RLock()
        self.own_registry_url: str = ""
        # 主名簿が受け取った署名済みバンドルを送る複製名簿。
        self.replica_registries: list[str] = []
        self._load()

    def _load(self) -> None:
        if not self.state_file.exists():
            return
        data = json.loads(self.state_file.read_text(encoding="utf-8"))
        self.service.delegations = data.get("delegations", {})
        self.service.logs = data.get("logs", {})
        self.service.locators = data.get("locators", {})
        raw_archives = data.get("archives", {})
        self.service.archives = {}
        if isinstance(raw_archives, dict):
            for path, values in raw_archives.items():
                if not isinstance(values, dict):
                    continue
                parsed: Dict[int, Dict[str, Any]] = {}
                for version, envelope in values.items():
                    try:
                        parsed[int(version)] = envelope
                    except (TypeError, ValueError):
                        continue
                self.service.archives[str(path)] = parsed
        self.service.candidacy = data.get("candidacy")
        self.role = str(data.get("role", "primary"))
        self.role_epoch = int(data.get("role_epoch", 1))

    def save(self) -> None:
        data = {
            "delegations": self.service.delegations,
            "archives": self.service.archives,
            "candidacy": self.service.candidacy,
            "locators": self.service.locators,
            "logs": self.service.logs,
            "role": self.role,
            "role_epoch": int(self.role_epoch),
        }
        write_private_json(self.state_file, data)

    def load_ost_chunks(self, ost: ChunkStoreServer) -> None:
        for f in self.chunks_dir.glob("*.blk"):
            ost.store[f.stem] = f.read_bytes()

    def save_ost_chunks(self, ost: ChunkStoreServer) -> None:
        store_lock = getattr(ost, "_store_lock", None)
        if store_lock is not None:
            with store_lock:
                items = list(ost.store.items())
        else:
            items = list(ost.store.items())
        for wid, blob in items:
            p = self.chunks_dir / f"{wid}.blk"
            if p.exists():
                continue
            fd, tmp_name = tempfile.mkstemp(
                prefix=f".{wid}.", suffix=".tmp", dir=str(self.chunks_dir)
            )
            tmp = Path(tmp_name)
            try:
                with os.fdopen(fd, "wb") as f:
                    f.write(blob)
                    f.flush()
                    os.fsync(f.fileno())
                os.replace(tmp, p)
            finally:
                try:
                    tmp.unlink()
                except FileNotFoundError:
                    pass

    def push_to_replicas(self, bundle: Optional[Dict[str, Any]]) -> None:
        """主名簿の更新を複製名簿へベストエフォートで送る。"""
        if not bundle:
            return
        for url in self.replica_registries:
            if self.own_registry_url and url.rstrip("/") == self.own_registry_url.rstrip("/"):
                continue
            try:
                RemoteRegistryClient(url).replicate_bundle(bundle)
            except Exception as e:  # noqa: BLE001 - 複製失敗で主の書き込みを落とさない
                print(f"[L2] replica {url} failed: {type(e).__name__}: {e}", file=sys.stderr)


def make_registry_http_handler(
    pstate: PersistentRegistryState,
    ost: ChunkStoreServer,
    relay_hub: Optional[RelayHub] = None,
):
    ost_load_lock = threading.Lock()
    ost_inflight = [0]
    ost_overload_threshold = max(
        1, int(os.environ.get("DFS_OST_OVERLOAD_INFLIGHT", "8") or "8")
    )

    class RegistryHTTPHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        request_timeout = REGISTRY_REQUEST_TIMEOUT

        def setup(self) -> None:
            super().setup()
            self.connection.settimeout(self.request_timeout)

        def log_message(self, fmt: str, *args: Any) -> None:
            sys.stderr.write(f"[L2-HTTP] {self.address_string()} - {fmt % args}\n")

        def _send_json(self, status: int, body: Dict[str, Any]) -> None:
            raw = json.dumps(body, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def _send_binary(
            self,
            status: int,
            body: bytes,
            content_type: str = "application/octet-stream",
            close: bool = False,
        ) -> None:
            with ost_load_lock:
                inflight_now = ost_inflight[0]
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            if close:
                self.send_header("Connection", "close")
            self.send_header("X-DFS-Inflight", str(inflight_now))
            if inflight_now >= ost_overload_threshold:
                self.send_header("X-DFS-Overloaded", "1")
            self.end_headers()
            if body:
                self.wfile.write(body)

        def _client_observed_ip(self) -> str:
            xff = self.headers.get("X-Forwarded-For") or ""
            if xff:
                first = xff.split(",")[0].strip()
                if first:
                    return first
            xri = (self.headers.get("X-Real-IP") or "").strip()
            if xri:
                return xri
            if self.client_address and self.client_address[0]:
                return str(self.client_address[0])
            return ""

        def _handle_ice(self) -> bool:
            from urllib.parse import parse_qs, urlsplit

            parsed = urlsplit(self.path)
            if parsed.path == "/_ice/stun":
                self._send_json(200, {"observed_ip": self._client_observed_ip()})
                return True
            if parsed.path == "/_ice/candidates":
                if relay_hub is None:
                    self._send_json(404, {"error_type": "RegistryError", "message": "Relay hub is not enabled"})
                    return True
                qs = parse_qs(parsed.query)
                node_id = (qs.get("node") or [""])[0] or None
                try:
                    payload = relay_hub.get_ice_candidates(node_id)
                except ValueError as e:
                    self._send_json(400, {"error_type": "RegistryError", "message": str(e)})
                    return True
                self._send_json(200, payload)
                return True
            if parsed.path == "/_ice/announce":
                if relay_hub is None:
                    self._send_json(404, {"error_type": "RegistryError", "message": "Relay hub is not enabled"})
                    return True
                try:
                    relay_hub.verify_token(self.headers.get("X-DFS-Relay-Token"))
                except RelayAuthError as e:
                    self._send_json(403, {"error_type": "RegistryError", "message": str(e)})
                    return True
                req = self._read_json_body()
                if req is None:
                    return True
                try:
                    payload = relay_hub.announce_peer(
                        node_id=str(req.get("node_id") or ""),
                        direct_endpoints=req.get("direct_endpoints") or [],
                        observed_ip=self._client_observed_ip(),
                        role=str(req.get("role") or "seeder"),
                    )
                except (ValueError, TypeError) as e:
                    self._send_json(400, {"error_type": "RegistryError", "message": str(e)})
                    return True
                self._send_json(200, payload)
                return True
            return False

        def _handle_relay_control(self) -> bool:
            from urllib.parse import parse_qs, urlsplit

            parsed = urlsplit(self.path)
            if not parsed.path.startswith("/_relay/"):
                return False
            if relay_hub is None:
                self._send_json(404, {"error_type": "RegistryError", "message": "Relay hub is not enabled"})
                return True
            try:
                relay_hub.verify_token(self.headers.get("X-DFS-Relay-Token"))
            except RelayAuthError as e:
                self._send_json(403, {"error_type": "RegistryError", "message": str(e)})
                return True

            qs = parse_qs(parsed.query)
            if parsed.path == "/_relay/status":
                self._send_json(200, relay_hub.status_snapshot())
                return True
            node_id = (qs.get("node") or [""])[0]
            if parsed.path == "/_relay/pull":
                self.connection.settimeout(35.0)
                raw_eps = self.headers.get("X-DFS-Direct-Endpoints") or ""
                direct_eps = [ep.strip() for ep in raw_eps.split(",") if ep.strip()]
                try:
                    req = relay_hub.pull_next(
                        node_id,
                        observed_ip=self._client_observed_ip(),
                        direct_endpoints=direct_eps or None,
                    )
                except ValueError as e:
                    self._send_json(400, {"error_type": "RegistryError", "message": str(e)})
                    return True
                finally:
                    self.connection.settimeout(self.request_timeout)
                if req is None:
                    self.send_response(204)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return True
                frame = encode_relay_frame(
                    {
                        "id": req.id,
                        "method": req.method,
                        "path": req.path,
                        "content_type": req.content_type,
                    },
                    req.body,
                )
                self._send_binary(200, frame)
                return True
            if parsed.path == "/_relay/reply":
                req_id = (qs.get("id") or [""])[0]
                raw = self._read_binary_body(MAX_OST_HTTP_BODY_BYTES + 1024 * 1024)
                if raw is None:
                    return True
                try:
                    hdr, resp_body = decode_relay_frame(raw)
                    ok = relay_hub.deliver_reply(
                        node_id=node_id,
                        req_id=req_id,
                        status=int(hdr.get("status", 200)),
                        content_type=str(hdr.get("content_type", "application/octet-stream")),
                        body=resp_body,
                    )
                except (RelayError, ValueError, TypeError) as e:
                    self._send_json(400, {"error_type": "RegistryError", "message": str(e)})
                    return True
                if not ok:
                    self._send_json(404, {"error_type": "RegistryError", "message": "Unknown relay request id"})
                    return True
                self._send_json(200, {"ok": True})
                return True
            self._send_json(404, {"error_type": "RegistryError", "message": f"Unknown relay path {parsed.path}"})
            return True

        def _handle_relay_forward(self, method: str) -> bool:
            if not self.path.startswith("/relay/"):
                return False
            if relay_hub is None:
                self._send_json(404, {"error_type": "RegistryError", "message": "Relay hub is not enabled"})
                return True
            rest = self.path[len("/relay/") :]
            node_id, sep, sub_path = rest.partition("/")
            if not sep or not node_id:
                self._send_json(404, {"error_type": "RegistryError", "message": "Malformed relay path"})
                return True
            target_path = "/" + sub_path
            max_bytes = (
                MAX_OST_HTTP_BODY_BYTES
                if target_path.startswith("/v1/ost/")
                else MAX_REGISTRY_BODY_BYTES
            )
            body = self._read_binary_body(max_bytes) if method == "POST" else b""
            if body is None:
                return True
            self.connection.settimeout(45.0)
            try:
                status, ct, resp_body = relay_hub.forward(
                    node_id=node_id,
                    method=method,
                    sub_path=target_path,
                    content_type=self.headers.get("Content-Type", "application/octet-stream"),
                    body=body,
                )
                self._send_binary(status, resp_body, content_type=ct)
            except RelayNodeOfflineError as e:
                self._send_json(503, {"error_type": "ServiceUnavailableError", "message": str(e)})
            except RelayTimeoutError as e:
                self._send_json(504, {"error_type": "ServiceUnavailableError", "message": str(e)})
            except ValueError as e:
                self._send_json(400, {"error_type": "RegistryError", "message": str(e)})
            finally:
                self.connection.settimeout(self.request_timeout)
            return True

        def do_GET(self) -> None:
            if self._handle_ice():
                return
            if self._handle_relay_control():
                return
            if self._handle_relay_forward("GET"):
                return
            self._send_json(404, {"error_type": "RegistryError", "message": f"Unknown path {self.path}"})

        def _read_binary_body(self, max_bytes: int) -> Optional[bytes]:
            if self.headers.get("Transfer-Encoding"):
                self.close_connection = True
                self._send_binary(400, b"ETransfer-Encoding is not supported", close=True)
                return None
            raw_length = self.headers.get("Content-Length", "0")
            try:
                length = int(raw_length)
            except (TypeError, ValueError):
                self.close_connection = True
                self._send_binary(400, b"Einvalid Content-Length", close=True)
                return None
            if length < 0 or length > max_bytes:
                self.close_connection = True
                self._send_binary(413, b"Epayload too large", close=True)
                return None
            try:
                return self.rfile.read(length) if length else b""
            except (OSError, TimeoutError, socket.timeout):
                self.close_connection = True
                self._send_binary(408, b"Erequest body timed out", close=True)
                return None

        def _handle_ost_http(self) -> None:
            self.connection.settimeout(max(self.request_timeout, ost_socket_timeout()))
            with ost_load_lock:
                ost_inflight[0] += 1
            try:
                raw_body = self._read_binary_body(MAX_OST_HTTP_BODY_BYTES)
                if raw_body is None:
                    return
                if self.path == "/v1/ost/batch_has":
                    self._send_binary(200, ost.batch_has_raw(raw_body))
                elif self.path == "/v1/ost/batch_get":
                    self._send_binary(200, ost.batch_get_raw(raw_body))
                elif self.path == "/v1/ost/batch_put":
                    ost.batch_put_raw(raw_body)
                    self._send_binary(200, b"O")
            except ServiceUnavailableError:
                self._send_binary(503, b"U")
            except (OSTProtocolError, ChunkIntegrityError, ValueError) as e:
                self._send_binary(400, f"E{e}".encode("utf-8", errors="replace"))
            except Exception as e:
                self._send_binary(500, f"E{e}".encode("utf-8", errors="replace"))
            finally:
                with ost_load_lock:
                    ost_inflight[0] = max(0, ost_inflight[0] - 1)
                self.connection.settimeout(self.request_timeout)

        def _read_json_body(self) -> Optional[Dict[str, Any]]:
            raw_length = self.headers.get("Content-Length", "0")
            try:
                length = int(raw_length)
            except (TypeError, ValueError):
                self._send_json(
                    400,
                    {"error_type": "RegistryError", "message": "Invalid Content-Length"},
                )
                return None
            if length < 0 or length > MAX_REGISTRY_BODY_BYTES:
                self._send_json(
                    413,
                    {
                        "error_type": "RegistryError",
                        "message": f"Request body exceeds {MAX_REGISTRY_BODY_BYTES} bytes",
                    },
                )
                return None
            try:
                raw = self.rfile.read(length) if length else b""
            except (OSError, TimeoutError, socket.timeout):
                self.close_connection = True
                self._send_json(
                    408,
                    {"error_type": "RegistryError", "message": "Request body timed out"},
                )
                return None
            if not raw:
                return {}
            try:
                req = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as e:
                self._send_json(
                    400,
                    {"error_type": "RegistryError", "message": f"Invalid JSON body: {e}"},
                )
                return None
            if not isinstance(req, dict):
                self._send_json(
                    400,
                    {"error_type": "RegistryError", "message": "JSON body must be an object"},
                )
                return None
            return req

        def do_POST(self) -> None:
            if self._handle_ice():
                return
            if self._handle_relay_control():
                return
            if self._handle_relay_forward("POST"):
                return
            if self.path in ("/v1/ost/batch_has", "/v1/ost/batch_get", "/v1/ost/batch_put"):
                self._handle_ost_http()
                return
            req = self._read_json_body()
            if req is None:
                return
            # 認可時刻は必ずサーバ側の時計で決める。リクエストの "now" は使わない。
            now = int(time.time())
            replica_bundle: Optional[Dict[str, Any]] = None
            response_body: Optional[Dict[str, Any]] = None
            try:
                with pstate.lock:
                    if self.path == "/v1/delegate":
                        if pstate.role != "primary":
                            raise RegistryError(
                                f"Registry is {pstate.role}; delegation writes require primary"
                            )
                        verified = pstate.service.register_delegation(req["envelope"], now=now)
                        pstate.save()
                        replica_bundle = pstate.service.replication_bundle(verified["path"])
                        response_body = {"ok": True, "verified": verified}
                    elif self.path == "/v1/announce":
                        if pstate.role != "primary":
                            raise RegistryError(
                                f"Registry is {pstate.role}; announce requires primary"
                            )
                        if int(req.get("role_epoch", 1)) != pstate.role_epoch:
                            raise ConflictError(
                                f"Registry role epoch mismatch: expected {pstate.role_epoch}, "
                                f"got {req.get('role_epoch')!r}"
                            )
                        pstate.service.announce_and_append(
                            path=req["path"],
                            log_envelope=req["log_envelope"],
                            locator_envelope=req["locator_envelope"],
                            now=now,
                            role_epoch=pstate.role_epoch,
                        )
                        pstate.save()
                        pstate.save_ost_chunks(ost)
                        replica_bundle = pstate.service.replication_bundle(req["path"])
                        response_body = {"ok": True}
                    elif self.path == "/v1/replicate":
                        updated = pstate.service.ingest_replica(req["bundle"], now=now)
                        pstate.save()
                        response_body = {"ok": True, "updated": updated}
                    elif self.path == "/v1/archive":
                        if pstate.role != "primary":
                            raise RegistryError(
                                f"Registry is {pstate.role}; archive publishing requires primary"
                            )
                        if int(req.get("role_epoch", 1)) != pstate.role_epoch:
                            raise ConflictError(
                                f"Registry role epoch mismatch: expected {pstate.role_epoch}, "
                                f"got {req.get('role_epoch')!r}"
                            )
                        verified = pstate.service.register_archive(
                            req["envelope"], now=now
                        )
                        pstate.save()
                        replica_bundle = pstate.service.replication_bundle(verified["path"])
                        response_body = {"ok": True, "verified": verified}
                    elif self.path == "/v1/archives":
                        rows = pstate.service.list_archives(
                            req["path"], version=req.get("version")
                        )
                        response_body = {
                            "archives": rows,
                            "count": len(rows),
                            "path": req["path"],
                        }
                    elif self.path == "/v1/resolve":
                        version = req.get("version")
                        del_env, loc_env, head_env = pstate.service.resolve(
                            req["path"], version=version
                        )
                        response_body = {
                            "delegation": del_env,
                            "head_log": head_env,
                            "locator": loc_env,
                        }
                    elif self.path == "/v1/history":
                        rows = pstate.service.history(
                            req["path"], limit=int(req.get("limit", 50))
                        )
                        response_body = {
                            "path": req["path"],
                            "history": rows,
                            "count": len(rows),
                        }
                    elif self.path == "/v1/paths":
                        # 登録済みのサブツリーと、その書き手公開鍵を返す。
                        # CLI が --path を省略したとき、鍵の指紋から自分のパスを探すのに使う。
                        rows = []
                        for path, env in sorted(pstate.service.delegations.items()):
                            p = env.get("payload", {})
                            head = pstate.service.logs.get(path) or []
                            rows.append({
                                "path": path,
                                "writer": p.get("writer", ""),
                                "epoch": p.get("epoch"),
                                "base_version": p.get("base_version"),
                                "head_version": head[-1]["payload"]["version"] if head else 0,
                            })
                        response_body = {
                            "root_anchor": pstate.root_anchor,
                            "root_pubkey": pstate.root_pubkey,
                            "paths": rows,
                        }
                    elif self.path == "/v1/candidacy":
                        response_body = {"candidacy": pstate.service.candidacy}
                    elif self.path == "/v1/candidacy/announce":
                        from .discovery import CandidacyError

                        try:
                            verified = pstate.service.set_candidacy(req["envelope"], now=now)
                        except CandidacyError as e:
                            raise RegistryError(str(e)) from e
                        pstate.save()
                        response_body = {"ok": True, "verified": verified}
                    elif self.path == "/v1/ost":
                        # L3 の場所を返す。ロケータ（endpoints）がまだ無い初回でも引けるように、
                        # サーバ自身が把握している endpoint を返す。
                        response_body = {
                            "endpoint": pstate.ost_endpoint,
                            "alternates": list(pstate.ost_alternates),
                            "relay_endpoint": pstate.relay_endpoint,
                            "relay_endpoints": list(pstate.relay_endpoints),
                            "locators": {
                                path: (env.get("payload", {}).get("endpoints") or [None])[0]
                                for path, env in pstate.service.locators.items()
                            },
                        }
                    else:
                        self._send_json(404, {"error_type": "RegistryError", "message": f"Unknown path {self.path}"})
                        return
                if replica_bundle is not None:
                    pstate.push_to_replicas(replica_bundle)
                if response_body is not None:
                    self._send_json(200, response_body)
            except (ConflictError, DelegationError, ChunkIntegrityError, ServiceUnavailableError, RegistryError) as e:
                self._send_json(400, {"error_type": type(e).__name__, "message": str(e)})
            except (KeyError, TypeError, ValueError) as e:
                self._send_json(400, {"error_type": "RegistryError", "message": f"Invalid request: {e}"})
            except Exception as e:
                self._send_json(500, {"error_type": "RegistryError", "message": f"Internal error: {e}"})

    return RegistryHTTPHandler


# ==========================================
# 設定ロード・ノード構築ヘルパー
# ==========================================
CONFIG_FILENAME = "dfs_config.json"


def load_node_from_mount(
    mount_dir: Path,
) -> Tuple[DFSNode, Dict[str, Any], CachedRegistryClient]:
    mount_root = mount_dir.expanduser().resolve()
    cfg_path = mount_root / ".clayfs" / CONFIG_FILENAME
    if not cfg_path.is_file():
        raise SystemExit(f"Error: {mount_root} is not initialized (missing {cfg_path}). Run 'dfs init' first.")

    ensure_private_dir(cfg_path.parent)
    restrict_to_owner(cfg_path)
    cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
    if cfg.get("read_only") or not cfg.get("priv_key"):
        priv_key = Path("")
        pub_key_str = ""
    else:
        priv_key = Path(cfg["priv_key"]).expanduser().resolve()
        pub_key_path = Path(cfg.get("pub_key") or f"{priv_key}.pub").expanduser().resolve()
        pub_key_str = pub_key_path.read_text(encoding="utf-8").strip()

    reg_urls = [cfg["registry_url"], *(cfg.get("registry_alternates") or [])]
    reg_client = CachedRegistryClient(
        RemoteRegistryClient(reg_urls),
        mount_root / ".clayfs" / "l2_cache.json",
    )
    node = DFSNode(
        name=cfg["node_name"],
        sub_path=cfg["sub_path"],
        mount_root=mount_root,
        priv_key_path=priv_key,
        pub_key_str=pub_key_str,
        tree_secret=cfg["tree_secret"],
        registry=reg_client,  # type: ignore[arg-type]
        ost_host=cfg.get("ost_host", ""),
        ost_port=int(cfg.get("ost_port", 0) or 0),
        ost_endpoint=cfg.get("ost_endpoint") or None,
        root_pubkey=cfg.get("root_pubkey"),
        ost_alternates=cfg.get("ost_alternates") or [],
        libp2p_peers=cfg.get("libp2p_peers") or [],
        libp2p_psk=cfg.get("libp2p_psk") or "",
        role_epoch=int(cfg.get("role_epoch", 1)),
        compression=str(cfg.get("compression", "auto") or "auto"),
    )
    return node, cfg, reg_client


# ==========================================
# サブコマンド実装
# ==========================================
def cmd_serve(args: argparse.Namespace) -> None:
    state_dir = Path(args.state_dir).expanduser().resolve()
    ensure_private_dir(state_dir)
    chunks_dir = (
        Path(args.ost_dir).expanduser().resolve()
        if getattr(args, "ost_dir", None)
        else state_dir / "ost_chunks"
    )
    ensure_private_dir(chunks_dir)

    root_pub_path = Path(args.root_pubkey).expanduser().resolve()
    root_pubkey = root_pub_path.read_text(encoding="utf-8").strip()

    cert = state_dir / "ost_cert.pem"
    key = state_dir / "ost_key.pem"
    if not cert.exists() or not key.exists():
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-keyout", str(key), "-out", str(cert),
                "-days", "365", "-nodes", "-subj", "/CN=dfs-ost",
            ],
            check=True,
            capture_output=True,
        )

    ost = ChunkStoreServer(cert, key, host=args.bind, port=args.ost_port)
    pstate = PersistentRegistryState(
        state_dir, args.root_anchor, root_pubkey, chunks_dir=chunks_dir
    )
    if getattr(args, "role", None):
        pstate.role = str(args.role)
    if getattr(args, "role_epoch", None) is not None:
        pstate.role_epoch = int(args.role_epoch)
    pstate.save()
    pstate.load_ost_chunks(ost)
    pstate.replica_registries = [
        value.strip().rstrip("/")
        for value in (getattr(args, "replica", None) or [])
        if value.strip()
    ]

    # 自前の L3 の場所を広告する（--advertise があれば優先。無ければ bind から推定）
    advertised_host = args.advertise or ("127.0.0.1" if args.bind in ("0.0.0.0", "::") else args.bind)
    endpoint_host = f"[{advertised_host}]" if ":" in advertised_host else advertised_host
    pstate.ost_endpoint = f"tls://{endpoint_host}:{ost.port}"
    pstate.own_registry_url = f"http://{endpoint_host}:{args.registry_port}"

    relay_token = getattr(args, "relay_token", None) or os.environ.get("DFS_RELAY_TOKEN", "")
    enable_relay = bool(
        getattr(args, "enable_relay", False)
        or os.environ.get("DFS_ENABLE_RELAY", "").strip() in ("1", "true", "yes")
        or relay_token
    )
    if (
        enable_relay
        and not relay_token
        and args.bind not in ("127.0.0.1", "::1", "localhost")
        and os.environ.get("DFS_RELAY_ALLOW_UNAUTH", "").strip() not in ("1", "true", "yes")
    ):
        raise SystemExit(
            "Non-loopback relay hub requires --relay-token or DFS_RELAY_TOKEN "
            "(set DFS_RELAY_ALLOW_UNAUTH=1 to override)"
        )
    relay_hub = RelayHub(token=relay_token) if enable_relay else None

    raw_relays = getattr(args, "relay", None) or []
    if isinstance(raw_relays, str):
        raw_relays = [raw_relays]
    relay_urls = [str(u).strip().rstrip("/") for u in raw_relays if str(u).strip()]
    relay_node = (getattr(args, "relay_node", None) or "").strip()
    if relay_urls and not relay_node:
        raise SystemExit("--relay requires --relay-node")
    if relay_urls and relay_node:
        for r_url in relay_urls:
            ep = f"{r_url}/relay/{relay_node}"
            if ep not in pstate.relay_endpoints:
                pstate.relay_endpoints.append(ep)
            if ep not in pstate.ost_alternates:
                pstate.ost_alternates.append(ep)
        pstate.relay_endpoint = pstate.relay_endpoints[0]

    handler = make_registry_http_handler(pstate, ost, relay_hub=relay_hub)
    httpd = BoundedThreadingHTTPServer((args.bind, args.registry_port), handler)

    relay_agents: List[RelayAgent] = []
    if relay_urls and relay_node:
        direct_eps = [ep for ep in (pstate.ost_endpoint, pstate.own_registry_url) if ep]
        for r_url in relay_urls:
            agent = RelayAgent(
                relay_url=r_url,
                node_id=relay_node,
                local_port=httpd.server_port,
                token=relay_token,
                workers=int(getattr(args, "relay_workers", 4) or 4),
                direct_endpoints=direct_eps,
            )
            agent.start()
            relay_agents.append(agent)

    # 実際にサーバを動かしているプロセスの PID を残す。
    # Windows の venv 版 python.exe は本体を子プロセスで起動するため、
    # 起動側が Popen で得る PID はサーバ本体とは限らない。
    pid_file = state_dir / "serve.pid"
    pid_file.write_text(str(os.getpid()), encoding="utf-8")

    # 停止要求ファイルを見張る。SIGTERM / taskkill に頼らず、どの OS でも
    # httpd.shutdown() 経由で finally（状態とチャンクの保存）を通すため。
    stop_request = state_dir / "stop.request"

    def _watch_stop() -> None:
        while True:
            if stop_request.exists():
                try:
                    stop_request.unlink()
                except OSError:
                    pass
                httpd.shutdown()
                return
            time.sleep(0.5)

    threading.Thread(target=_watch_stop, daemon=True).start()

    print(f"[dfs serve] Root Anchor : {args.root_anchor}")
    print(f"[dfs serve] Role        : {pstate.role} (epoch={pstate.role_epoch})")
    print(f"[dfs serve] State Dir   : {state_dir}")
    print(f"[dfs serve] OST Dir     : {pstate.chunks_dir}")
    print(f"[dfs serve] L2 Registry : http://{args.bind}:{args.registry_port}")
    print(f"[dfs serve] L3 OST (TLS): {pstate.ost_endpoint}")
    if relay_hub is not None:
        print(f"[dfs serve] Relay Hub   : enabled (token={'set' if relay_token else 'none'})")
    if relay_agents:
        print(f"[dfs serve] Relay Agent : {', '.join(pstate.relay_endpoints)}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[dfs serve] Shutting down...")
    finally:
        for agent in relay_agents:
            agent.close()
        with pstate.lock:
            pstate.save()
            pstate.save_ost_chunks(ost)
        ost.close()
        try:
            pid_file.unlink()
        except OSError:
            pass
        httpd.server_close()


def cmd_promote(args: argparse.Namespace) -> None:
    """停止中の registry state を primary に昇格する（ローカル操作）。"""
    state_dir = Path(args.state_dir).expanduser().resolve()
    state_file = state_dir / "registry_state.json"
    if not state_file.is_file():
        raise SystemExit(f"State file not found: {state_file}")
    data = json.loads(state_file.read_text(encoding="utf-8"))
    current = int(data.get("role_epoch", 1))
    requested = int(args.role_epoch) if args.role_epoch is not None else current + 1
    if requested <= current:
        raise SystemExit(
            f"role epoch must increase: current={current}, requested={requested}"
        )
    data["role"] = "primary"
    data["role_epoch"] = requested
    write_private_json(state_file, data)
    print(f"[dfs promote] primary role epoch -> {requested}")
    print(f"[dfs promote] state: {state_file}")
    print("[dfs promote] restart 'dfs serve' on this node with --role primary")
    print(f"               (or --role-epoch {requested})")


def cmd_delegate(args: argparse.Namespace) -> None:
    priv_key = Path(args.signing_key).expanduser().resolve()
    writer_pub = Path(args.writer_pubkey).expanduser().resolve().read_text(encoding="utf-8").strip()
    now = int(time.time())

    env = create_delegation_envelope(
        parent_priv_key=priv_key,
        parent=args.parent,
        path=args.path,
        writer_pubkey=writer_pub,
        epoch=args.epoch,
        base_version=args.base_version,
        issued_at=now - 60,
        expires_at=now + int(args.ttl_days * 86400),
    )

    if args.output:
        Path(args.output).write_text(json.dumps(env, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"[dfs delegate] Wrote signed delegation envelope to {args.output}")

    if args.registry:
        client = RemoteRegistryClient(args.registry)
        verified = client.register_delegation(env, now=now)
        print(
            f"[dfs delegate] Registered on {args.registry}: "
            f"path={verified['path']} epoch={verified['epoch']} base_version={verified['base_version']}"
        )


def cmd_init(args: argparse.Namespace) -> None:
    mount_root = Path(args.mount).expanduser().resolve()
    clayfs_dir = mount_root / ".clayfs"
    tree_dir = mount_root / "tree"
    ensure_private_dir(clayfs_dir)
    tree_dir.mkdir(parents=True, exist_ok=True)

    host, port_str = args.ost.split(":", 1)
    cfg = {
        "delegation_epoch": int(args.epoch),
        "node_name": args.name,
        "ost_host": host,
        "ost_port": int(port_str),
        "priv_key": str(Path(args.key).expanduser().resolve()),
        "registry_url": args.registry,
        "sub_path": normalize_path(args.path),
        "tree_secret": args.secret,
    }
    cfg_path = clayfs_dir / CONFIG_FILENAME
    write_private_json(cfg_path, cfg)
    print(f"[dfs init] Initialized mount at {mount_root}")
    print(f"  Working tree : {tree_dir}")
    print(f"  Snapshots    : {clayfs_dir / 'snapshots'}")


def _emit_metrics(
    args: argparse.Namespace,
    node: Any,
    direction: str,
    version: int,
    elapsed_ms: float,
    payload_bytes: int,
) -> None:
    """計測ハーネス向けに L3 の往復回数・転送量を機械可読で出す（``--metrics`` 指定時のみ）。"""
    if not getattr(args, "metrics", False):
        return
    ost = node.read_ost if direction == "pull" else node.ost
    row = {
        "direction": direction,
        "version": int(version),
        "elapsed_ms": round(elapsed_ms, 3),
        "round_trips": int(ost.round_trips),
        "bytes_sent": int(ost.bytes_sent),
        "bytes_received": int(ost.bytes_received),
        "blob_bytes_sent": int(ost.blob_bytes_sent),
        "put_count": int(ost.put_count),
        "get_count": int(ost.get_count),
        "tls_handshakes": int(ost.tls_handshakes),
        "payload_bytes": int(payload_bytes),
    }
    print("[dfs metrics] " + json.dumps(row, sort_keys=True, ensure_ascii=False))


def cmd_push(args: argparse.Namespace) -> None:
    node, cfg, _ = load_node_from_mount(Path(args.mount))
    epoch = int(args.epoch) if args.epoch is not None else int(cfg.get("delegation_epoch", 1))
    now = int(time.time())

    mounts: Dict[str, str] = {}
    for m in args.delegated_mount or []:
        if "=" not in m:
            raise SystemExit(f"Invalid --delegated-mount format {m!r} (expected DIR_NAME=/full/sub/path)")
        k, v = m.split("=", 1)
        mounts[k] = v

    t0 = time.perf_counter()
    try:
        log_env, snap_dir, wire_bytes = node.push(delegation_epoch=epoch, now=now, delegated_mounts=mounts)
    except ConflictError as e:
        raise SystemExit(f"[REJECTED: Single-Writer Conflict] {e}\nHint: Run 'dfs pull' first.") from e
    except DelegationError as e:
        raise SystemExit(f"[REJECTED: L1 Delegation Error] {e}") from e
    except SilentDropDetectedError as e:
        raise SystemExit(f"[ALERT: Evil B7 Silent Drop Detected] {e}") from e
    except ServiceUnavailableError as e:
        raise SystemExit(f"[UNAVAILABLE: L2/L3 Unreachable] {e}") from e
    except ChunkIntegrityError as e:
        raise SystemExit(f"[ALERT: Evil A2 Chunk Integrity Error] {e}") from e

    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    p = log_env["payload"]
    print(
        f"[dfs push] OK v{p['version']} (epoch={p['delegation_epoch']}) "
        f"| root={p['root_plain_id'][:12]}... | sent={wire_bytes} B | {elapsed_ms:.1f} ms"
    )
    print(f"  Snapshot saved at: {snap_dir}")
    _emit_metrics(args, node, direction="push", version=p["version"], elapsed_ms=elapsed_ms, payload_bytes=wire_bytes)


def cmd_pull(args: argparse.Namespace) -> None:
    node, cfg, _ = load_node_from_mount(Path(args.mount))
    t0 = time.perf_counter()
    try:
        snap_dir = node.pull()
    except RollbackDetectedError as e:
        raise SystemExit(f"[ALERT: Evil B6 Rollback Detected] {e}") from e
    except ChunkIntegrityError as e:
        raise SystemExit(f"[ALERT: Evil A2 Chunk Integrity Error] {e}") from e
    except ServiceUnavailableError as e:
        raise SystemExit(f"[UNAVAILABLE: L2/L3 Unreachable] {e}") from e

    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    pin = node.l4.pin
    if cfg.get("delegation_epoch") != pin.delegation_epoch:
        cfg["delegation_epoch"] = pin.delegation_epoch
        write_private_json(node.clayfs.clayfs_meta / CONFIG_FILENAME, cfg)
    print(
        f"[dfs pull] OK v{pin.version} (epoch={pin.delegation_epoch}) "
        f"| recv={node.read_ost.bytes_received} B | {elapsed_ms:.1f} ms"
    )
    print(f"  Working tree updated : {node.clayfs.work_tree}")
    print(f"  Snapshot saved at    : {snap_dir}")
    _emit_metrics(
        args, node, direction="pull", version=pin.version,
        elapsed_ms=elapsed_ms, payload_bytes=node.read_ost.bytes_received,
    )


def cmd_status(args: argparse.Namespace) -> None:
    node, cfg, reg = load_node_from_mount(Path(args.mount))
    pin = node.l4.pin
    print(f"Node Name   : {cfg['node_name']}")
    print(f"Subtree Path: {cfg['sub_path']}")
    print(f"Local Pin   : v{pin.version} (epoch={pin.delegation_epoch}, hash={pin.entry_hash[:12]}...)")
    try:
        del_env, _, head_env = reg.resolve(cfg["sub_path"])
        if del_env:
            dp = del_env["payload"]
            print(f"Active L1   : epoch={dp['epoch']} base_version={dp['base_version']} writer={dp['writer'][:36]}...")
        if head_env:
            hp = head_env["payload"]
            print(f"Remote Head : v{hp['version']} (epoch={hp['delegation_epoch']}, hash={head_env['entry_hash'][:12]}...)")
        else:
            print("Remote Head : (empty)")
    except Exception as e:
        print(f"Remote Head : [unreachable: {e}]")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="dfs", description="dfs: Layered Single-Writer Distributed File System CLI")
    sub = parser.add_subparsers(dest="cmd", required=True)

    # serve
    p_serve = sub.add_parser("serve", help="Run L2 Registry (HTTP) and L3 OST (TLS/TCP) daemon")
    p_serve.add_argument("--bind", default="0.0.0.0", help="Bind address (default: 0.0.0.0)")
    p_serve.add_argument("--registry-port", type=int, default=9440, help="L2 HTTP port (default: 9440)")
    p_serve.add_argument("--ost-port", type=int, default=9443, help="L3 OST TLS port (default: 9443)")
    p_serve.add_argument("--root-anchor", default="/example.com", help="Root anchor path (default: /example.com)")
    p_serve.add_argument("--root-pubkey", required=True, help="Path to root anchor .pub file")
    p_serve.add_argument("--state-dir", default="~/.dfs_server", help="Server persistence directory")
    p_serve.add_argument(
        "--ost-dir",
        help="L3 OST チャンクの保存先（既定: <state-dir>/ost_chunks）",
    )
    p_serve.add_argument(
        "--role", choices=["primary", "secondary"],
        help="Registry role（既存 state の値を上書き）",
    )
    p_serve.add_argument(
        "--role-epoch", type=int,
        help="Registry fencing epoch（既存 state の値を上書き）",
    )
    p_serve.add_argument(
        "--advertise",
        help="L2 が L3 の場所として広告するホスト名/IP（既定は bind から推定）",
    )
    p_serve.add_argument(
        "--replica",
        action="append",
        default=[],
        help="主名簿から複製する代替名簿 URL（複数指定可。例: http://host:19440）",
    )
    p_serve.add_argument(
        "--enable-relay",
        action="store_true",
        help="root リレーハブ (/relay/<node>/..., /_relay/*) を有効にする",
    )
    p_serve.add_argument(
        "--relay-token",
        help="リレー認証トークン (未指定時は DFS_RELAY_TOKEN を参照)",
    )
    p_serve.add_argument(
        "--relay",
        action="append",
        default=[],
        help="NAT 裏からアウトバウンド接続するパブリックリレー URL（複数指定可。例: https://dfs.yashiki.top）",
    )
    p_serve.add_argument(
        "--relay-node",
        help="リレー上で名乗るノード ID (例: mac1 -> /relay/mac1/...)",
    )
    p_serve.add_argument(
        "--relay-workers",
        type=int,
        default=4,
        help="リレーの同時待ち受けワーカー数 (既定: 4)",
    )
    p_serve.set_defaults(func=cmd_serve)

    p_promote = sub.add_parser(
        "promote", help="停止中の registry state を primary に昇格する"
    )
    p_promote.add_argument("--state-dir", default="~/.dfs_server")
    p_promote.add_argument("--role-epoch", type=int)
    p_promote.set_defaults(func=cmd_promote)

    # delegate
    p_del = sub.add_parser("delegate", help="Sign and register an L1 delegation record")
    p_del.add_argument("--parent", required=True, help="Parent path (e.g. /example.com)")
    p_del.add_argument("--path", required=True, help="Delegated child path (e.g. /example.com/alice)")
    p_del.add_argument("--signing-key", required=True, help="Parent private key path")
    p_del.add_argument("--writer-pubkey", required=True, help="New writer public key (.pub) path")
    p_del.add_argument("--epoch", type=int, default=1, help="Delegation epoch (>=1)")
    p_del.add_argument("--base-version", type=int, default=0, help="L4 base_version to continue from")
    p_del.add_argument("--ttl-days", type=int, default=365, help="Validity period in days")
    p_del.add_argument("--registry", help="L2 Registry URL (e.g. http://raspi5.local:9440)")
    p_del.add_argument("--output", help="Optional file path to save the signed JSON envelope")
    p_del.set_defaults(func=cmd_delegate)

    # init
    p_init = sub.add_parser("init", help="Initialize a local dfs mount directory")
    p_init.add_argument("--mount", required=True, help="Mount root directory")
    p_init.add_argument("--name", default="node", help="Node identifier (e.g. mac, raspi5)")
    p_init.add_argument("--path", required=True, help="Subtree path (e.g. /example.com/alice/notes)")
    p_init.add_argument("--key", required=True, help="Writer OpenSSH Ed25519 private key path")
    p_init.add_argument("--secret", required=True, help="Subtree shared secret for Convergent AEAD")
    p_init.add_argument("--registry", required=True, help="L2 Registry URL (e.g. http://raspi5.local:9440)")
    p_init.add_argument("--ost", required=True, help="L3 OST host:port (e.g. raspi5.local:9443)")
    p_init.add_argument("--epoch", type=int, default=1, help="Initial delegation epoch")
    p_init.set_defaults(func=cmd_init)

    # push
    p_push = sub.add_parser("push", help="Snapshot, encrypt, upload chunks, and commit next L4 version")
    p_push.add_argument("--mount", default=".", help="Mount root directory")
    p_push.add_argument("--epoch", type=int, help="Override delegation epoch")
    p_push.add_argument("--metrics", action="store_true", help="Print machine-readable L3 metrics")
    p_push.add_argument(
        "--delegated-mount",
        action="append",
        help="Mark child directory as delegated boundary (format: DIR_NAME=/full/sub/path)",
    )
    p_push.set_defaults(func=cmd_push)

    # pull
    p_pull = sub.add_parser("pull", help="Verify remote head (B6), download chunks (A2), and update work tree")
    p_pull.add_argument("--mount", default=".", help="Mount root directory")
    p_pull.add_argument("--metrics", action="store_true", help="Print machine-readable L3 metrics")
    p_pull.set_defaults(func=cmd_pull)

    # status
    p_stat = sub.add_parser("status", help="Show local HeadPin and remote L2/L4 status")
    p_stat.add_argument("--mount", default=".", help="Mount root directory")
    p_stat.set_defaults(func=cmd_status)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
