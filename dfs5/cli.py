#!/usr/bin/env python3
"""
dfs5/cli.py
Mac と raspi5 のターミナルから直接実行できる dfs5 CLI エントリポイント。

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
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Optional, Sequence, Tuple

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from dfs5.crypto import ChunkIntegrityError, normalize_path
    from dfs5.l1_delegation import DelegationError, create_delegation_envelope
    from dfs5.l2_registry import (
        ConflictError,
        DirectoryRegistryService,
        RegistryError,
        ServiceUnavailableError,
    )
    from dfs5.l3_store import ChunkStoreServer
    from dfs5.l4_log import RollbackDetectedError, SilentDropDetectedError
    from dfs5.l5_clayfs import DFS5Node
    from dfs5.paths import restrict_to_owner
    from dfs5.private_io import ensure_private_dir, write_private_json
else:
    from .crypto import ChunkIntegrityError, normalize_path
    from .l1_delegation import DelegationError, create_delegation_envelope
    from .l2_registry import (
        ConflictError,
        DirectoryRegistryService,
        RegistryError,
        ServiceUnavailableError,
    )
    from .l3_store import ChunkStoreServer
    from .l4_log import RollbackDetectedError, SilentDropDetectedError
    from .l5_clayfs import DFS5Node
    from .paths import restrict_to_owner
    from .private_io import ensure_private_dir, write_private_json


# ---------------------------------------------------------------------------
# WAN（高遅延）で L2 の 1 往復が LAN 時代の 5 秒固定で切れないよう、環境変数で
# 上書きできるようにする。既定は RTT 300ms 級を想定した 10 秒。
# ---------------------------------------------------------------------------
DEFAULT_L2_TIMEOUT = 10.0
# L2 の JSON-RPC は小さなエンベロープだけを扱う。巨大な body で
# サーバのメモリを消費させないよう、読み込み前に上限を設ける。
MAX_REGISTRY_BODY_BYTES = 8 * 1024 * 1024


def l2_timeout() -> float:
    """L2 HTTP タイムアウト秒（既定 10 秒、``DFS5_L2_TIMEOUT`` で変更）"""
    raw = os.environ.get("DFS5_L2_TIMEOUT")
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
        """1 つの名簿へ POST する。タイムアウトは ``DFS5_L2_TIMEOUT``（既定 10 秒）。

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
            return self._post_one(self.registry_url, endpoint, payload, timeout)

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
    ) -> None:
        # now は旧サーバとの互換用。現行サーバは認可判定に自分の時計を使う。
        self._post(
            "/v1/announce",
            {
                "locator_envelope": locator_envelope,
                "log_envelope": log_envelope,
                "now": int(now),
                "path": path,
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

    def replicate_bundle(self, bundle: Dict[str, Any]) -> None:
        """主名簿から複製名簿へ、署名済みバンドルを送る。"""
        self._post("/v1/replicate", {"bundle": bundle}, timeout=3.0)

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


class PersistentRegistryState:
    """サー再起動時にも L1 委譲・L2 ロケータ・L4 ログ・L3 チャンクを保持する永続化ラッパー"""

    def __init__(self, state_dir: Path, root_anchor: str, root_pubkey: str):
        self.state_dir = state_dir
        self.state_file = state_dir / "registry_state.json"
        self.chunks_dir = state_dir / "ost_chunks"
        self.chunks_dir.mkdir(parents=True, exist_ok=True)
        self.service = DirectoryRegistryService(root_anchor, root_pubkey)
        # L3 OST の広告用。`serve` の起動時に埋める（ロケータが無い初回でも引けるように）。
        self.ost_endpoint: str = ""
        self.root_anchor = root_anchor
        # root アンカーの公開鍵。クライアントの初回（TOFU）が取得する。
        # ここから取った値をクライアントが記録し、以降は記録した値だけを信頼する。
        self.root_pubkey = root_pubkey.strip()
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

    def save(self) -> None:
        data = {
            "delegations": self.service.delegations,
            "locators": self.service.locators,
            "logs": self.service.logs,
        }
        write_private_json(self.state_file, data)

    def load_ost_chunks(self, ost: ChunkStoreServer) -> None:
        for f in self.chunks_dir.glob("*.blk"):
            ost.store[f.stem] = f.read_bytes()

    def save_ost_chunks(self, ost: ChunkStoreServer) -> None:
        for wid, blob in list(ost.store.items()):
            p = self.chunks_dir / f"{wid}.blk"
            if not p.exists():
                p.write_bytes(blob)

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


def make_registry_http_handler(pstate: PersistentRegistryState, ost: ChunkStoreServer):
    class RegistryHTTPHandler(BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args: Any) -> None:
            sys.stderr.write(f"[L2-HTTP] {self.address_string()} - {fmt % args}\n")

        def _send_json(self, status: int, body: Dict[str, Any]) -> None:
            raw = json.dumps(body, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

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
            raw = self.rfile.read(length) if length else b""
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
            req = self._read_json_body()
            if req is None:
                return
            # 認可時刻は必ずサーバ側の時計で決める。リクエストの "now" は使わない。
            now = int(time.time())
            try:
                with pstate.lock:
                    if self.path == "/v1/delegate":
                        verified = pstate.service.register_delegation(req["envelope"], now=now)
                        pstate.save()
                        pstate.push_to_replicas(
                            pstate.service.replication_bundle(verified["path"])
                        )
                        self._send_json(200, {"ok": True, "verified": verified})
                    elif self.path == "/v1/announce":
                        pstate.service.announce_and_append(
                            path=req["path"],
                            log_envelope=req["log_envelope"],
                            locator_envelope=req["locator_envelope"],
                            now=now,
                        )
                        pstate.save()
                        pstate.save_ost_chunks(ost)
                        pstate.push_to_replicas(
                            pstate.service.replication_bundle(req["path"])
                        )
                        self._send_json(200, {"ok": True})
                    elif self.path == "/v1/replicate":
                        updated = pstate.service.ingest_replica(req["bundle"], now=now)
                        pstate.save()
                        self._send_json(200, {"ok": True, "updated": updated})
                    elif self.path == "/v1/resolve":
                        version = req.get("version")
                        del_env, loc_env, head_env = pstate.service.resolve(
                            req["path"], version=version
                        )
                        self._send_json(
                            200,
                            {
                                "delegation": del_env,
                                "head_log": head_env,
                                "locator": loc_env,
                            },
                        )
                    elif self.path == "/v1/history":
                        rows = pstate.service.history(
                            req["path"], limit=int(req.get("limit", 50))
                        )
                        self._send_json(
                            200,
                            {"path": req["path"], "history": rows, "count": len(rows)},
                        )
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
                        self._send_json(200, {
                            "root_anchor": pstate.root_anchor,
                            "root_pubkey": pstate.root_pubkey,
                            "paths": rows,
                        })
                    elif self.path == "/v1/ost":
                        # L3 の場所を返す。ロケータ（endpoints）がまだ無い初回でも引けるように、
                        # サーバ自身が把握している endpoint を返す。
                        self._send_json(200, {
                            "endpoint": pstate.ost_endpoint,
                            "locators": {
                                path: (env.get("payload", {}).get("endpoints") or [None])[0]
                                for path, env in pstate.service.locators.items()
                            },
                        })
                    else:
                        self._send_json(404, {"error_type": "RegistryError", "message": f"Unknown path {self.path}"})
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
CONFIG_FILENAME = "dfs5_config.json"


def load_node_from_mount(mount_dir: Path) -> Tuple[DFS5Node, Dict[str, Any], RemoteRegistryClient]:
    mount_root = mount_dir.expanduser().resolve()
    cfg_path = mount_root / ".clayfs" / CONFIG_FILENAME
    if not cfg_path.is_file():
        raise SystemExit(f"Error: {mount_root} is not initialized (missing {cfg_path}). Run 'dfs5 init' first.")

    ensure_private_dir(cfg_path.parent)
    restrict_to_owner(cfg_path)
    cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
    priv_key = Path(cfg["priv_key"]).expanduser().resolve()
    pub_key_path = Path(cfg.get("pub_key") or f"{priv_key}.pub").expanduser().resolve()
    pub_key_str = pub_key_path.read_text(encoding="utf-8").strip()

    reg_urls = [cfg["registry_url"], *(cfg.get("registry_alternates") or [])]
    reg_client = RemoteRegistryClient(reg_urls)
    node = DFS5Node(
        name=cfg["node_name"],
        sub_path=cfg["sub_path"],
        mount_root=mount_root,
        priv_key_path=priv_key,
        pub_key_str=pub_key_str,
        tree_secret=cfg["tree_secret"],
        registry=reg_client,  # type: ignore[arg-type]
        ost_host=cfg["ost_host"],
        ost_port=int(cfg["ost_port"]),
        root_pubkey=cfg.get("root_pubkey"),
        ost_alternates=cfg.get("ost_alternates") or [],
        libp2p_peers=cfg.get("libp2p_peers") or [],
        libp2p_psk=cfg.get("libp2p_psk") or "",
    )
    return node, cfg, reg_client


# ==========================================
# サブコマンド実装
# ==========================================
def cmd_serve(args: argparse.Namespace) -> None:
    state_dir = Path(args.state_dir).expanduser().resolve()
    ensure_private_dir(state_dir)

    root_pub_path = Path(args.root_pubkey).expanduser().resolve()
    root_pubkey = root_pub_path.read_text(encoding="utf-8").strip()

    cert = state_dir / "ost_cert.pem"
    key = state_dir / "ost_key.pem"
    if not cert.exists() or not key.exists():
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-keyout", str(key), "-out", str(cert),
                "-days", "365", "-nodes", "-subj", "/CN=dfs5-ost",
            ],
            check=True,
            capture_output=True,
        )

    ost = ChunkStoreServer(cert, key, host=args.bind, port=args.ost_port)
    pstate = PersistentRegistryState(state_dir, args.root_anchor, root_pubkey)
    pstate.load_ost_chunks(ost)
    pstate.replica_registries = [
        value.strip().rstrip("/")
        for value in (getattr(args, "replica", None) or [])
        if value.strip()
    ]

    # 自前の L3 の場所を広告する（--advertise があれば優先。無ければ bind から推定）
    advertised_host = args.advertise or ("127.0.0.1" if args.bind in ("0.0.0.0", "::") else args.bind)
    pstate.ost_endpoint = f"tls://{advertised_host}:{ost.port}"
    pstate.own_registry_url = f"http://{advertised_host}:{args.registry_port}"

    handler = make_registry_http_handler(pstate, ost)
    httpd = ThreadingHTTPServer((args.bind, args.registry_port), handler)

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

    print(f"[dfs5 serve] Root Anchor : {args.root_anchor}")
    print(f"[dfs5 serve] State Dir   : {state_dir}")
    print(f"[dfs5 serve] L2 Registry : http://{args.bind}:{args.registry_port}")
    print(f"[dfs5 serve] L3 OST (TLS): {pstate.ost_endpoint}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[dfs5 serve] Shutting down...")
    finally:
        with pstate.lock:
            pstate.save()
            pstate.save_ost_chunks(ost)
        ost.close()
        try:
            pid_file.unlink()
        except OSError:
            pass
        httpd.server_close()


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
        print(f"[dfs5 delegate] Wrote signed delegation envelope to {args.output}")

    if args.registry:
        client = RemoteRegistryClient(args.registry)
        verified = client.register_delegation(env, now=now)
        print(
            f"[dfs5 delegate] Registered on {args.registry}: "
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
    print(f"[dfs5 init] Initialized mount at {mount_root}")
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
    print("[dfs5 metrics] " + json.dumps(row, sort_keys=True, ensure_ascii=False))


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
        raise SystemExit(f"[REJECTED: Single-Writer Conflict] {e}\nHint: Run 'dfs5 pull' first.") from e
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
        f"[dfs5 push] OK v{p['version']} (epoch={p['delegation_epoch']}) "
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
        f"[dfs5 pull] OK v{pin.version} (epoch={pin.delegation_epoch}) "
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
    parser = argparse.ArgumentParser(prog="dfs5", description="dfs5: Layered Single-Writer Distributed File System CLI")
    sub = parser.add_subparsers(dest="cmd", required=True)

    # serve
    p_serve = sub.add_parser("serve", help="Run L2 Registry (HTTP) and L3 OST (TLS/TCP) daemon")
    p_serve.add_argument("--bind", default="0.0.0.0", help="Bind address (default: 0.0.0.0)")
    p_serve.add_argument("--registry-port", type=int, default=9440, help="L2 HTTP port (default: 9440)")
    p_serve.add_argument("--ost-port", type=int, default=9443, help="L3 OST TLS port (default: 9443)")
    p_serve.add_argument("--root-anchor", default="/example.com", help="Root anchor path (default: /example.com)")
    p_serve.add_argument("--root-pubkey", required=True, help="Path to root anchor .pub file")
    p_serve.add_argument("--state-dir", default="~/.dfs5_server", help="Server persistence directory")
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
    p_serve.set_defaults(func=cmd_serve)

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
    p_init = sub.add_parser("init", help="Initialize a local dfs5 mount directory")
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
