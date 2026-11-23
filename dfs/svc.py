#!/usr/bin/env python3
"""
dfs/svc.py
ローカルに dfs サーバを簡単に立てるコマンド（`dfssvc`）。

`dfs serve` は状態ディレクトリ・root 公開鍵・L2/L3 のポートをすべて自分で用意する。
このコマンドは「ローカルで 1 つ立てて試す」ための最小の入口で、次を肩代わりする。

1. 連続した空きポートを 2 つ探し、1 つ目を L2（名簿）、2 つ目を L3（OST）に割り当てる。
2. root の鍵（L1 権威の Ed25519）が無ければ作る。
3. 状態ディレクトリを用意し、`dfs serve` を起動する。
4. 立ち上がったら、接続に必要な値を `~/.config/dfs/services.json` に記録する
   （`dfscli config create` に渡す値を自分で組み立てなくて済むように）。
5. `stop` / `list` / `status` で後始末と確認ができる。

使い方:
    dfssvc start                 # 連続した空きポートで1つ立てる（既定 19440 から探索）
    dfssvc start --name dev      # 名前を付ける（既定 "local"）
    dfssvc start --port 20000    # この番号から連続した空きを探す
    dfssvc start --ost-dir /Volumes/ExtSSD/dfs/ost/dev  # OST を外部ディスクへ
    dfssvc start --foreground    # 前面で動かす（Ctrl-C で止まる）
    dfssvc list                  # 記録済みのサービス
    dfssvc status dev            # 状態と接続情報
    dfssvc stop dev              # 止める
    dfssvc env dev               # dfscli config create の行を出す
    dfssvc dnssec dev            # _dfs.<domain> TXT の JSON を出す

出力は機械可読も兼ねる（`--json`）。

配布:
  `pyproject.toml` の console_scripts で `dfscli` / `dfssvc` をインストールできる。
  リポジトリ直下のシェルラッパーは開発用の互換入口として残している。
"""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .dnssec import DEFAULT_RECORD_PREFIX, parse_discovery_text
from .i18n import _
from .paths import config_dir, dfs_home, restrict_to_owner
from .private_io import ensure_private_dir, write_private_json

CONFIG_FILENAME = "services.json"
DEFAULT_START_PORT = 19440
DEFAULT_NAME = "local"
DEFAULT_ROOT_ANCHOR = "/example.com"

# 委譲の有効期間（日）。L1 は ``child.expires_at <= parent.expires_at`` を要求する。
# 親子は**別のプロセス**で署名するため、同じ日数だと実行時刻が 1 秒ずれただけで子が親を
# 超えて Invariant 3 に落ちる（テストで実際に起きた）。中間を 1 日長くして必ず親 > 子に
# なるようにする。日単位の粗さで足りる（ずれは高々数秒）。
LEAF_TTL_DAYS = 365
INTERMEDIATE_TTL_DAYS = LEAF_TTL_DAYS + 1
BASE_DIR_NAME = "dfssvc"
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")


class ServiceError(Exception):
    """使い方の誤り・状態の不整合"""


def validate_service_name(name: str) -> str:
    """サービス名が安全な識別子であることを検証する（パストラバーサル防止）。"""
    value = str(name or "").strip()
    if not value or value in (".", "..") or not NAME_RE.match(value):
        raise ServiceError(
            f"不正なサービス名です: {name!r}（先頭は英数字、以降は英数字と _ . - のみ使用可）"
        )
    return value


# --------------------------------------------------------------------------
# 空きポート
# --------------------------------------------------------------------------
def is_port_free(port: int, host: str = "127.0.0.1", *, allow_reuse: bool = False) -> bool:
    """そのポートを今から使えるか。

    2 段で確かめる。macOS では ``SO_REUSEADDR`` を立てた bind が、他のプロセスが
    ``0.0.0.0:port`` で待ち受けていても通ってしまう（``127.0.0.1:port`` とは別物として
    扱われるため）。まず接続を試して「誰かが答えている」なら使用中とし、次に
    ``SO_REUSEADDR`` 無しの bind で確かめる。``allow_reuse=True`` の場合は既存ポートの
    再起動向けに ``TIME_WAIT`` 残骸を許容する。

    L3 は TLS のサーバなので、接続するとハンドシェイク前で切れる。connect が
    成功した時点で「そのポートには誰かがいる」と判断してよい。
    """
    # 1) 接続してみる（応答があれば使用中）
    for family, socktype, proto, _canon, addr in socket.getaddrinfo(
        host, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP
    ):
        s = socket.socket(family, socktype, proto)
        s.settimeout(0.4)
        try:
            s.connect(addr)
            return False  # 誰かが待ち受けている
        except (ConnectionRefusedError, OSError):
            pass
        finally:
            s.close()

    # 2) bind で確かめる（通常は TIME_WAIT 残骸も避けるため SO_REUSEADDR 無し）
    for family, socktype, proto, _canon, addr in socket.getaddrinfo(
        host, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP
    ):
        s = socket.socket(family, socktype, proto)
        try:
            if allow_reuse:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(addr)
        except OSError:
            return False
        finally:
            s.close()
    return True


def find_consecutive_free_ports(
    start: int,
    count: int = 2,
    host: str = "127.0.0.1",
    limit: int = 1000,
    *,
    allow_reuse: bool = False,
) -> Tuple[int, int]:
    """``start`` から探し、連続して空いている ``count`` 個のポートを返す。

    L2 と L3 を隣り合わせに置くと、`--registry-port N` / `--ost-port N+1` のように
    覚えやすく、衝突の確認も 1 回で済む。見つからなければ ServiceError。
    """
    if not (1 <= start <= 65535) or start + count - 1 > 65535:
        raise ServiceError(f"開始ポートが不正です: {start}")
    port = start
    tried = 0
    while port + count - 1 <= 65535 and tried < limit:
        if all(is_port_free(port + i, host, allow_reuse=allow_reuse) for i in range(count)):
            return port, port + 1
        port += 1
        tried += 1
    raise ServiceError(f"{start} から連続した空きポート {count} 個が見つかりませんでした")


def _port_listening(port: int, host: str = "127.0.0.1", timeout: float = 0.4) -> bool:
    """そのポートに接続できるか（= 誰かが待ち受けているか）。"""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _process_alive(pid: int) -> bool:
    """その PID のプロセスが生きているか。

    Windows の ``os.kill(pid, 0)`` は「存在確認」にならない（TerminateProcess 相当）
    ため、OpenProcess + GetExitCodeProcess で調べる。
    """
    if pid <= 0:
        return False
    if sys.platform == "win32":
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel32.GetExitCodeProcess.argtypes = [
            wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD),
        ]
        kernel32.GetExitCodeProcess.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        STILL_ACTIVE = 259
        handle = kernel32.OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid)
        )
        if not handle:
            return False
        try:
            code = wintypes.DWORD()
            if not kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
                return False
            return code.value == STILL_ACTIVE
        finally:
            kernel32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def _windows_pid_owns_port(pid: int, port: int) -> bool:
    """``netstat -ano`` で「その PID がそのポートを待ち受けている」ことを確かめる。"""
    try:
        res = subprocess.run(
            ["netstat", "-ano", "-p", "TCP"],
            capture_output=True, text=True, timeout=15,
        )
    except (OSError, subprocess.SubprocessError):
        return _port_listening(port)
    needle = f":{port}"
    for line in res.stdout.splitlines():
        parts = line.split()
        if len(parts) < 5 or parts[0].upper() != "TCP":
            continue
        if not parts[1].endswith(needle):
            continue
        if parts[-1] == str(pid):
            return True
    return False


def _port_in_use_by_us(pid: int, port: int) -> bool:
    """その pid が port を掴んでいるか。"""
    if sys.platform == "win32":
        return _windows_pid_owns_port(pid, port)
    try:
        res = subprocess.run(
            ["lsof", "-nP", "-a", "-p", str(pid), f"-iTCP:{port}", "-sTCP:LISTEN"],
            capture_output=True, text=True, timeout=15,
        )
    except (OSError, subprocess.SubprocessError):
        # lsof が無い環境向けの保険。ポートが生きていれば掴んでいるとみなす。
        return _port_listening(port)
    return res.returncode == 0 and str(port) in res.stdout


# --------------------------------------------------------------------------
# 記録（サービス一覧）
# --------------------------------------------------------------------------
@dataclass
class Service:
    """立てた dfs サーバ 1 つぶんの記録。"""

    name: str
    state_dir: str
    root_key: str
    root_pub: str
    registry_port: int
    ost_port: int
    bind: str
    advertise: str
    root_anchor: str
    pid: int
    started_at: str
    writer_key: str = ""
    writer_pub: str = ""
    sub_path: str = ""
    config_path: str = ""
    log_path: str = ""
    role: str = "primary"
    role_epoch: int = 1
    ost_dir: str = ""

    @property
    def registry_url(self) -> str:
        host = self.advertise or "127.0.0.1"
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        return f"http://{host}:{self.registry_port}"

    @property
    def ost_endpoint(self) -> str:
        host = self.advertise or "127.0.0.1"
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        return f"{host}:{self.ost_port}"

    def is_running(self) -> bool:
        """プロセスが生きていて、その pid が L2/L3 のポートを掴んでいるか。

        Windows の ``os.kill(pid, 0)`` は存在確認にならないので使わない。
        """
        if not _process_alive(self.pid):
            return False
        return _port_in_use_by_us(self.pid, self.registry_port) or _port_in_use_by_us(
            self.pid, self.ost_port
        )

    def to_dict(self) -> dict:
        d = asdict(self)
        d["registry_url"] = self.registry_url
        d["ost_endpoint"] = self.ost_endpoint
        d["running"] = self.is_running()
        return d


class ServiceStore:
    """`~/.config/dfs/services.json` の読み書き。"""

    def __init__(self, path: Optional[Path] = None):
        self.path = path or (config_dir() / CONFIG_FILENAME)
        self.services: Dict[str, Service] = {}
        self.load()

    def load(self) -> None:
        self.services = {}
        if not self.path.is_file():
            return
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            raise ServiceError(f"{self.path} が壊れています: {e}") from e
        for name, item in (raw.get("services") or {}).items():
            clean_name = validate_service_name(name)
            data = dict(item)
            data.setdefault("name", clean_name)
            data.pop("registry_url", None)  # 派生値は保存しない
            data.pop("ost_endpoint", None)
            data.pop("running", None)
            self.services[clean_name] = Service(**data)

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "schema": "dfs-services-v1",
            "services": {n: asdict(s) for n, s in sorted(self.services.items())},
        }
        raw = (json.dumps(payload, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
        tmp = self.path.with_name(f".{self.path.name}.{os.getpid()}.{secrets.token_hex(4)}.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            view = memoryview(raw)
            written = 0
            while written < len(raw):
                written += os.write(fd, view[written:])
            os.fsync(fd)
        finally:
            os.close(fd)
        restrict_to_owner(tmp)
        os.replace(tmp, self.path)

    def get(self, name: str) -> Service:
        if name not in self.services:
            known = ", ".join(sorted(self.services)) or "(なし)"
            raise ServiceError(f"サービス {name!r} は記録にありません。あるもの: {known}")
        return self.services[name]


# --------------------------------------------------------------------------
# 鍵と状態ディレクトリ
# --------------------------------------------------------------------------
def ensure_root_key(path: Path) -> Path:
    """root の Ed25519 鍵を用意する（無ければ作る）。"""
    from .crypto import CryptoError, generate_ed25519_keypair

    if path.exists() and Path(f"{path}.pub").exists():
        return path
    try:
        generate_ed25519_keypair(path, comment=f"dfssvc-root@{socket.gethostname()}")
    except CryptoError as e:
        raise ServiceError(f"root 鍵を作れませんでした: {e}") from e
    restrict_to_owner(path)
    return path


def ensure_writer_key(path: Path) -> Path:
    """書き手（L4 のログに署名する人）の Ed25519 鍵を用意する。"""
    from .crypto import CryptoError, generate_ed25519_keypair

    if path.exists() and Path(f"{path}.pub").exists():
        return path
    try:
        generate_ed25519_keypair(path, comment=f"dfssvc-writer@{socket.gethostname()}")
    except CryptoError as e:
        raise ServiceError(f"書き手の鍵を作れませんでした: {e}") from e
    restrict_to_owner(path)
    return path


def register_delegation(
    root_key: Path, writer_pub: Path, sub_path: str, registry_url: str,
    ttl_days: int = LEAF_TTL_DAYS,
) -> None:
    """root 鍵で書き手への委譲を署名し、L2 に登録する。

    すでに同じ書き手・同じパスの委譲があれば何もしない（再起動で作り直さない）。

    ``ttl_days`` は末端（書き手への委譲）の有効期間。中間の委譲はこれより長くする
    （``LEAF_TTL_DAYS`` と ``INTERMEDIATE_TTL_DAYS`` の関係を参照）。
    """
    import urllib.error
    import urllib.request

    writer_line = writer_pub.read_text(encoding="utf-8").strip()

    # 既にこの書き手の委譲があるか
    body = json.dumps({}).encode("utf-8")
    req = urllib.request.Request(
        f"{registry_url}/v1/paths", data=body,
        headers={"Content-Type": "application/json"}, method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            rows = json.loads(resp.read().decode("utf-8")).get("paths", [])
    except Exception:  # noqa: BLE001 - 未登録なら無いものとして進める
        rows = []
    if any(r.get("path") == sub_path and r.get("writer", "").strip() == writer_line for r in rows):
        return

    repo = _repo_root()
    env = dict(os.environ)
    env["PYTHONPATH"] = str(repo) + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    parent = sub_path.rsplit("/", 1)[0] or "/"
    cmd = [
        sys.executable, "-m", "dfs.cli", "delegate",
        "--parent", parent,
        "--path", sub_path,
        "--signing-key", str(root_key),
        "--writer-pubkey", str(writer_pub),
        "--registry", registry_url,
        "--ttl-days", str(int(ttl_days)),
    ]
    res = subprocess.run(
        cmd,
        env=env,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=60,
    )
    if res.returncode != 0:
        raise ServiceError(
            "委譲の登録に失敗しました: " + (res.stderr.strip() or res.stdout.strip())
        )


def _ensure_parent_delegations(
    root_key: Path, root_pub: Path, root_anchor: str, sub_path: str, registry_url: str,
) -> None:
    """``sub_path`` の途中のディレクトリにも委譲を張る（L1 は多段を要求する）。

    ``/example.com/a/b`` なら ``/example.com/a`` を経て ``/example.com/a/b`` に至る。
    親の委譲は root の書き手（= root 公開鍵）で作る。
    """
    anchor = root_anchor.rstrip("/")
    if not sub_path.startswith(anchor + "/"):
        return
    rel = sub_path[len(anchor) + 1:]
    parts = [p for p in rel.split("/") if p]
    if len(parts) <= 1:
        return  # 根の直下は 1 段で届く
    # 途中の各階層に委譲を張る（parent -> child）
    current = anchor
    for i, part in enumerate(parts):
        child = f"{current}/{part}"
        if i == len(parts) - 1:
            break  # 最後は書き手への委譲なので呼び出し側がやる
        register_delegation_chain_step(root_key, root_pub, current, child, registry_url)
        current = child


def register_delegation_chain_step(
    root_key: Path, root_pub: Path, parent: str, child: str, registry_url: str,
    ttl_days: int = INTERMEDIATE_TTL_DAYS,
) -> None:
    """親のパスから子のパスへの委譲を、root 鍵で署名して登録する（中間の層）。"""
    import urllib.error
    import urllib.request

    writer_line = root_pub.read_text(encoding="utf-8").strip()
    body = json.dumps({}).encode("utf-8")
    req = urllib.request.Request(
        f"{registry_url}/v1/paths", data=body,
        headers={"Content-Type": "application/json"}, method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            rows = json.loads(resp.read().decode("utf-8")).get("paths", [])
    except Exception:  # noqa: BLE001
        rows = []
    if any(r.get("path") == child and r.get("writer", "").strip() == writer_line for r in rows):
        return

    repo = _repo_root()
    env = dict(os.environ)
    env["PYTHONPATH"] = str(repo) + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    cmd = [
        sys.executable, "-m", "dfs.cli", "delegate",
        "--parent", parent,
        "--path", child,
        "--signing-key", str(root_key),
        "--writer-pubkey", str(root_pub),
        "--registry", registry_url,
        "--ttl-days", str(int(ttl_days)),
    ]
    res = subprocess.run(
        cmd,
        env=env,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=60,
    )
    if res.returncode != 0:
        raise ServiceError(
            f"中間の委譲 ({child}) の登録に失敗しました: "
            + (res.stderr.strip() or res.stdout.strip())
        )


def wait_for_l2(registry_url: str, timeout: float = 30.0, path: str = DEFAULT_ROOT_ANCHOR) -> bool:
    """L2 が resolve に答えるようになるまで待つ。"""
    import urllib.error
    import urllib.request

    body = json.dumps({"path": path}).encode("utf-8")
    req = urllib.request.Request(
        f"{registry_url}/v1/resolve", data=body,
        headers={"Content-Type": "application/json"}, method="POST",
    )
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(req, timeout=3) as resp:
                if resp.status == 200:
                    return True
        except Exception:  # noqa: BLE001 - 起動待ちなので握りつぶす
            time.sleep(0.5)
    return False


# --------------------------------------------------------------------------
# コマンド
# --------------------------------------------------------------------------
def _base_dir(name: str) -> Path:
    clean = validate_service_name(name)
    root = (dfs_home() / BASE_DIR_NAME).resolve()
    target = (root / clean).resolve()
    if not target.is_relative_to(root) or target == root:
        raise ServiceError(f"不正なサービスディレクトリです: {name!r}")
    return dfs_home() / BASE_DIR_NAME / clean


def _read_serve_pid(state_dir: Path, timeout: float = 5.0) -> int:
    """サーバが書いた ``serve.pid`` を読む。無ければ 0。

    Windows の venv 版 ``python.exe`` は本体を子プロセスで起動するため、
    起動側の ``Popen.pid`` はサーバ本体ではない。サーバ自身に書かせる。
    """
    path = Path(state_dir) / "serve.pid"
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            raw = path.read_text(encoding="utf-8").strip()
        except OSError:
            raw = ""
        if raw.isdigit() and int(raw) > 0:
            return int(raw)
        time.sleep(0.1)
    return 0


def default_root_anchor_for_pubkey(pubkey_str: str) -> str:
    """ルート公開鍵の短縮ハッシュから自己認証型 root_anchor (``/k-<16hex>``) を生成する。"""
    import hashlib

    clean = " ".join(str(pubkey_str or "").split())
    if not clean:
        return DEFAULT_ROOT_ANCHOR
    digest = hashlib.sha256(clean.encode("utf-8")).hexdigest()[:16]
    return f"/k-{digest}"


def generate_relay_node_id(name: str, base: Path | str) -> str:
    """他端末と衝突しない ``n-<hash>`` 形式のリレーノード ID を生成する。"""
    import base64
    import hashlib

    seed = f"{socket.gethostname()}\n{name}\n{base}\n{secrets.token_hex(16)}".encode("utf-8")
    digest = hashlib.sha256(seed).digest()
    return "n-" + base64.urlsafe_b64encode(digest[:12]).decode("ascii").rstrip("=")


def _normalize_hub_url(raw: str) -> str:
    value = str(raw or "").strip().rstrip("/")
    if not value:
        return ""
    if "://" in value:
        return value
    # ポート番号付き (例: 192.0.2.254:19440) は http://、ドメインのみ (例: dfs.example.com) は https://
    if ":" in value and not value.startswith("["):
        return f"http://{value}"
    return f"https://{value}"


def _normalize_hub_urls(raw: Any) -> List[str]:
    """文字列・カンマ区切り・シーケンスから重複なしの正規化済みハブ URL リストを作る。"""
    if not raw:
        return []
    items = [raw] if isinstance(raw, str) else list(raw)
    result: List[str] = []
    seen = set()
    for item in items:
        for part in str(item or "").split(","):
            norm = _normalize_hub_url(part)
            if norm and norm not in seen:
                seen.add(norm)
                result.append(norm)
    return result


def _resolve_service_name(args: argparse.Namespace) -> str:
    """位置引数と ``--name`` のどちらからでもサービス名を解決する。"""
    opt_name = getattr(args, "name_opt", None)
    pos_name = getattr(args, "target_name", None)
    if opt_name and pos_name and opt_name != pos_name:
        raise ServiceError(f"--name {opt_name!r} と位置引数 {pos_name!r} が一致しません")
    return validate_service_name(opt_name or pos_name or getattr(args, "name", None) or DEFAULT_NAME)


def _add_service_name_args(parser: argparse.ArgumentParser) -> None:
    """サブコマンドに共通の位置引数 ``<name>`` と ``--name <name>`` を登録する。"""
    parser.add_argument(
        "target_name", nargs="?",
        help=f"サービスの名前（--name と同じ。既定 {DEFAULT_NAME}）",
    )
    parser.add_argument(
        "--name", dest="name_opt", default=None,
        help=f"サービスの名前（既定 {DEFAULT_NAME}）",
    )


def cmd_start(args: argparse.Namespace) -> int:
    store = ServiceStore()
    name = _resolve_service_name(args)
    existing = store.services.get(name)
    start_port_arg = getattr(args, "port", None)
    registry_port_arg = getattr(args, "registry_port", None)
    ost_port_arg = getattr(args, "ost_port", None)

    if start_port_arg is not None and (
        registry_port_arg is not None or ost_port_arg is not None
    ):
        raise ServiceError("--port と --registry-port/--ost-port は同時に指定できません")
    if (registry_port_arg is None) != (ost_port_arg is None):
        raise ServiceError("--registry-port と --ost-port は両方指定してください")
    if (
        registry_port_arg is not None
        and registry_port_arg == ost_port_arg
    ):
        raise ServiceError("--registry-port と --ost-port には別のポートを指定してください")

    is_alive = existing is not None and (
        existing.is_running() or _recorded_server_is_alive(existing)
    )
    if is_alive and not getattr(args, "force", False):
        raise ServiceError(
            f"サービス {name!r} は既に起動しています。"
            f"止めるなら 'dfssvc stop {name}'、再起動するなら --force を付けてください"
        )
    if is_alive and getattr(args, "force", False):
        if not _stop_process(existing):
            raise ServiceError(f"既存のサービス {name!r} を停止できませんでした")

    host_arg = getattr(args, "host", None)
    host = host_arg if host_arg is not None else (existing.bind if existing and existing.bind else "127.0.0.1")
    start_port = (
        start_port_arg
        if start_port_arg is not None
        else (existing.registry_port if existing and existing.registry_port else DEFAULT_START_PORT)
    )
    # 停止済みの古い記録はポートを予約しない。実際に稼働中のサービスだけを避ける。
    port_owners: Dict[int, str] = {}
    for service in store.services.values():
        if service.name == name or not (
            service.is_running() or _recorded_server_is_alive(service)
        ):
            continue
        port_owners[service.registry_port] = service.name
        port_owners[service.ost_port] = service.name
    used = set(port_owners)
    if registry_port_arg is not None and ost_port_arg is not None:
        registry_port, ost_port = registry_port_arg, ost_port_arg
        owners = sorted({
            port_owners[port] for port in (registry_port, ost_port) if port in port_owners
        })
        if owners:
            raise ServiceError(
                f"指定したポートは起動中のサービス {', '.join(owners)} が使用しています"
            )
        for label, port in (("L2", registry_port), ("L3", ost_port)):
            if not 1 <= port <= 65535:
                raise ServiceError(f"{label} ポートが範囲外です: {port}")
            if not is_port_free(port, host, allow_reuse=True):
                raise ServiceError(f"{label} ポートは使用中です: {port}")
    elif (
        start_port_arg is None
        and existing is not None
        and existing.registry_port
        and existing.ost_port
        and existing.registry_port not in used
        and existing.ost_port not in used
        and is_port_free(existing.registry_port, host, allow_reuse=True)
        and is_port_free(existing.ost_port, host, allow_reuse=True)
    ):
        registry_port, ost_port = existing.registry_port, existing.ost_port
    else:
        while True:
            while start_port in used:
                start_port += 1
            registry_port, ost_port = find_consecutive_free_ports(
                start_port, 2, host, allow_reuse=(start_port_arg is not None)
            )
            if registry_port not in used and ost_port not in used:
                break
            start_port = ost_port + 1

    base = _base_dir(name)
    cfg_file = base / "dfssvc.json"
    saved_cfg: Dict[str, Any] = {}
    if cfg_file.is_file():
        try:
            loaded = json.loads(cfg_file.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                saved_cfg = loaded
        except (OSError, ValueError, TypeError):
            saved_cfg = {}

    hub_arg = getattr(args, "hub", None)
    join_arg = getattr(args, "join", None)
    is_hub = bool(hub_arg) or bool(saved_cfg.get("hub"))
    join_urls = _normalize_hub_urls(join_arg) if join_arg else _normalize_hub_urls(saved_cfg.get("join"))
    join_url = join_urls[0] if join_urls else ""
    allow_unauth_relay = os.environ.get("DFS_RELAY_ALLOW_UNAUTH", "").strip().lower() in (
        "1",
        "true",
        "yes",
    )
    relay_token_arg = getattr(args, "relay_token", None)
    if relay_token_arg is not None:
        relay_token = str(relay_token_arg)
    elif allow_unauth_relay:
        relay_token = ""
    else:
        relay_token = str(saved_cfg.get("relay_token") or "")
    if is_hub and not relay_token and not allow_unauth_relay:
        relay_token = secrets.token_urlsafe(24)
    relay_node = (
        getattr(args, "relay_node", None)
        or str(saved_cfg.get("relay_node") or "")
    )
    if join_url and not relay_node:
        relay_node = generate_relay_node_id(name, base)

    sync_id = str(saved_cfg.get("sync_id") or "").strip()
    if join_url and not sync_id:
        import base64
        import hashlib

        seed = f"{socket.gethostname()}\n{name}\n{base}".encode("utf-8")
        sync_id = base64.urlsafe_b64encode(hashlib.sha256(seed).digest()[:12]).decode("ascii").rstrip("=")

    raw_subs = getattr(args, "subscribe", None)
    if raw_subs:
        subscribe_list = list(dict.fromkeys(
            s.strip()
            for item in raw_subs
            for s in str(item).split(",")
            if s.strip()
        ))
    else:
        saved_subs = saved_cfg.get("subscribe")
        subscribe_list = [str(s).strip() for s in saved_subs if str(s).strip()] if isinstance(saved_subs, list) else []

    effective_host = host
    if is_hub and host_arg is None and not (existing and existing.bind) and effective_host == "127.0.0.1":
        effective_host = "0.0.0.0"

    effective_advertise = (
        args.advertise
        or str(saved_cfg.get("advertise") or "")
        or (existing.advertise if existing and existing.advertise else "")
    )
    if not effective_advertise and isinstance(hub_arg, str) and hub_arg not in ("", "auto"):
        from urllib.parse import urlsplit

        parsed_hub = urlsplit(_normalize_hub_url(hub_arg))
        if parsed_hub.hostname:
            effective_advertise = parsed_hub.hostname
    if not effective_advertise:
        effective_advertise = "127.0.0.1" if effective_host in ("0.0.0.0", "::") else effective_host

    state_dir = (
        Path(args.state_dir).expanduser()
        if args.state_dir
        else (Path(existing.state_dir).expanduser() if existing and existing.state_dir else base / "server")
    )
    raw_ost_dir = getattr(args, "ost_dir", None) or (existing.ost_dir if existing else "")
    ost_dir = (
        Path(raw_ost_dir).expanduser().resolve()
        if raw_ost_dir
        else state_dir / "ost_chunks"
    )
    root_key = (
        Path(args.root_key).expanduser()
        if args.root_key
        else (Path(existing.root_key).expanduser() if existing and existing.root_key else base / "keys" / "root")
    )
    writer_key = (
        Path(args.writer_key).expanduser()
        if args.writer_key
        else (Path(existing.writer_key).expanduser() if existing and existing.writer_key else base / "keys" / "writer")
    )
    log_path = base / "logs" / "serve.log"

    ensure_private_dir(base)
    state_dir.mkdir(parents=True, exist_ok=True)
    ost_dir.mkdir(parents=True, exist_ok=True)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    ensure_root_key(root_key)
    ensure_writer_key(writer_key)
    root_pub = Path(f"{root_key}.pub")
    writer_pub = Path(f"{writer_key}.pub")

    if getattr(args, "root_anchor", None) is not None:
        effective_root_anchor = args.root_anchor
    elif existing and existing.root_anchor:
        effective_root_anchor = existing.root_anchor
    else:
        raw_path_arg = (getattr(args, "path", None) or "").strip()
        path_parts = [p for p in raw_path_arg.strip("/").split("/") if p]
        if raw_path_arg.startswith("/") and len(path_parts) >= 2:
            effective_root_anchor = f"/{path_parts[0]}"
        else:
            effective_root_anchor = default_root_anchor_for_pubkey(
                root_pub.read_text(encoding="utf-8")
            )

    cfg_payload = (
        json.dumps(
            {
                "hub": is_hub,
                "join": join_urls,
                "relay_node": relay_node,
                "relay_token": relay_token,
                "advertise": effective_advertise,
                "sync_id": sync_id,
                "subscribe": subscribe_list,
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n"
    ).encode("utf-8")
    cfg_tmp = cfg_file.with_name(f".{cfg_file.name}.{os.getpid()}.{secrets.token_hex(4)}.tmp")
    fd = os.open(cfg_tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        view = memoryview(cfg_payload)
        written = 0
        while written < len(cfg_payload):
            written += os.write(fd, view[written:])
        os.fsync(fd)
    finally:
        os.close(fd)
    restrict_to_owner(cfg_tmp)
    os.replace(cfg_tmp, cfg_file)

    advertised = effective_advertise
    advertised_host = f"[{advertised}]" if ":" in advertised else advertised
    registry_url = f"http://{advertised_host}:{registry_port}"
    service_role = args.role or (existing.role if existing and existing.role else "primary")
    service_role_epoch = (
        args.role_epoch
        if args.role_epoch is not None
        else (existing.role_epoch if existing and existing.role_epoch else 1)
    )
    state_file = state_dir / "registry_state.json"
    if state_file.is_file():
        try:
            state = json.loads(state_file.read_text(encoding="utf-8"))
            if not args.role:
                service_role = str(state.get("role", service_role))
            if args.role_epoch is None:
                service_role_epoch = int(state.get("role_epoch", service_role_epoch))
        except (OSError, ValueError, TypeError):
            pass

    cmd = [
        sys.executable, "-m", "dfs.cli", "serve",
        "--bind", effective_host,
        "--registry-port", str(registry_port),
        "--ost-port", str(ost_port),
        "--root-anchor", effective_root_anchor,
        "--root-pubkey", str(root_pub),
        "--state-dir", str(state_dir),
        "--ost-dir", str(ost_dir),
        "--advertise", advertised,
    ]
    if is_hub:
        cmd.append("--relay-hub")
        auto_delegate_enabled = (
            bool(getattr(args, "auto_delegate", False))
            or os.environ.get("DFS_AUTO_DELEGATE", "").strip() in ("1", "true", "yes")
        ) and not getattr(args, "no_auto_delegate", False)
        if service_role == "primary" and root_key.is_file() and auto_delegate_enabled:
            cmd.extend(["--auto-delegate-key", str(root_key)])
    for jurl in join_urls:
        cmd.extend(["--relay", jurl])
    if relay_node:
        cmd.append(f"--relay-node={relay_node}")
    if sync_id:
        cmd.append(f"--sync-id={sync_id}")
    for sub_id in subscribe_list:
        cmd.append(f"--subscribe={sub_id}")
    for replica in (getattr(args, "replica", None) or []):
        cmd.extend(["--replica", replica])
    if getattr(args, "role", None):
        cmd.extend(["--role", args.role])
    if getattr(args, "role_epoch", None) is not None:
        cmd.extend(["--role-epoch", str(args.role_epoch)])

    print(_("[dfssvc] 空きポート: L2={registry_port} / L3={ost_port}（連続した組）").format(registry_port=registry_port, ost_port=ost_port))
    print(_("[dfssvc] 状態      : {state_dir}").format(state_dir=state_dir))
    print(_("[dfssvc] OST       : {ost_dir}").format(ost_dir=ost_dir))
    print(_("[dfssvc] root 鍵   : {root_key}").format(root_key=root_key))
    print(_("[dfssvc] ログ      : {log_path}").format(log_path=log_path))

    # 前回強制終了時などに残留した stop.request / serve.pid を掃除してから起動する
    for stale_name in ("stop.request", "serve.pid"):
        try:
            (state_dir / stale_name).unlink(missing_ok=True)
        except OSError:
            pass

    env = dict(os.environ)
    repo = _repo_root()
    env["PYTHONPATH"] = str(repo) + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    if relay_token:
        env["DFS_RELAY_TOKEN"] = relay_token

    if args.foreground:
        print("[dfssvc] 前面で起動します（Ctrl-C で停止）")
        proc = subprocess.Popen(cmd, env=env, stdin=subprocess.DEVNULL)
    else:
        try:
            if log_path.is_file() and log_path.stat().st_size > 10 * 1024 * 1024:
                rotated = log_path.with_name("serve.log.1")
                log_path.replace(rotated)
        except OSError:
            pass
        with open(log_path, "ab") as log:
            proc = subprocess.Popen(
                cmd, env=env, stdout=log, stderr=log,
                stdin=subprocess.DEVNULL, start_new_session=True,
            )

    local_host = "127.0.0.1" if effective_host in ("0.0.0.0", "::", "") else effective_host
    local_host_fmt = f"[{local_host}]" if ":" in local_host else local_host
    local_registry_url = f"http://{local_host_fmt}:{registry_port}"

    if not wait_for_l2(local_registry_url, timeout=args.wait, path=effective_root_anchor):
        tail = ""
        if not args.foreground and log_path.is_file():
            tail = log_path.read_text(encoding="utf-8", errors="replace")[-4000:]
        if proc.poll() is not None:
            detail = f"\n{tail}" if tail else ""
            raise ServiceError(
                f"サーバが起動しませんでした（終了コード {proc.returncode}）:{detail}"
            )
        _terminate(proc)
        detail = f"\n{tail}" if tail else ""
        raise ServiceError(
            f"L2 ({registry_url}) が {args.wait:.0f} 秒以内に応答しませんでした"
            f"（ログ: {log_path}）:{detail}"
        )

    # サーバ本体の PID を state_dir/serve.pid から取る（Windows の venv 版
    # python.exe は本体を子プロセスで起動するので proc.pid は当てにならない）。
    server_pid = _read_serve_pid(state_dir) or proc.pid

    # サービスが空のままでは使い道が無いので、書き手への委譲まで登録する。
    # --no-delegate を付けたときだけ省く（自分で委譲を組む場合）。
    #
    # ここで失敗したら、起動済みのサーバを必ず止めてから抜ける。止めないと、
    # 記録にも残らないプロセスがポートを掴んだまま残る（テストで実際に起きた）。
    sub_path = ""
    try:
        if not args.no_delegate:
            raw_path = (args.path or "").strip() or (existing.sub_path if existing else "")
            default_leaf = sync_id if (join_url and sync_id) else name
            sub_path = raw_path.rstrip("/") if raw_path else f"{effective_root_anchor}/{default_leaf}"
            if not sub_path.startswith("/"):
                sub_path = "/" + sub_path
            # 根の直下でなければ、親のパスも委譲が要る（L1 は多段）
            _ensure_parent_delegations(root_key, root_pub, effective_root_anchor, sub_path, local_registry_url)
            register_delegation(root_key, writer_pub, sub_path, local_registry_url)
            print(_("[dfssvc] 委譲を登録: {sub_path}（書き手 {writer_name}）").format(sub_path=sub_path, writer_name=writer_key.name))

        service = Service(
            name=name,
            state_dir=str(state_dir),
            root_key=str(root_key),
            root_pub=str(root_pub),
            writer_key=str(writer_key),
            writer_pub=str(writer_pub),
            sub_path=sub_path,
            registry_port=registry_port,
            ost_port=ost_port,
            bind=effective_host,
            advertise=advertised,
            root_anchor=effective_root_anchor,
            pid=server_pid,
            started_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            config_path=str(store.path),
            log_path=str(log_path),
            role=service_role,
            role_epoch=service_role_epoch,
            ost_dir=str(ost_dir),
        )
        store.services[name] = service
        store.save()
    except BaseException:
        _terminate(proc)
        raise

    if args.json:
        print(json.dumps(service.to_dict(), ensure_ascii=False, indent=2))
    else:
        print(_("[dfssvc] 起動しました: {name}（PID {pid}）").format(name=name, pid=proc.pid))
        print(f"  L2 Registry : {service.registry_url}")
        print(f"  L3 OST      : tls://{service.ost_endpoint}")
        if sync_id:
            print(f"  共有 ID     : {sync_id}")
        if subscribe_list:
            print(f"  購読 ID     : {', '.join(subscribe_list)}")
        print()
        print(_("[dfssvc] dfscli につなぐには:"))
        key_hint = service.writer_key or _("<書き手の Ed25519 秘密鍵>")
        print(
            f"  dfscli config create {name} --registry {service.registry_url} "
            f"--key {key_hint} --secret <tree_secret>"
        )
        print(_("  # L3 の場所もサブツリーも L2 が知っているので --ost も --path も不要です"))
        if service.sub_path:
            print(_("  # このサーバのサブツリー: {sub_path}").format(sub_path=service.sub_path))
        print(_("  # 書き手の鍵: {key_hint}").format(key_hint=key_hint) if service.writer_key else "")
    if args.foreground:
        try:
            return int(proc.wait() or 0)
        except KeyboardInterrupt:
            _terminate(proc)
            return 0
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    store = ServiceStore()
    if args.json:
        print(json.dumps([s.to_dict() for s in store.services.values()], ensure_ascii=False, indent=2))
        return 0
    if not store.services:
        print("記録されたサービスはありません")
        return 0
    for name, s in sorted(store.services.items()):
        state = "稼働中" if s.is_running() else "停止"
        print(f"{name:12} {state:6} L2={s.registry_port} L3={s.ost_port} PID={s.pid}")
        print(f"{'':12} {s.registry_url}  (状態: {s.state_dir})")
    return 0


def _fetch_runtime_status(registry_url: str) -> Optional[Dict[str, Any]]:
    import urllib.request

    headers: Dict[str, str] = {}
    token = os.environ.get("DFS_RELAY_TOKEN", "").strip()
    if token:
        headers["X-DFS-Relay-Token"] = token
    req = urllib.request.Request(
        f"{registry_url.rstrip('/')}/_p2p/status",
        headers=headers,
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=2.0) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def cmd_status(args: argparse.Namespace) -> int:
    store = ServiceStore()
    s = store.get(_resolve_service_name(args))
    alive = s.is_running()
    runtime = _fetch_runtime_status(s.registry_url) if alive else None
    if args.json:
        payload = s.to_dict()
        if runtime is not None:
            payload["runtime_status"] = runtime
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0 if alive else 1
    print(f"Name        : {s.name}")
    print(f"State       : {'稼働中' if alive else '停止'}")
    print(f"PID         : {s.pid}")
    print(f"Started     : {s.started_at}")
    print(f"L2 Registry : {s.registry_url}")
    print(f"L3 OST      : tls://{s.ost_endpoint}")
    print(f"Root Anchor : {s.root_anchor}")
    print(f"Role        : {s.role} (epoch={s.role_epoch})")
    if s.sub_path:
        print(f"Subtree     : {s.sub_path}")
    if s.writer_key:
        print(f"Writer Key  : {s.writer_key}")
    print(f"State Dir   : {s.state_dir}")
    if s.ost_dir:
        print(f"OST Dir     : {s.ost_dir}")
    print(f"Root Pubkey : {s.root_pub}")
    print(f"Log         : {s.log_path}")
    if not alive:
        return 1
    # L2 に実際に聞く
    try:
        import urllib.request

        body = json.dumps({"path": s.root_anchor}).encode("utf-8")
        req = urllib.request.Request(
            f"{s.registry_url}/v1/resolve", data=body,
            headers={"Content-Type": "application/json"}, method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        head = data.get("head_log")
        print(f"L2 応答     : OK（先頭版 {'あり' if head else 'なし'}）")
    except Exception as e:  # noqa: BLE001 - 表示のため
        print(f"L2 応答     : 失敗（{e}）")
        return 1
    if runtime:
        ost_info = runtime.get("ost") or {}
        ram_mb = (ost_info.get("ram_bytes") or 0) / (1024 * 1024)
        max_ram_mb = (ost_info.get("max_ram_bytes") or 0) / (1024 * 1024)
        disk_mb = (ost_info.get("disk_bytes") or 0) / (1024 * 1024)
        avail = ost_info.get("mem_available_bytes")
        avail_str = f", Avail={avail / (1024 * 1024):.1f} MiB" if avail is not None else ""
        print(
            f"OST Memory  : RAM {ram_mb:.1f} / {max_ram_mb:.1f} MiB, "
            f"Disk {disk_mb:.1f} MiB ({ost_info.get('chunks_count', 0)} chunks{avail_str})"
        )
        sh = ost_info.get("storage_health") or {}
        if sh:
            kind = "tmpfs" if sh.get("is_tmpfs") else "disk"
            free_gb = (sh.get("free_bytes") or 0) / (1024 ** 3)
            print(f"Storage     : {kind}, free={free_gb:.2f} GiB")
        p2p_info = runtime.get("p2p") or {}
        if p2p_info.get("enabled"):
            conns = p2p_info.get("connections") or {}
            pid = str(p2p_info.get("peer_id") or "")
            short_pid = pid[:16] + "..." if len(pid) > 16 else pid
            print(
                f"P2P Paths   : peer={short_pid}, total={conns.get('total', 0)} "
                f"(direct={conns.get('direct', 0)}, relay={conns.get('relayed', 0)}, "
                f"ipv6={conns.get('ipv6', 0)}, dcutr={conns.get('dcutr_active', 0)})"
            )
            ls = p2p_info.get("last_sync")
            if isinstance(ls, dict):
                mb = (ls.get("bytes") or 0) / (1024 * 1024)
                mbps = (ls.get("bps") or 0.0) / (1024 * 1024)
                per_peer = ls.get("per_peer") or {}
                peer_dist = ", ".join(f"{str(k)[:10]}={v}" for k, v in per_peer.items())
                print(
                    f"Last Sync   : {ls.get('fetched', 0)}/{ls.get('remote_total', 0)} chunks "
                    f"({mb:.2f} MiB in {ls.get('duration_s', 0)}s, {mbps:.2f} MiB/s)"
                    + (f" [{peer_dist}]" if peer_dist else "")
                )
        else:
            print("P2P Paths   : disabled")
    return 0


def cmd_stop(args: argparse.Namespace) -> int:
    store = ServiceStore()
    name = _resolve_service_name(args)
    s = store.get(name)
    stopped = _stop_process(s)
    if args.forget:
        store.services.pop(name, None)
        store.save()
        print(f"[dfssvc] 記録からも消しました: {name}")
    else:
        # 状態は残す（再開できるように PID だけ 0 にする）
        s.pid = 0
        store.save()
    print(f"[dfssvc] {'停止しました' if stopped else 'もともと動いていません'}: {name}")
    return 0


def cmd_forget(args: argparse.Namespace) -> int:
    """停止済みサービスの記録だけを削除し、状態・鍵・チャンクは残す。"""
    store = ServiceStore()
    name = _resolve_service_name(args)
    service = store.get(name)
    if service.is_running() or _recorded_server_is_alive(service):
        raise ServiceError(
            f"サービス {name!r} は稼働中です。先に 'dfssvc stop {name}' を実行してください"
        )
    store.services.pop(name, None)
    store.save()
    print(f"[dfssvc] 記録だけ削除しました（状態は保持）: {name}")
    return 0


def cmd_prune(args: argparse.Namespace) -> int:
    """停止済みかつプロセスが存在しないサービス記録を整理する。"""
    store = ServiceStore()
    stale = [
        service
        for service in store.services.values()
        if not service.is_running() and not _recorded_server_is_alive(service)
    ]
    if not stale:
        print("[dfssvc] 削除対象の停止済み記録はありません")
        return 0
    for service in sorted(stale, key=lambda item: item.name):
        print(f"[dfssvc] 停止済み記録: {service.name}")
    if not args.apply:
        print(f"[dfssvc] dry-run: {len(stale)}件。削除するには --apply を指定してください")
        return 0
    for service in stale:
        store.services.pop(service.name, None)
    store.save()
    print(f"[dfssvc] 停止済み記録を{len(stale)}件削除しました（状態は保持）")
    return 0


def _purge_targets(service: Service) -> List[Path]:
    raw = [
        service.state_dir,
        service.ost_dir,
        service.root_key,
        f"{service.root_key}.pub",
        service.writer_key,
        f"{service.writer_key}.pub",
    ]
    targets: List[Path] = []
    seen: set[Path] = set()
    for value in raw:
        if not value:
            continue
        raw_p = Path(value).expanduser()
        path = raw_p if raw_p.is_symlink() else (raw_p.parent.resolve(strict=False) / raw_p.name)
        if path not in seen:
            seen.add(path)
            targets.append(path)
    base_raw = _base_dir(service.name)
    base = base_raw if base_raw.is_symlink() else (base_raw.parent.resolve(strict=False) / base_raw.name)
    if base not in seen:
        targets.append(base)
    return targets


def _remove_path(path: Path) -> None:
    forbidden = {
        Path("/").resolve(),
        Path.home().resolve(),
        dfs_home().resolve(strict=False),
        config_dir().resolve(strict=False),
        _repo_root().resolve(),
    }
    if path in forbidden:
        raise ServiceError(f"安全のため削除できません: {path}")
    if path.is_symlink() or path.is_file():
        path.unlink(missing_ok=True)
    elif path.is_dir():
        shutil.rmtree(path)


def cmd_purge(args: argparse.Namespace) -> int:
    """停止・記録・状態・鍵・OSTを明示的に削除する。"""
    store = ServiceStore()
    name = _resolve_service_name(args)
    service = store.get(name)
    targets = _purge_targets(service)
    if not args.yes:
        print(f"[dfssvc] purge対象: {name}")
        for path in targets:
            print(f"  {path}")
        print("[dfssvc] 実行するには --yes を指定してください")
        return 0
    if not _stop_process(service) and (
        service.is_running() or _recorded_server_is_alive(service)
    ):
        raise ServiceError(f"サービス {name!r} を停止できませんでした")
    for path in targets:
        _remove_path(path)
    store.services.pop(name, None)
    store.save()
    print(f"[dfssvc] サービスをpurgeしました: {name}")
    return 0


def cmd_prune_cache(args: argparse.Namespace) -> int:
    """停止中サービスの期限切れL2 locatorだけを削除する。"""
    store = ServiceStore()
    name = _resolve_service_name(args)
    service = store.get(name)
    if service.is_running() or _recorded_server_is_alive(service):
        raise ServiceError(
            f"サービス {name!r} は稼働中です。先に 'dfssvc stop {name}' を実行してください"
        )
    state_file = Path(service.state_dir).expanduser() / "registry_state.json"
    if not state_file.is_file():
        print(f"[dfssvc] registry_state.json がありません: {state_file}")
        return 0
    try:
        data = json.loads(state_file.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise ServiceError(f"registry state を読めません: {e}") from e
    locators = data.get("locators")
    if not isinstance(locators, dict):
        print("[dfssvc] locatorキャッシュはありません")
        return 0
    now = int(time.time())
    expired: List[str] = []
    for path, envelope in locators.items():
        try:
            expires_at = int((envelope.get("payload") or {}).get("expires_at", 0))
        except (AttributeError, TypeError, ValueError):
            expires_at = 0
        if now >= expires_at:
            expired.append(str(path))
    if not expired:
        print("[dfssvc] 期限切れlocatorはありません")
        return 0
    for path in sorted(expired):
        print(f"[dfssvc] 期限切れlocator: {path}")
    if not args.apply:
        print(
            f"[dfssvc] dry-run: {len(expired)}件。"
            "削除するには --apply を指定してください"
        )
        return 0
    for path in expired:
        locators.pop(path, None)
    write_private_json(state_file, data)
    print(f"[dfssvc] 期限切れlocatorを{len(expired)}件削除しました")
    return 0


def _terminate(proc: subprocess.Popen, timeout: float = 10.0) -> None:
    """起動したばかりのサーバを確実に止める（記録に載せる前の後始末）。"""
    if proc.poll() is not None:
        return
    if sys.platform == "win32":
        # venv 版 python.exe は本体を子プロセスで動かすので、木ごと止める。
        try:
            subprocess.run(
                ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                capture_output=True, timeout=15,
            )
        except (OSError, subprocess.SubprocessError):
            pass
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            pass
        return
    try:
        proc.terminate()
        proc.wait(timeout=timeout)
        return
    except subprocess.TimeoutExpired:
        pass
    except Exception:  # noqa: BLE001
        pass
    try:
        proc.kill()
        proc.wait(timeout=5)
    except Exception:  # noqa: BLE001
        pass


def _signal_terminate(pid: int) -> None:
    """プロセスに終了を頼む（Windows は taskkill、POSIX は SIGTERM）。"""
    if pid <= 0:
        return
    if sys.platform == "win32":
        try:
            subprocess.run(
                ["taskkill", "/PID", str(pid), "/T"],
                capture_output=True, timeout=15,
            )
        except (OSError, subprocess.SubprocessError):
            pass
        return
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError:
        pass


def _signal_kill(pid: int) -> None:
    """プロセスを強制終了する（Windows は taskkill /F、POSIX は SIGKILL）。"""
    if pid <= 0:
        return
    if sys.platform == "win32":
        try:
            subprocess.run(
                ["taskkill", "/PID", str(pid), "/T", "/F"],
                capture_output=True, timeout=15,
            )
        except (OSError, subprocess.SubprocessError):
            pass
        return
    try:
        os.kill(pid, signal.SIGKILL)
    except OSError:
        pass


def _request_stop(state_dir: Path) -> bool:
    """サーバに「止まれ」と伝える（``stop.request`` を見張っている）。"""
    try:
        (Path(state_dir) / "stop.request").write_text("stop\n", encoding="utf-8")
        return True
    except OSError:
        return False


def _process_matches_dfs(pid: int) -> bool:
    """POSIX で対象 PID が dfs プロセスであることを確認し、PID 再利用による誤殺を防ぐ。"""
    if sys.platform == "win32" or pid <= 0:
        return True
    proc_cmd = Path(f"/proc/{pid}/cmdline")
    if proc_cmd.is_file():
        try:
            cmdline = proc_cmd.read_bytes().replace(b"\x00", b" ").decode("utf-8", errors="ignore")
            return "dfs" in cmdline
        except OSError:
            return False
    try:
        res = subprocess.run(
            ["ps", "-p", str(pid), "-o", "command="],
            capture_output=True,
            text=True,
            timeout=2.0,
        )
        if res.returncode == 0 and res.stdout.strip():
            return "dfs" in res.stdout
    except (OSError, subprocess.SubprocessError):
        return True
    return False


def _recorded_server_is_alive(service: Service) -> bool:
    """PID と serve.pid の一致を確認し、記録されたサーバプロセスかを判定する。"""
    if not _process_alive(service.pid):
        return False
    try:
        recorded = int(
            (Path(service.state_dir) / "serve.pid").read_text(encoding="utf-8").strip()
        )
    except (OSError, ValueError):
        return False
    if recorded != service.pid:
        return False
    return _process_matches_dfs(service.pid)


def _stop_process(s: Service) -> bool:
    if not s.is_running() and not _recorded_server_is_alive(s):
        return False

    def _server_stopped() -> bool:
        if sys.platform == "win32":
            # Windowsではポートが閉じてもserve.logを書き終えるまで待つ。
            return not _process_alive(s.pid)
        # POSIXではdetached serverが親に回収されず、ゾンビの間は
        # _process_alive()が真を返すため、待受終了かつポート解放を停止完了とする。
        check_host = "127.0.0.1" if s.bind in ("0.0.0.0", "::", "") else s.bind
        return (
            not s.is_running()
            and is_port_free(s.registry_port, host=check_host, allow_reuse=True)
            and is_port_free(s.ost_port, host=check_host, allow_reuse=True)
        )

    # まずは穏当に。サーバは stop.request を見て httpd.shutdown() し、
    # finally で状態とチャンクを保存してから終了する（データを落とさない）。
    _request_stop(Path(s.state_dir))
    deadline = time.time() + 10
    while time.time() < deadline:
        if _server_stopped():
            return True
        time.sleep(0.3)
    # 応答が無ければ強制終了に切り替える。
    _signal_terminate(s.pid)
    deadline = time.time() + 3
    while time.time() < deadline:
        if _server_stopped():
            return True
        time.sleep(0.3)
    _signal_kill(s.pid)
    deadline = time.time() + 5
    while time.time() < deadline:
        if _server_stopped():
            return True
        time.sleep(0.2)
    return False


def cmd_env(args: argparse.Namespace) -> int:
    """dfscli につなぐための設定行を出す。"""
    store = ServiceStore()
    s = store.get(_resolve_service_name(args))
    writer = s.writer_key or "<書き手の Ed25519 秘密鍵>"
    print(f"# {s.name} に接続する（L3 は L2 が広告するので --ost は不要）")
    print(
        f"dfscli create {s.name} --registry {s.registry_url} "
        f"--key {writer} --secret <tree_secret>"
        f"{f' --root-pubkey {s.root_pub}' if s.root_pub else ''}"
        f"{f' --workdir {args.workdir}' if args.workdir else ''}"
    )
    print()
    print(f"# 参考: このサーバの L3 は tls://{s.ost_endpoint}")
    print(f"#        書き手の鍵 : {writer}" + ("（--key にそのまま使える）" if s.writer_key else ""))
    if s.sub_path:
        print(f"#        サブツリー : {s.sub_path}（L2 が鍵から引くので --path は不要）")
    if s.root_pub:
        # 本番はこちらを使う（TOFU を飛ばして初回から root を固定する）
        print(f"#        root の公開鍵: {s.root_pub}（--root-pubkey に渡すと TOFU を飛ばせる）")
    print(f"#        L1 の root 鍵: {s.root_key}（--signing-key に使う）")
    return 0


def _domain_from_root_anchor(root_anchor: str) -> str:
    """``/example.com`` から ``example.com`` を取り出す。"""
    value = str(root_anchor or "").strip().strip("/")
    if not value:
        raise ServiceError("root_anchor が空です。--domain を指定してください")
    return value.split("/", 1)[0].lower()


def cmd_dnssec(args: argparse.Namespace) -> int:
    """DNSSEC の ``_dfs.<domain>`` TXT に置く JSON を出力する。"""
    store = ServiceStore()
    service = store.get(_resolve_service_name(args))
    domain = (args.domain or _domain_from_root_anchor(service.root_anchor)).strip().rstrip(".").lower()

    root_pub_path = Path(service.root_pub).expanduser()
    if not root_pub_path.is_file():
        raise ServiceError(f"root 公開鍵がありません: {root_pub_path}")
    root_pubkey = root_pub_path.read_text(encoding="utf-8").strip()
    if not root_pubkey:
        raise ServiceError(f"root 公開鍵が空です: {root_pub_path}")

    primary_url = args.primary_url
    if not primary_url:
        if service.role == "secondary":
            raise ServiceError(
                "secondary の TXT を作るには --primary-url が必要です"
            )
        primary_url = service.registry_url

    registries: List[Dict[str, str]] = [
        {"role": "primary", "url": primary_url}
    ]
    secondary_urls = list(getattr(args, "secondary_url", None) or [])
    if (
        service.role == "secondary"
        and service.registry_url != primary_url
        and service.registry_url not in secondary_urls
    ):
        secondary_urls.append(service.registry_url)
    seen_urls = {primary_url}
    for url in secondary_urls:
        value = str(url).strip()
        if not value or value in seen_urls:
            continue
        seen_urls.add(value)
        registries.append({"role": "secondary", "url": value})

    record = {
        "schema": "dfs-discovery-v1",
        "domain": domain,
        "epoch": int(args.epoch) if args.epoch is not None else int(service.role_epoch),
        "registries": registries,
        "root_anchor": service.root_anchor,
        "root_pubkey": root_pubkey,
        "ttl": int(args.ttl),
    }
    txt_value = json.dumps(
        record, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    )
    # 生成した値を discovery のパーサにも通し、primary 1 つ・URL 形式・TTL を確認する。
    parse_discovery_text(txt_value, expected_domain=domain)

    record_name = f"{DEFAULT_RECORD_PREFIX}.{domain}"
    if args.json:
        print(json.dumps(record, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        print(txt_value)
    print(f"# TXT record: {record_name}", file=sys.stderr)
    return 0


def cmd_logs(args: argparse.Namespace) -> int:
    store = ServiceStore()
    s = store.get(_resolve_service_name(args))
    path = Path(s.log_path)
    if not path.is_file():
        raise ServiceError(f"ログがありません: {path}")
    text = path.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()
    for line in lines[-args.lines:]:
        print(line)
    return 0


# --------------------------------------------------------------------------
def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="dfssvc",
        description="ローカルに dfs サーバ（L2 + L3）を 1 つ立てる",
    )
    ap.add_argument("--json", action="store_true", help="結果を JSON で出す")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("start", help="サーバを立てる（引数なしでローカル単一起動）")
    _add_service_name_args(p)
    p.add_argument(
        "--hub",
        nargs="?",
        const="auto",
        help="root / リレーハブとして公開起動する（例: --hub dfs.example.com）",
    )
    p.add_argument(
        "--join",
        action="append",
        default=None,
        help="指定した root ハブへ参加する（複数指定可。例: --join https://dfs.example.com）",
    )
    p.add_argument(
        "--subscribe",
        action="append",
        default=[],
        help="自動同期・シードする相手の Base64 共有 ID（複数指定可）",
    )
    p.add_argument(
        "--port",
        type=int,
        help=(
            f"L2 Registryの開始番号。L3 OSTにはN+1を使う"
            f"（既定 {DEFAULT_START_PORT}）"
        ),
    )
    p.add_argument(
        "--registry-port",
        type=int,
        help="L2 Registry（L4ログもここで公開）の待受ポート",
    )
    p.add_argument(
        "--ost-port",
        type=int,
        help="L3 OST（暗号化チャンク）の待受ポート。--registry-portとセットで指定",
    )
    p.add_argument("--ost-dir", help="L3 OST チャンクの保存先（既定: <state-dir>/ost_chunks）")
    p.add_argument("--foreground", action="store_true", help="前面で動かす（Ctrl-C で停止）")
    p.add_argument("--force", action="store_true", help="起動中なら停止し、既存設定を引き継いで再起動する")
    # 高度な設定・後方互換用（--help を簡潔に保つため既定では非表示）
    p.add_argument("--host", default=None, help=argparse.SUPPRESS)
    p.add_argument("--advertise", help=argparse.SUPPRESS)
    p.add_argument("--state-dir", help=argparse.SUPPRESS)
    p.add_argument("--root-key", help=argparse.SUPPRESS)
    p.add_argument("--root-anchor", default=None, help=argparse.SUPPRESS)
    p.add_argument("--writer-key", help=argparse.SUPPRESS)
    p.add_argument("--path", help=argparse.SUPPRESS)
    p.add_argument("--no-delegate", action="store_true", help=argparse.SUPPRESS)
    p.add_argument("--auto-delegate", action="store_true", help="公開ハブで /v1/auto-delegate を有効化する")
    p.add_argument("--no-auto-delegate", action="store_true", help=argparse.SUPPRESS)
    p.add_argument("--wait", type=float, default=30.0, help=argparse.SUPPRESS)
    p.add_argument("--replica", action="append", default=[], help=argparse.SUPPRESS)
    p.add_argument("--role", choices=["primary", "secondary"], help=argparse.SUPPRESS)
    p.add_argument("--role-epoch", type=int, help=argparse.SUPPRESS)
    p.add_argument("--relay-node", help=argparse.SUPPRESS)
    p.add_argument("--relay-token", help=argparse.SUPPRESS)
    p.set_defaults(func=cmd_start)

    p = sub.add_parser("list", help="記録済みのサービスを一覧する")
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("status", help="状態と接続情報を出す")
    _add_service_name_args(p)
    p.set_defaults(func=cmd_status)

    p = sub.add_parser("stop", help="止める")
    _add_service_name_args(p)
    p.add_argument("--forget", action="store_true", help="記録からも消す")
    p.set_defaults(func=cmd_stop)

    p = sub.add_parser("forget", help="停止済みサービスの記録だけを消す")
    _add_service_name_args(p)
    p.set_defaults(func=cmd_forget)

    p = sub.add_parser("prune", help="停止済みサービス記録を整理する")
    p.add_argument(
        "--apply",
        action="store_true",
        help="実際に削除する（省略時はdry-run）",
    )
    p.set_defaults(func=cmd_prune)

    p = sub.add_parser("purge", help="サービスを停止して状態・鍵・OSTを削除する")
    _add_service_name_args(p)
    p.add_argument(
        "--yes",
        action="store_true",
        help="破壊的な削除を確認して実行する",
    )
    p.set_defaults(func=cmd_purge)

    p = sub.add_parser("prune-cache", help="停止中サービスの期限切れlocatorを掃除する")
    _add_service_name_args(p)
    p.add_argument(
        "--apply",
        action="store_true",
        help="実際に削除する（省略時はdry-run）",
    )
    p.set_defaults(func=cmd_prune_cache)

    p = sub.add_parser("env", help="dfscli の設定行を出す")
    _add_service_name_args(p)
    p.add_argument("--workdir", help="--workdir も付ける")
    p.set_defaults(func=cmd_env)

    p = sub.add_parser("dnssec", help="_dfs.<domain> TXT に置く JSON を出す")
    _add_service_name_args(p)
    p.add_argument("--domain", help="TXT のドメイン（既定は root_anchor から推定）")
    p.add_argument(
        "--primary-url",
        help="primary registry の URL（secondary では必須。既定はこのサービスの URL）",
    )
    p.add_argument(
        "--secondary-url", action="append", default=[],
        help="secondary registry の URL（複数指定可）",
    )
    p.add_argument("--ttl", type=int, default=300, help="TXT の推奨 TTL（既定 300）")
    p.add_argument(
        "--epoch", type=int,
        help="discovery の世代（既定は service の role_epoch）",
    )
    p.set_defaults(func=cmd_dnssec)

    p = sub.add_parser("logs", help="ログの末尾を出す")
    _add_service_name_args(p)
    p.add_argument("-n", "--lines", type=int, default=30)
    p.set_defaults(func=cmd_logs)

    return ap


def main(argv: Optional[List[str]] = None) -> int:
    from .i18n import _, configure_stdio, translate_parser

    configure_stdio()
    parser = translate_parser(build_parser(), _)
    args = parser.parse_args(argv)
    try:
        return int(args.func(args) or 0)
    except ServiceError as e:
        print(f"[dfssvc] {e}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print(f"\n[dfssvc] {_('中断しました')}", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
