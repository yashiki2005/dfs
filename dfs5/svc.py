#!/usr/bin/env python3
"""
dfs5/svc.py
ローカルに dfs5 サーバを簡単に立てるコマンド（`dfs5svc`）。

`dfs5 serve` は状態ディレクトリ・root 公開鍵・L2/L3 のポートをすべて自分で用意する。
このコマンドは「ローカルで 1 つ立てて試す」ための最小の入口で、次を肩代わりする。

1. 連続した空きポートを 2 つ探し、1 つ目を L2（名簿）、2 つ目を L3（OST）に割り当てる。
2. root の鍵（L1 権威の Ed25519）が無ければ作る。
3. 状態ディレクトリを用意し、`dfs5 serve` を起動する。
4. 立ち上がったら、接続に必要な値を `~/.config/dfs5/services.json` に記録する
   （`dfs5r config create` に渡す値を自分で組み立てなくて済むように）。
5. `stop` / `list` / `status` で後始末と確認ができる。

使い方:
    dfs5svc start                 # 連続した空きポートで1つ立てる（既定 19440 から探索）
    dfs5svc start --name dev      # 名前を付ける（既定 "local"）
    dfs5svc start --port 20000    # この番号から連続した空きを探す
    dfs5svc start --foreground    # 前面で動かす（Ctrl-C で止まる）
    dfs5svc list                  # 記録済みのサービス
    dfs5svc status dev            # 状態と接続情報
    dfs5svc stop dev              # 止める
    dfs5svc env dev               # dfs5r config create の行を出す

出力は機械可読も兼ねる（`--json`）。
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import socket
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

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
BASE_DIR_NAME = "dfs5svc"


class ServiceError(Exception):
    """使い方の誤り・状態の不整合"""


# --------------------------------------------------------------------------
# 空きポート
# --------------------------------------------------------------------------
def is_port_free(port: int, host: str = "127.0.0.1") -> bool:
    """そのポートを今から使えるか。

    2 段で確かめる。macOS では ``SO_REUSEADDR`` を立てた bind が、他のプロセスが
    ``0.0.0.0:port`` で待ち受けていても通ってしまう（``127.0.0.1:port`` とは別物として
    扱われるため）。まず接続を試して「誰かが答えている」なら使用中とし、次に
    ``SO_REUSEADDR`` 無しの bind で確かめる。

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

    # 2) SO_REUSEADDR を付けずに bind してみる（TIME_WAIT の残骸にも当たる）
    for family, socktype, proto, _canon, addr in socket.getaddrinfo(
        host, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP
    ):
        s = socket.socket(family, socktype, proto)
        try:
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
        if all(is_port_free(port + i, host) for i in range(count)):
            return port, port + 1
        port += 1
        tried += 1
    raise ServiceError(f"{start} から連続した空きポート {count} 個が見つかりませんでした")


def _port_in_use_by_us(pid: int, port: int) -> bool:
    """その pid が port を掴んでいるか（lsof があれば見る）。"""
    res = subprocess.run(
        ["lsof", "-nP", "-a", "-p", str(pid), f"-iTCP:{port}", "-sTCP:LISTEN"],
        capture_output=True, text=True,
    )
    return res.returncode == 0 and str(port) in res.stdout


# --------------------------------------------------------------------------
# 記録（サービス一覧）
# --------------------------------------------------------------------------
@dataclass
class Service:
    """立てた dfs5 サーバ 1 つぶんの記録。"""

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

    @property
    def registry_url(self) -> str:
        host = self.advertise or "127.0.0.1"
        return f"http://{host}:{self.registry_port}"

    @property
    def ost_endpoint(self) -> str:
        host = self.advertise or "127.0.0.1"
        return f"{host}:{self.ost_port}"

    def is_running(self) -> bool:
        if self.pid <= 0:
            return False
        try:
            os.kill(self.pid, 0)
        except OSError:
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
    """`~/.config/dfs5/services.json` の読み書き。"""

    def __init__(self, path: Optional[Path] = None):
        self.path = path or (Path.home() / ".config" / "dfs5" / CONFIG_FILENAME)
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
            data = dict(item)
            data.setdefault("name", name)
            data.pop("registry_url", None)  # 派生値は保存しない
            data.pop("ost_endpoint", None)
            data.pop("running", None)
            self.services[name] = Service(**data)

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "schema": "dfs5-services-v1",
            "services": {n: asdict(s) for n, s in sorted(self.services.items())},
        }
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        os.chmod(tmp, 0o600)
        tmp.replace(self.path)

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
    if path.exists() and Path(f"{path}.pub").exists():
        return path
    path.parent.mkdir(parents=True, exist_ok=True)
    res = subprocess.run(
        ["ssh-keygen", "-t", "ed25519", "-N", "", "-C", f"dfs5svc-root@{socket.gethostname()}",
         "-f", str(path)],
        capture_output=True, text=True,
    )
    if res.returncode != 0:
        raise ServiceError(f"root 鍵を作れませんでした: {res.stderr.strip()}")
    os.chmod(path, 0o600)
    return path


def ensure_writer_key(path: Path) -> Path:
    """書き手（L4 のログに署名する人）の Ed25519 鍵を用意する。"""
    if path.exists() and Path(f"{path}.pub").exists():
        return path
    path.parent.mkdir(parents=True, exist_ok=True)
    res = subprocess.run(
        ["ssh-keygen", "-t", "ed25519", "-N", "", "-C", f"dfs5svc-writer@{socket.gethostname()}",
         "-f", str(path)],
        capture_output=True, text=True,
    )
    if res.returncode != 0:
        raise ServiceError(f"書き手の鍵を作れませんでした: {res.stderr.strip()}")
    os.chmod(path, 0o600)
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
        sys.executable, "-m", "dfs5.cli", "delegate",
        "--parent", parent,
        "--path", sub_path,
        "--signing-key", str(root_key),
        "--writer-pubkey", str(writer_pub),
        "--registry", registry_url,
        "--ttl-days", str(int(ttl_days)),
    ]
    res = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=60)
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
        sys.executable, "-m", "dfs5.cli", "delegate",
        "--parent", parent,
        "--path", child,
        "--signing-key", str(root_key),
        "--writer-pubkey", str(root_pub),
        "--registry", registry_url,
        "--ttl-days", str(int(ttl_days)),
    ]
    res = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=60)
    if res.returncode != 0:
        raise ServiceError(
            f"中間の委譲 ({child}) の登録に失敗しました: "
            + (res.stderr.strip() or res.stdout.strip())
        )


def wait_for_l2(registry_url: str, timeout: float = 30.0) -> bool:
    """L2 が resolve に答えるようになるまで待つ。"""
    import urllib.error
    import urllib.request

    body = json.dumps({"path": DEFAULT_ROOT_ANCHOR}).encode("utf-8")
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
    return Path.home() / BASE_DIR_NAME / name


def cmd_start(args: argparse.Namespace) -> int:
    store = ServiceStore()
    name = args.name

    if name in store.services and not args.force:
        raise ServiceError(
            f"サービス {name!r} は既に記録にあります。"
            f"止めるなら 'dfs5svc stop {name}'、作り直すなら --force を付けてください"
        )

    host = args.host
    start_port = args.port if args.port is not None else DEFAULT_START_PORT
    # 記録済みのサービスが使っているポートは避ける
    while True:
        used = {
            s.registry_port for s in store.services.values() if s.name != name
        } | {s.ost_port for s in store.services.values() if s.name != name}
        while start_port in used:
            start_port += 1
        registry_port, ost_port = find_consecutive_free_ports(start_port, 2, host)
        if registry_port not in used and ost_port not in used:
            break
        start_port = ost_port + 1

    base = _base_dir(name)
    state_dir = Path(args.state_dir).expanduser() if args.state_dir else base / "server"
    root_key = Path(args.root_key).expanduser() if args.root_key else base / "keys" / "root"
    writer_key = Path(args.writer_key).expanduser() if args.writer_key else base / "keys" / "writer"
    log_path = base / "serve.log"

    state_dir.mkdir(parents=True, exist_ok=True)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    ensure_root_key(root_key)
    ensure_writer_key(writer_key)
    root_pub = Path(f"{root_key}.pub")
    writer_pub = Path(f"{writer_key}.pub")

    advertised = args.advertise or ("127.0.0.1" if host in ("0.0.0.0", "::") else host)
    registry_url = f"http://{advertised}:{registry_port}"

    cmd = [
        sys.executable, "-m", "dfs5.cli", "serve",
        "--bind", host,
        "--registry-port", str(registry_port),
        "--ost-port", str(ost_port),
        "--root-anchor", args.root_anchor,
        "--root-pubkey", str(root_pub),
        "--state-dir", str(state_dir),
        "--advertise", advertised,
    ]

    print(f"[dfs5svc] 空きポート: L2={registry_port} / L3={ost_port}（連続した組）")
    print(f"[dfs5svc] 状態      : {state_dir}")
    print(f"[dfs5svc] root 鍵   : {root_key}")
    print(f"[dfs5svc] ログ      : {log_path}")

    if args.foreground:
        print("[dfs5svc] 前面で起動します（Ctrl-C で停止）")
        env = dict(os.environ)
        repo = _repo_root()
        env["PYTHONPATH"] = str(repo) + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
        try:
            return subprocess.call(cmd, env=env)
        except KeyboardInterrupt:
            return 0

    env = dict(os.environ)
    repo = _repo_root()
    env["PYTHONPATH"] = str(repo) + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    with open(log_path, "ab") as log:
        proc = subprocess.Popen(
            cmd, env=env, stdout=log, stderr=log,
            stdin=subprocess.DEVNULL, start_new_session=True,
        )

    if not wait_for_l2(registry_url, timeout=args.wait):
        if proc.poll() is not None:
            tail = log_path.read_text(encoding="utf-8", errors="replace")[-2000:]
            raise ServiceError(f"サーバが起動しませんでした（終了コード {proc.returncode}）:\n{tail}")
        proc.terminate()
        raise ServiceError(f"L2 ({registry_url}) が {args.wait:.0f} 秒以内に応答しませんでした")

    # サービスが空のままでは使い道が無いので、書き手への委譲まで登録する。
    # --no-delegate を付けたときだけ省く（自分で委譲を組む場合）。
    #
    # ここで失敗したら、起動済みのサーバを必ず止めてから抜ける。止めないと、
    # 記録にも残らないプロセスがポートを掴んだまま残る（テストで実際に起きた）。
    sub_path = ""
    try:
        if not args.no_delegate:
            raw_path = (args.path or "").strip()
            sub_path = raw_path.rstrip("/") if raw_path else f"{args.root_anchor}/{name}"
            if not sub_path.startswith("/"):
                sub_path = "/" + sub_path
            # 根の直下でなければ、親のパスも委譲が要る（L1 は多段）
            _ensure_parent_delegations(root_key, root_pub, args.root_anchor, sub_path, registry_url)
            register_delegation(root_key, writer_pub, sub_path, registry_url)
            print(f"[dfs5svc] 委譲を登録: {sub_path}（書き手 {writer_key.name}）")
    except BaseException:
        _terminate(proc)
        raise

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
        bind=host,
        advertise=advertised,
        root_anchor=args.root_anchor,
        pid=proc.pid,
        started_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        config_path=str(store.path),
        log_path=str(log_path),
    )
    store.services[name] = service
    store.save()

    if args.json:
        print(json.dumps(service.to_dict(), ensure_ascii=False, indent=2))
    else:
        print(f"[dfs5svc] 起動しました: {name}（PID {proc.pid}）")
        print(f"  L2 Registry : {service.registry_url}")
        print(f"  L3 OST      : tls://{service.ost_endpoint}")
        print()
        print("[dfs5svc] dfs5r につなぐには:")
        key_hint = service.writer_key or "<書き手の Ed25519 秘密鍵>"
        print(
            f"  dfs5r config create {name} --registry {service.registry_url} "
            f"--key {key_hint} --secret <tree_secret>"
        )
        print(f"  # L3 の場所もサブツリーも L2 が知っているので --ost も --path も不要です")
        if service.sub_path:
            print(f"  # このサーバのサブツリー: {service.sub_path}")
        print(f"  # 書き手の鍵: {key_hint}" if service.writer_key else "")
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


def cmd_status(args: argparse.Namespace) -> int:
    store = ServiceStore()
    s = store.get(args.name)
    alive = s.is_running()
    if args.json:
        print(json.dumps(s.to_dict(), ensure_ascii=False, indent=2))
        return 0 if alive else 1
    print(f"Name        : {s.name}")
    print(f"State       : {'稼働中' if alive else '停止'}")
    print(f"PID         : {s.pid}")
    print(f"Started     : {s.started_at}")
    print(f"L2 Registry : {s.registry_url}")
    print(f"L3 OST      : tls://{s.ost_endpoint}")
    print(f"Root Anchor : {s.root_anchor}")
    if s.sub_path:
        print(f"Subtree     : {s.sub_path}")
    if s.writer_key:
        print(f"Writer Key  : {s.writer_key}")
    print(f"State Dir   : {s.state_dir}")
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
    return 0


def cmd_stop(args: argparse.Namespace) -> int:
    store = ServiceStore()
    s = store.get(args.name)
    stopped = _stop_process(s)
    if args.forget:
        store.services.pop(args.name, None)
        store.save()
        print(f"[dfs5svc] 記録からも消しました: {args.name}")
    else:
        # 状態は残す（再開できるように PID だけ 0 にする）
        s.pid = 0
        store.save()
    print(f"[dfs5svc] {'停止しました' if stopped else 'もともと動いていません'}: {args.name}")
    return 0


def _terminate(proc: subprocess.Popen, timeout: float = 10.0) -> None:
    """起動したばかりのサーバを確実に止める（記録に載せる前の後始末）。"""
    if proc.poll() is not None:
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


def _stop_process(s: Service) -> bool:
    if not s.is_running():
        return False
    try:
        os.kill(s.pid, signal.SIGTERM)
    except OSError:
        return False
    deadline = time.time() + 10
    while time.time() < deadline:
        if not s.is_running():
            return True
        time.sleep(0.3)
    try:
        os.kill(s.pid, signal.SIGKILL)
    except OSError:
        pass
    time.sleep(0.5)
    return not s.is_running()


def cmd_env(args: argparse.Namespace) -> int:
    """dfs5r につなぐための設定行を出す。"""
    store = ServiceStore()
    s = store.get(args.name)
    writer = s.writer_key or "<書き手の Ed25519 秘密鍵>"
    print(f"# {s.name} に接続する（L3 は L2 が広告するので --ost は不要）")
    print(
        f"dfs5r config create {s.name} --registry {s.registry_url} "
        f"--key {writer} --secret <tree_secret>"
        f"{f' --workdir {args.workdir}' if args.workdir else ''}"
    )
    print()
    print(f"# 参考: このサーバの L3 は tls://{s.ost_endpoint}")
    print(f"#        書き手の鍵 : {writer}" + (f"（--key にそのまま使える）" if s.writer_key else ""))
    if s.sub_path:
        print(f"#        サブツリー : {s.sub_path}（L2 が鍵から引くので --path は不要）")
    print(f"#        L1 の root : {s.root_key}（--signing-key に使う）")
    return 0


def cmd_logs(args: argparse.Namespace) -> int:
    store = ServiceStore()
    s = store.get(args.name)
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
        prog="dfs5svc",
        description="ローカルに dfs5 サーバ（L2 + L3）を 1 つ立てる",
    )
    ap.add_argument("--json", action="store_true", help="結果を JSON で出す")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("start", help="サーバを立てる")
    p.add_argument("--name", default=DEFAULT_NAME, help=f"サービスの名前（既定 {DEFAULT_NAME}）")
    p.add_argument("--host", default="127.0.0.1", help="bind するアドレス（既定 127.0.0.1）")
    p.add_argument("--advertise", help="L2 が L3 の場所として広告するホスト（既定は --host から推定）")
    p.add_argument("--port", type=int, help=f"この番号から連続した空きを探す（既定 {DEFAULT_START_PORT}）")
    p.add_argument("--state-dir", help="状態ディレクトリ（既定 ~/dfs5svc/<name>/server）")
    p.add_argument("--root-key", help="root の Ed25519 鍵（既定 ~/dfs5svc/<name>/keys/root）")
    p.add_argument("--root-anchor", default=DEFAULT_ROOT_ANCHOR, help=f"根のパス（既定 {DEFAULT_ROOT_ANCHOR}）")
    p.add_argument("--writer-key", help="書き手の Ed25519 鍵（既定 ~/dfs5svc/<name>/keys/writer）")
    p.add_argument(
        "--path",
        help=f"委譲するサブツリー（既定 {DEFAULT_ROOT_ANCHOR}/<name>）。"
             "dfs5r は書き手の鍵からこのパスを引く",
    )
    p.add_argument("--no-delegate", action="store_true",
                   help="委譲を登録しない（サーバだけ立てる）")
    p.add_argument("--wait", type=float, default=30.0, help="起動を待つ秒数（既定 30）")
    p.add_argument("--foreground", action="store_true", help="前面で動かす（Ctrl-C で停止）")
    p.add_argument("--force", action="store_true", help="同じ名前の記録を上書きする")
    p.set_defaults(func=cmd_start)

    p = sub.add_parser("list", help="記録済みのサービスを一覧する")
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("status", help="状態と接続情報を出す")
    p.add_argument("name", nargs="?", default=DEFAULT_NAME)
    p.set_defaults(func=cmd_status)

    p = sub.add_parser("stop", help="止める")
    p.add_argument("name", nargs="?", default=DEFAULT_NAME)
    p.add_argument("--forget", action="store_true", help="記録からも消す")
    p.set_defaults(func=cmd_stop)

    p = sub.add_parser("env", help="dfs5r の設定行を出す")
    p.add_argument("name", nargs="?", default=DEFAULT_NAME)
    p.add_argument("--workdir", help="--workdir も付ける")
    p.set_defaults(func=cmd_env)

    p = sub.add_parser("logs", help="ログの末尾を出す")
    p.add_argument("name", nargs="?", default=DEFAULT_NAME)
    p.add_argument("-n", "--lines", type=int, default=30)
    p.set_defaults(func=cmd_logs)

    return ap


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args) or 0)
    except ServiceError as e:
        print(f"[dfs5svc] {e}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\n[dfs5svc] 中断しました", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
