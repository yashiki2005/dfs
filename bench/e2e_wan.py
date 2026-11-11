#!/usr/bin/env python3
"""
bench/e2e_wan.py
WAN 実機試験: WireGuard 越しの拠点（Mac / Pi5 / Sakura）から Scaleway の
dfs5 サーバへ push/pull し、高遅延・往復回数・耐障害性を測る。

`bench/e2e_lan.py` との違い:
  - L2/L3 の接続先と ssh 先を引数で指定できる（--server-host / --server-ssh）。
  - 各 push/pull の所要時間・往復回数・送受信バイトを JSON に残す（CLI の --metrics）。
  - サーバ側の状態を ssh 経由でリセット・再起動できる（--reset / --start-server）。
  - クライアントを ssh 先（Pi5 / Sakura）でも実行できる（--client-ssh）。
  - 失敗は例外にせず {"ok": false, "detail": ...} として記録する。

モード:
  --mode loopback : Mac 内でサーバもクライアントも動かす（ハーネスの自己検証用）
  --mode wan      : サーバは ssh 先（Scaleway）、クライアントはローカルまたは ssh 先

使い方（WAN, Mac → Scaleway）:
    python bench/e2e_wan.py --mode wan --label mac-to-scaleway \
        --server-host 172.16.1.60 --server-ssh ubuntu@172.16.1.60 \
        --server-key ~/.ssh/pi-mock-test

使い方（WAN, Pi5 → Scaleway。クライアントは ssh 先）:
    python bench/e2e_wan.py --mode wan --label pi5-to-scaleway \
        --server-host 172.16.1.60 --server-ssh ubuntu@172.16.1.60 \
        --server-key ~/.ssh/pi-mock-test \
        --client-ssh yy@192.168.0.7 --client-key ~/.ssh/pi-mock-test
"""

from __future__ import annotations

import argparse
import json
import platform
import re
import shlex
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SSH_COMMON = ["-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=15"]


# --------------------------------------------------------------------------
# プロセス・SSH 補助
# --------------------------------------------------------------------------
def sh(cmd: list[str], timeout: float = 300.0, stdin: str | None = None) -> tuple[int, str]:
    """外部コマンドを実行する。タイムアウトも例外にせず rc=124 で返す。"""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, input=stdin)
    except subprocess.TimeoutExpired:
        return 124, f"TIMEOUT after {timeout}s"
    except FileNotFoundError as e:
        return 127, f"{cmd[0]}: {e}"
    return p.returncode, (p.stdout + p.stderr).strip()


def ssh_run(key: str, target: str, command: str, timeout: float = 300.0, port: int = 22) -> tuple[int, str]:
    cmd = ["ssh", "-i", str(Path(key).expanduser()), *SSH_COMMON]
    if port != 22:
        cmd += ["-p", str(port)]
    return sh(cmd + [target, command], timeout)


def ssh_run(key: str, target: str, command: str, timeout: float = 300.0, port: int = 22) -> tuple[int, str]:
    """ssh でコマンドを実行する。

    stdin を ``/dev/null`` に固定する（``-n`` 相当）。これをしないと、ssh 先で
    起動した背景プロセスが stdin を握り、ssh チャネルが閉じずにタイムアウトする。
    scp/rsync はこの関数を使わないので、``-n`` を共有オプションにしない。
    """
    cmd = ["ssh", "-i", str(Path(key).expanduser()), *SSH_COMMON]
    if port != 22:
        cmd += ["-p", str(port)]
    return sh(cmd + [target, command], timeout, stdin="")


def scp_to(key: str, src: Path, target: str, dest: str, timeout: float = 120.0, port: int = 22) -> tuple[int, str]:
    cmd = ["scp", "-i", str(Path(key).expanduser()), *SSH_COMMON]
    if port != 22:
        cmd += ["-P", str(port)]
    return sh(cmd + [str(src), f"{target}:{dest}"], timeout)


def rsync_repo(key: str, src: Path, target: str, dest: str, timeout: float = 300.0, port: int = 22) -> tuple[int, str]:
    ssh_cmd = f"ssh -i {shlex.quote(str(Path(key).expanduser()))} {' '.join(SSH_COMMON)}"
    if port != 22:
        ssh_cmd += f" -p {port}"
    cmd = ["rsync", "-az", "--delete", "--exclude", ".git", "--exclude", "__pycache__",
           "--exclude", ".pytest_cache", "-e", ssh_cmd, str(src) + "/", f"{target}:{dest}/"]
    return sh(cmd, timeout)


def rtt_ms(host: str, count: int = 10) -> float | None:
    """ping の平均 RTT（ms）。macOS/Linux どちらの出力形式も受ける。"""
    rc, out = sh(["ping", "-c", str(count), host], timeout=45)
    m = re.search(r"min/avg/max/(?:mdev|stddev) = [\d.]+/([\d.]+)/", out)
    return float(m.group(1)) if m else None


def qpath(p: str) -> str:
    """シェル用にパスを引用する。先頭の ``~`` は ``"$HOME"`` に置き換える。

    ``shlex.quote("~/src")`` は ``'~/src'`` になり、チルダが展開されない。
    ローカル・ssh 先のどちらのシェルでも同じ文字列が使えるよう、ここで吸収する。
    """
    if p == "~":
        return '"$HOME"'
    if p.startswith("~/"):
        return '"$HOME"/' + shlex.quote(p[2:])
    return shlex.quote(p)


def _normalize_digest_lines(text: str) -> str:
    rows = []
    for line in text.splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2 and len(parts[0]) == 64:
            rows.append(f"{parts[0]}  {parts[1].strip().lstrip('*')}")
    return "\n".join(sorted(rows))


def tree_digest(path: Path, python: str = "python3") -> str:
    """ローカルのツリーを 1 本の正規化ダイジェスト文字列にする。"""
    code = (
        "import hashlib, os, sys\n"
        "root = sys.argv[1]\n"
        "rows = []\n"
        "for dirpath, dirnames, filenames in os.walk(root):\n"
        "    for fn in filenames:\n"
        "        if fn == '.DS_Store' or fn.startswith('._'):\n"
        "            continue\n"
        "        p = os.path.join(dirpath, fn)\n"
        "        rel = os.path.relpath(p, root)\n"
        "        h = hashlib.sha256(open(p,'rb').read()).hexdigest()\n"
        "        rows.append(h + '  ' + rel)\n"
        "print('\\n'.join(sorted(rows)))\n"
    )
    rc, out = sh([python, "-c", code, str(path)], timeout=120)
    return out if rc == 0 else ""


# --------------------------------------------------------------------------
# ハーネス本体
# --------------------------------------------------------------------------
class Harness:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.result: dict = {
            "schema": "dfs5-e2e-wan-v1",
            "label": args.label,
            "mode": args.mode,
            "measured_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "environment": {
                "control_host": platform.platform(),
                "control_python": platform.python_version(),
                "server_host": args.server_host,
                "server_ssh": args.server_ssh,
                "client_ssh": args.client_ssh,
                "l2_port": args.l2_port,
                "l3_port": args.l3_port,
                "files": args.files,
                "file_size": args.file_size,
                "chunk_count": args.chunk_count,
                "rtt_avg_ms": None,
            },
            "steps": [],
            "metrics": [],
            "verdict": {},
        }
        self.work = Path(args.work)
        self.remote_work = args.remote_work
        self.sub_path = "/example.com/alice/notes"
        self.secret = "dfs5-wan-shared-secret"
        self.registry_url = f"http://{args.server_host}:{args.l2_port}"
        self.ost_endpoint = f"{args.server_host}:{args.l3_port}"

    # ---- 記録 ----------------------------------------------------------
    def step(self, name: str, ok: bool, detail: str = "", ms: float | None = None) -> bool:
        row = {"step": name, "ok": bool(ok), "detail": str(detail)[:800]}
        if ms is not None:
            row["elapsed_ms"] = round(ms, 1)
        self.result["steps"].append(row)
        t0 = "\033[32mOK  \033[0m" if ok else "\033[31mNG  \033[0m"
        suffix = f" ({ms:.1f} ms)" if ms is not None else ""
        tail = f"  {str(detail)[:110]}" if detail else ""
        print(f"{t0} {name}{suffix}{tail}", flush=True)
        return bool(ok)

    def verdict(self, key: str, value) -> None:
        self.result["verdict"][key] = value

    def collect_metrics(self, out: str) -> None:
        for line in out.splitlines():
            if line.startswith("[dfs5 metrics] "):
                try:
                    self.result["metrics"].append(json.loads(line[len("[dfs5 metrics] "):]))
                except json.JSONDecodeError:
                    pass

    # ---- クライアント抽象化（ローカル or ssh 先） -----------------------
    def client_exec(self, command: str, timeout: float | None = None) -> tuple[int, str, float]:
        """クライアント側でコマンドを実行し、(rc, out, ms) を返す。"""
        t0 = time.perf_counter()
        if self.args.client_ssh:
            rc, out = ssh_run(self.args.client_key, self.args.client_ssh, command,
                              timeout=timeout or self.args.timeout)
        else:
            rc, out = sh(["/bin/sh", "-c", command], timeout=timeout or self.args.timeout)
        return rc, out, (time.perf_counter() - t0) * 1000.0

    def client_path(self, rel: str) -> str:
        """クライアント側のパス文字列（ローカルと ssh 先で同じ表記にする）。"""
        return rel

    def client_py(self) -> str:
        """クライアント側で使う python。ssh 先ならその端末の python3 を使う。"""
        if self.args.client_ssh:
            return self.args.remote_py
        return self.args.local_py

    def client_dfs5(self, subcmd: str) -> str:
        py = self.client_py()
        if self.args.client_ssh:
            return f"cd {qpath(self.args.remote_src_path)} && {py} -m dfs5.cli {subcmd}"
        return f"cd {shlex.quote(str(ROOT))} && {py} -m dfs5.cli {subcmd}"

    def client_run(self, name: str, subcmd: str, expect: str | None = None,
                   timeout: float | None = None, metrics: bool = False) -> tuple[bool, str]:
        cmd = self.client_dfs5(subcmd)
        if metrics:
            cmd += " --metrics"
        rc, out, ms = self.client_exec(cmd, timeout=timeout)
        ok = rc == 0 and (expect is None or expect in out)
        self.step(name, ok, (f"rc={rc} " if rc else "") + out, ms)
        if metrics:
            self.collect_metrics(out)
        return ok, out

    def client_digest(self, path: str) -> str:
        if self.args.client_ssh:
            code = (
                "import hashlib, os, sys\n"
                "root = sys.argv[1]\n"
                "rows = []\n"
                "for dirpath, dirnames, filenames in os.walk(root):\n"
                "    for fn in filenames:\n"
                "        if fn == '.DS_Store' or fn.startswith('._'):\n"
                "            continue\n"
                "        p = os.path.join(dirpath, fn)\n"
                "        rel = os.path.relpath(p, root)\n"
                "        rows.append(hashlib.sha256(open(p,'rb').read()).hexdigest() + '  ' + rel)\n"
                "print('\\n'.join(sorted(rows)))\n"
            )
            rc, out = ssh_run(self.args.client_key, self.args.client_ssh,
                              f"{self.client_py()} -c {shlex.quote(code)} {qpath(path)}")
            return out if rc == 0 else ""
        return tree_digest(Path(path))

    # ---- サーバ操作 ----------------------------------------------------
    def server_exec(self, command: str, expect: str | None = None, name: str | None = None,
                    timeout: float | None = None) -> tuple[bool, str]:
        if not self.args.server_ssh:
            return False, "no --server-ssh"
        t0 = time.perf_counter()
        rc, out = ssh_run(self.args.server_key, self.args.server_ssh, command,
                          timeout=timeout or self.args.timeout, port=self.args.server_port)
        ms = (time.perf_counter() - t0) * 1000.0
        if name:
            ok = rc == 0 and (expect is None or expect in out)
            self.step(name, ok, (f"rc={rc} " if rc else "") + out, ms)
            return ok, out
        return rc == 0, out

    # ==================================================================
    # シナリオ
    # ==================================================================
    def run(self) -> int:
        args = self.args
        local_work = self.work
        if local_work.exists() and not args.keep:
            shutil.rmtree(local_work, ignore_errors=True)
        (local_work / "keys").mkdir(parents=True, exist_ok=True)

        print("=" * 72)
        print(f"dfs5 WAN 実機試験: label={args.label} mode={args.mode}")
        print(f"  サーバ : {args.server_host} (L2 {args.l2_port} / L3 {args.l3_port})")
        print(f"  クライアント: {'ssh ' + args.client_ssh if args.client_ssh else 'ローカル'}")
        print("=" * 72, flush=True)

        # ---- 0. RTT ----
        if args.mode != "loopback":
            r = rtt_ms(args.server_host)
            self.result["environment"]["rtt_avg_ms"] = r
            self.step(f"RTT 計測（{args.server_host}）", r is not None, f"avg={r} ms" if r else "ping 失敗")

        # ---- 1. 鍵 ----
        ok_keys = self._setup_keys()
        if not ok_keys:
            return self._finalize(False)

        # ---- 2. リポジトリ配置 ----
        self._deploy_repo()
        # リセット（状態とマウントのみ）は鍵配置の後・起動の前に必ず走らせる

        # ---- 3. サーバ起動 ----
        if args.mode != "loopback":
            if not self._start_server():
                return self._finalize(False)
        else:
            if not self._start_local_server():
                return self._finalize(False)

        # ---- 4. 疎通 ----
        self._probe_l2()
        self._probe_l3()

        # ---- 5. 委譲 ----
        self._delegate()

        # ---- 6. クライアント init + データ生成 ----
        client_mount = f"{local_work}/client_mount" if not args.client_ssh else f"{self.remote_work}/client_mount"
        reader_mount = f"{local_work}/reader_mount" if not args.client_ssh else f"{self.remote_work}/reader_mount"
        if args.client_ssh:
            # 消すのは「クライアント側」のマウント。ssh 先（Sakura など）で実行する。
            # サーバ側に対して消すと、クライアントに古い pin が残り CAS 競合になる。
            rc, out, ms = self.client_exec(
                f"mkdir -p {qpath(self.remote_work)} && "
                f"rm -rf {qpath(client_mount)} {qpath(reader_mount)} && echo CLEAN_OK")
            self.step("クライアント作業ディレクトリ初期化", rc == 0 and "CLEAN_OK" in out, out, ms)
            # 鍵もクライアント側の作業ディレクトリ配下に置き直す（--reset で消えているため）
            r, o = ssh_run(args.client_key, args.client_ssh,
                           f"mkdir -p {qpath(self.remote_work)}/keys && echo MKDIR_OK")
            if r == 0 and "MKDIR_OK" in o:
                for fname in ("root.pub", "alice", "alice.pub"):
                    scp_to(args.client_key, self.work / "keys" / fname, args.client_ssh,
                           f"{self.remote_work}/keys/{fname}")

        self._init_mount("クライアント init", client_mount, "wan-client")
        self._generate_data(client_mount)

        # ---- 7. push ----
        self.client_run("クライアント push", f"push --mount {qpath(client_mount)}",
                        expect="[dfs5 push] OK", metrics=True)
        self.verdict("push_ok", self._last_ok())

        # ---- 8. reader init + pull ----
        self._init_mount("読取側 init", reader_mount, "wan-reader")
        self.client_run("読取側 pull", f"pull --mount {qpath(reader_mount)}",
                        expect="[dfs5 pull] OK", metrics=True)
        self.verdict("pull_ok", self._last_ok())

        # ---- 9. 内容一致 ----
        writer_digest = self.client_digest(f"{client_mount}/tree")
        reader_digest = self.client_digest(f"{reader_mount}/tree")
        match = writer_digest != "" and writer_digest == reader_digest
        self.step("内容一致（SHA-256）", match,
                  f"writer={len(writer_digest.splitlines())} 件, reader={len(reader_digest.splitlines())} 件")
        self.verdict("content_matches", match)

        # ---- 10. 同時書き込み（CAS） ----
        self._concurrent_conflict(client_mount, reader_mount)

        # ---- 11. 通信断 ----
        self._outage_test(client_mount)

        all_ok = all(v for v in self.result["verdict"].values() if v is not None)
        return self._finalize(all_ok)

    # ---------------- 各段階 ----------------
    def _last_ok(self) -> bool:
        return bool(self.result["steps"][-1]["ok"]) if self.result["steps"] else False

    def _setup_keys(self) -> bool:
        keys = self.work / "keys"
        ok = True
        for name in ("root", "alice"):
            priv = keys / name
            if not priv.exists():
                rc, out = sh(["ssh-keygen", "-t", "ed25519", "-N", "", "-C", f"wan-{name}@example.com",
                              "-f", str(priv)], timeout=60)
                if rc != 0:
                    ok = False
                    self.step(f"鍵生成（{name}）", False, out)
                    continue
                sh(["chmod", "600", str(priv)], timeout=30)
            self.step(f"鍵生成（{name}）", True, "ok" if priv.exists() else "欠落")
            ok = ok and priv.exists()
        return ok

    def _deploy_repo(self) -> None:
        args = self.args
        if not args.server_ssh:
            return
        # サーバにリポジトリと鍵を送る（親ディレクトリは rsync が作らないので先に用意する）
        self.server_exec(f"mkdir -p {qpath(str(Path(args.remote_src_path).parent))} "
                         f"{qpath(self.remote_work)}/keys && echo PARENT_OK", expect="PARENT_OK")
        rc, out = rsync_repo(args.server_key, ROOT, args.server_ssh, args.remote_src_path,
                             port=args.server_port)
        self.step("サーバへリポジトリ同期（rsync）", rc == 0, out or "ok")
        self.server_exec(f"mkdir -p {qpath(self.remote_work)}/keys && echo MK_OK",
                         expect="MK_OK")
        key_errors = []
        for fname in ("root", "root.pub", "alice", "alice.pub"):
            r, o = scp_to(args.server_key, self.work / "keys" / fname, args.server_ssh,
                          f"{self.remote_work}/keys/{fname}", port=args.server_port)
            if r != 0:
                key_errors.append(f"{fname}: {o}")
        if key_errors:
            self.step("サーバへ鍵配置", False, " / ".join(key_errors))
            return
        self.server_exec(f"chmod 600 {qpath(self.remote_work)}/keys/root {qpath(self.remote_work)}/keys/alice && "
                         f"ls -1 {qpath(self.remote_work)}/keys | tr '\\n' ' ' && echo KEYS_OK",
                         expect="KEYS_OK", name="サーバへ鍵配置")

        if args.client_ssh:
            ssh_run(args.client_key, args.client_ssh,
                    f"mkdir -p {qpath(str(Path(args.remote_src_path).parent))} "
                    f"{qpath(self.remote_work)}/keys")
            rc, out = rsync_repo(args.client_key, ROOT, args.client_ssh, args.remote_src_path)
            self.step("クライアントへリポジトリ同期（rsync）", rc == 0, out or "ok")
            client_key_errors = []
            for fname in ("root.pub", "alice", "alice.pub"):
                r, o = scp_to(args.client_key, self.work / "keys" / fname, args.client_ssh,
                              f"{self.remote_work}/keys/{fname}")
                if r != 0:
                    client_key_errors.append(f"{fname}: {o}")
            if client_key_errors:
                self.step("クライアントへ鍵配置", False, " / ".join(client_key_errors))
                return
            rc, out = ssh_run(args.client_key, args.client_ssh,
                              f"chmod 600 {self.remote_work}/keys/alice && ls -1 {self.remote_work}/keys | tr '\\n' ' ' && echo CKEYS_OK")
            self.step("クライアントへ鍵配置", rc == 0 and "CKEYS_OK" in out, out)

    def _start_server(self) -> bool:
        """サーバを起動する。

        起動と確認を分けるのが要点。
          - 起動: nohup で背景に回し、すぐ LAUNCHED を返す（ssh チャネルを掴ませない）。
          - 確認: 制御側から L2 を短いタイムアウトで何度も叩く。
        WAN では ssh のチャネルが閉じない・経路が一瞬切れることがあるため、
        1 回の長い ssh に頼らない。
        """
        args = self.args
        if args.reset:
            # 消すのはサーバ状態とマウントだけ。鍵 (keys/) は直前に配置済みなので残す。
            # 鍵まで消すと serve が root.pub を見つけられず起動に失敗する。
            self.server_exec(
                "pkill -f 'dfs5[.]cli serve' 2>/dev/null; sleep 1; "
                f"rm -rf {qpath(args.state_dir)} "
                f"{qpath(self.remote_work)}/server_mount "
                f"{qpath(self.remote_work)}/client_mount "
                f"{qpath(self.remote_work)}/reader_mount; echo RESET_OK",
                expect="RESET_OK", name="サーバ状態リセット", timeout=60)

        launch = (
            f"mkdir -p {qpath(self.remote_work)} && "
            f"cd {qpath(args.remote_src_path)} && "
            f"setsid nohup {args.remote_py} -m dfs5.cli serve --bind 0.0.0.0 "
            f"--registry-port {args.l2_port} --ost-port {args.l3_port} "
            f"--root-anchor /example.com --root-pubkey {qpath(self.remote_work)}/keys/root.pub "
            f"--state-dir {qpath(args.state_dir)} "
            f"> {qpath(self.remote_work)}/serve.log 2>&1 < /dev/null & "
            "sleep 1; echo LAUNCHED"
        )
        t0 = time.perf_counter()
        # stdin を掴ませないため ssh は -n 付きで呼ぶ。高遅延 WAN では ssh チャネルが
        # 閉じずタイムアウト扱いになることがあるので、この段階だけでは失敗と断定しない。
        rc, out = ssh_run(args.server_key, args.server_ssh, launch,
                          timeout=args.launch_timeout, port=args.server_port)
        launch_ms = (time.perf_counter() - t0) * 1000.0
        launch_seen = rc == 0 and "LAUNCHED" in out

        # L2 が応答するまでポーリングする（経路が不安定なときは長めに待つ）
        deadline = time.time() + args.start_wait
        probe = ["curl", "-s", "-m", "5", "-o", "/dev/null", "-X", "POST",
                 f"{self.registry_url}/v1/resolve",
                 "-H", "Content-Type: application/json",
                 "-d", json.dumps({"path": "/example.com"})]
        ok = False
        attempts = 0
        while time.time() < deadline:
            attempts += 1
            prc, _pout = sh(probe, timeout=15)
            if prc == 0:
                ok = True
                break
            time.sleep(3)
        elapsed = (time.perf_counter() - t0) * 1000.0
        detail = f"{attempts} 回試行" if ok else f"{attempts} 回試行して応答なし"
        self.step("サーバ起動確認（L2 応答）", ok, detail, elapsed)
        # 起動コマンド送出の記録は、L2 が応答したなら成功とみなす。
        # ssh チャネルが閉じないだけで、デーモン自体は立ち上がっているため。
        launch_ok = launch_seen or ok
        self.step(
            "サーバ起動コマンド送出",
            launch_ok,
            "" if launch_seen else ("ssh はタイムアウトしたが L2 が応答（デーモンは起動済み）"
                                    if launch_ok else f"rc={rc} " + out),
            launch_ms,
        )
        self.verdict("server_started", ok)
        if not ok:
            _rc, log = self.server_exec(f"tail -15 {qpath(self.remote_work)}/serve.log")
            print(log[:1500])
        return ok

    def _start_local_server(self) -> bool:
        args = self.args
        state_dir = self.work / "server_state"
        root_pub = self.work / "keys" / "root.pub"
        sh(["pkill", "-f", "dfs5.cli serve"], timeout=30)
        time.sleep(1)
        if args.reset:
            shutil.rmtree(state_dir, ignore_errors=True)
        log = open(self.work / "serve.log", "w")
        proc = subprocess.Popen(
            [args.local_py, "-m", "dfs5.cli", "serve", "--bind", "127.0.0.1",
             "--registry-port", str(args.l2_port), "--ost-port", str(args.l3_port),
             "--root-anchor", "/example.com", "--root-pubkey", str(root_pub),
             "--state-dir", str(state_dir)],
            cwd=str(ROOT), stdout=log, stderr=log,
        )
        self._local_server_proc = proc
        time.sleep(3)
        ok = proc.poll() is None
        self.step("ローカルサーバ起動（loopback）", ok, "" if ok else "起動失敗")
        self.verdict("server_started", ok)
        return ok

    def _probe_l2(self) -> None:
        t0 = time.perf_counter()
        rc, out = sh(["curl", "-s", "-m", "20", "-X", "POST",
                      f"{self.registry_url}/v1/resolve",
                      "-H", "Content-Type: application/json",
                      "-d", json.dumps({"path": self.sub_path})], timeout=40)
        ms = (time.perf_counter() - t0) * 1000.0
        ok = rc == 0 and '"delegation"' in out
        self.step("L2 疎通（HTTP）", ok, out[:200], ms)
        self.verdict("l2_reachable", ok)

    def _probe_l3(self) -> None:
        code = (
            "import socket, ssl, time\n"
            "ctx = ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE\n"
            "t0=time.perf_counter()\n"
            f"s=socket.create_connection(('{self.args.server_host}',{self.args.l3_port}),timeout=20)\n"
            f"w=ctx.wrap_socket(s,server_hostname='{self.args.server_host}')\n"
            "print('TLS', w.version(), round((time.perf_counter()-t0)*1000,1),'ms')\n"
            "w.close()\n"
        )
        t0 = time.perf_counter()
        rc, out, ms = self.client_exec(f"{self.client_py()} -c {shlex.quote(code)}", timeout=60)
        ok = rc == 0 and "TLS" in out
        self.step("L3 疎通（TLS）", ok, out[:200], ms)
        self.verdict("l3_reachable", ok)

    def _delegate(self) -> None:
        """ルート鍵で alice への委譲を作り、サーバの L2 に登録する。

        実行する側（loopback ならローカル、WAN ならサーバ）から見たパスを使う。
        """
        if self.args.mode == "loopback":
            sub = (f"delegate --parent /example.com --path {self.sub_path} "
                   f"--signing-key {qpath(self.work)}/keys/root "
                   f"--writer-pubkey {qpath(self.work)}/keys/alice.pub "
                   f"--epoch 1 --base-version 0 --registry {self.registry_url}")
            rc, out, ms = self.client_exec(self.client_dfs5(sub), timeout=self.args.timeout)
            ok = rc == 0 and "Registered on" in out
            self.step("L1 委譲登録", ok, (f"rc={rc} " if rc else "") + out, ms)
            self.verdict("delegation_registered", ok)
            return

        # WAN: サーバ上で署名・登録する（root 秘密鍵と alice 公開鍵はサーバに送ってある）
        sub = (f"delegate --parent /example.com --path {self.sub_path} "
               f"--signing-key {qpath(self.remote_work)}/keys/root "
               f"--writer-pubkey {qpath(self.remote_work)}/keys/alice.pub "
               f"--epoch 1 --base-version 0 --registry {self.registry_url}")
        cmd = (f"cd {qpath(self.args.remote_src_path)} && {self.args.remote_py} -m dfs5.cli {sub}")
        ok, out = self.server_exec(cmd, expect="Registered on", name="L1 委譲登録（サーバの L2）")
        self.verdict("delegation_registered", ok)

    def _client_key_path(self) -> str:
        """クライアント側から見た alice 秘密鍵のパス。"""
        if self.args.client_ssh:
            return f"{self.remote_work}/keys/alice"
        return f"{self.work}/keys/alice"

    def _init_mount(self, name: str, mount: str, node_name: str) -> None:
        sub = (f"init --mount {qpath(mount)} --name {node_name} --path {self.sub_path} "
               f"--key {self._client_key_path()} --secret {self.secret} "
               f"--registry {self.registry_url} --ost {self.ost_endpoint} --epoch 1")
        self.client_run(name, sub, expect="Initialized")

    def _generate_data(self, client_mount: str) -> None:
        args = self.args
        tree = f"{client_mount}/tree"
        if args.chunk_count > 0:
            gen = (f"mkdir -p {qpath(tree)} && "
                   f"for i in $(seq 0 {args.chunk_count - 1}); do "
                   f"printf 'chunk-%s-' $i > {qpath(tree)}/chunk$i.bin; done")
            desc = f"{args.chunk_count} 個の小ファイル"
        else:
            gen = (
                f"mkdir -p {qpath(tree)} && "
                f"for i in $(seq 0 {args.files - 1}); do "
                f"{self.client_py()} -c \"import sys;open(sys.argv[1],'wb').write((b'file-%d'%int(sys.argv[2]))*"
                f"({args.file_size}//8+1))\" {qpath(tree)}/file$i.bin $i; done"
            )
            desc = f"{args.files} × {args.file_size} B"
        rc, out, ms = self.client_exec(gen, timeout=120)
        ok = rc == 0
        self.step(f"試験データ生成（{desc}）", ok, out[:200] if not ok else desc, ms)
        self.result["environment"]["payload_desc"] = desc
        # バイト数（ssh 先なら du）
        if self.args.client_ssh:
            rc2, out2 = ssh_run(self.args.client_key, self.args.client_ssh,
                                f"du -sb {qpath(tree)} | cut -f1")
            try:
                self.result["environment"]["payload_bytes"] = int(out2.strip())
            except ValueError:
                pass
        else:
            self.result["environment"]["payload_bytes"] = sum(
                f.stat().st_size for f in Path(tree).rglob("*") if f.is_file())

    def _concurrent_conflict(self, client_mount: str, reader_mount: str) -> None:
        """同じ親版から 2 クライアントが push し、後着が ConflictError になることを見る。"""
        # reader が先に push（todo.md を追加）して勝つ
        touch = (f"printf '# concurrent from reader\\n' > {qpath(reader_mount)}/tree/todo.md && echo TOUCH_OK")
        rc, out, ms = self.client_exec(touch)
        self.step("競合試験の準備（reader 側の変更）", rc == 0, out)

        ok1, out1 = self.client_run("競合試験: 先着 push", f"push --mount {qpath(reader_mount)}",
                                    expect="[dfs5 push] OK")
        # 先着が成功して初めて、後着の拒否に意味がある
        touch2 = (f"printf '# concurrent from client\\n' > {qpath(client_mount)}/tree/todo.md && echo TOUCH2_OK")
        rc, out, ms = self.client_exec(touch2)
        self.step("競合試験の準備（client 側の変更）", rc == 0, out)

        cmd = self.client_dfs5(f"push --mount {qpath(client_mount)}")
        rc2, out2, ms2 = self.client_exec(cmd)
        rejected = rc2 != 0 and ("Conflict" in out2 or "REJECTED" in out2)
        ok = ok1 and rejected
        self.step("同時書き込みを CAS で拒否（後着）", ok,
                  f"先着={out1[:80]} / 後着 rc={rc2}: {out2[:160]}", ms2)
        self.verdict("concurrent_cas", ok)

        # 衝突コピーは作らない
        find_cmd = (f"find {qpath(client_mount)}/tree {qpath(reader_mount)}/tree "
                    f"-name '*conflict*' 2>/dev/null | head -5; echo CONFLICT_SCAN_DONE")
        rc, out, ms = self.client_exec(find_cmd)
        conflicts = [ln for ln in out.splitlines() if ln.strip() and ln.strip() != "CONFLICT_SCAN_DONE"]
        self.step("衝突コピー 0 件", len(conflicts) == 0, f"{len(conflicts)} 件")
        self.verdict("no_conflict_copies", len(conflicts) == 0)

    def _outage_test(self, client_mount: str) -> None:
        """サーバを止めて push し、ハングせず失敗が記録されることを見る。"""
        if self.args.mode == "loopback":
            self.verdict("outage_handled", None)
            return
        ok_stop, _ = self.server_exec(
            "pkill -f 'dfs5[.]cli serve'; sleep 1; "
            f"if curl -s -m 2 -o /dev/null -X POST http://127.0.0.1:{self.args.l2_port}/v1/resolve "
            "-H 'Content-Type: application/json' -d '{\"path\":\"/example.com\"}'; then "
            "echo STILL; else echo STOPPED; fi",
            expect="STOPPED", name="サーバ停止（通信断の注入）")
        if not ok_stop:
            self.verdict("outage_handled", False)
            return

        touch = f"printf 'during outage\\n' > {qpath(client_mount)}/tree/outage.md && echo OK"
        self.client_exec(touch)
        budget_ms = (self.args.outage_timeout + 30.0) * 1000.0
        t0 = time.perf_counter()
        rc, out, ms = self.client_exec(self.client_dfs5(f"push --mount {qpath(client_mount)}"),
                                       timeout=self.args.outage_timeout + 20.0)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        handled = rc != 0 and elapsed_ms < budget_ms
        self.step("通信断を失敗として返す（ハングしない）", handled,
                  f"rc={rc} elapsed={elapsed_ms:.0f}ms {out[:200]}", elapsed_ms)
        self.verdict("outage_handled", handled)

        # サーバを戻す
        if self.args.server_ssh:
            self._start_server()

    # ---------------- 終了処理 ----------------
    def _finalize(self, all_ok: bool) -> int:
        args = self.args
        # ローカルサーバを止める
        proc = getattr(self, "_local_server_proc", None)
        if proc is not None and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()

        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        out_path = ROOT / "bench" / "results" / f"{stamp}-{args.label}-wan.json"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        self.result["all_ok"] = bool(all_ok)
        out_path.write_text(json.dumps(self.result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"\n保存: {out_path}", file=sys.stderr)

        print(f"\n判定: {'ALL OK' if all_ok else 'SOME FAILED'}")
        for k, v in self.result["verdict"].items():
            print(f"  {k:26s}: {v}")
        failed = [s["step"] for s in self.result["steps"] if not s["ok"]]
        if failed:
            print(f"  失敗した手順: {', '.join(failed)}")
        return 0 if all_ok else 1


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description="dfs5 WAN 実機試験ハーネス")
    ap.add_argument("--mode", choices=["wan", "loopback"], default="wan")
    ap.add_argument("--label", default="wan", help="結果のラベル（ファイル名に使う）")
    ap.add_argument("--server-host", required=True, help="L2/L3 サーバの IP またはホスト名")
    ap.add_argument("--server-ssh", help="サーバへ ssh するときの user@host（loopback では不要）")
    ap.add_argument("--server-key", default="~/.ssh/pi-mock-test")
    ap.add_argument("--server-port", type=int, default=22)
    ap.add_argument("--l2-port", type=int, default=19440)
    ap.add_argument("--l3-port", type=int, default=19443)
    ap.add_argument("--client-ssh", help="クライアントとして ssh する先（Pi5 など）。省略時はローカル")
    ap.add_argument("--client-key", default="~/.ssh/pi-mock-test")
    ap.add_argument("--remote-src-path", default="~/src/dfs5", help="ssh 先の dfs5 リポジトリパス")
    ap.add_argument("--remote-py", default="python3")
    ap.add_argument("--local-py", default=str(Path.home() / "dfs-venv" / "bin" / "python"))
    ap.add_argument("--work", default="/tmp/dfs5_wan", help="制御側（ローカル）の作業ディレクトリ")
    ap.add_argument("--remote-work", default="~/dfs5_wan", help="ssh 先の作業ディレクトリ")
    ap.add_argument("--state-dir", default="~/dfs5_wan/server_state")
    ap.add_argument("--files", type=int, default=20)
    ap.add_argument("--file-size", type=int, default=128 * 1024)
    ap.add_argument("--chunk-count", type=int, default=0,
                    help="0 より大きいとき、往復回数の検証用小ファイルを指定数だけ作る")
    ap.add_argument("--reset", action="store_true", help="サーバ状態を消してから始める")
    ap.add_argument("--keep", action="store_true", help="作業ディレクトリを消さない")
    ap.add_argument("--timeout", type=float, default=300.0)
    ap.add_argument("--outage-timeout", type=float, default=40.0,
                    help="通信断試験で許容する最大待ち時間（秒）")
    ap.add_argument("--start-wait", type=float, default=90.0,
                    help="サーバ起動確認（L2 応答）を待つ最大秒数")
    ap.add_argument("--launch-timeout", type=float, default=25.0,
                    help="サーバ起動コマンド送出の ssh タイムアウト秒")
    return ap


def main() -> int:
    args = build_parser().parse_args()
    if args.mode == "wan" and not args.server_ssh:
        print("ERROR: --mode wan では --server-ssh が必要です", file=sys.stderr)
        return 2
    return Harness(args).run()


if __name__ == "__main__":
    raise SystemExit(main())
