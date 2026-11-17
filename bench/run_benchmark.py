#!/usr/bin/env python3
"""
bench/run_benchmark.py
ローカル/ CI でベンチマークを実行し、結果を可視化するユーティリティ。

使い方:
  python bench/run_benchmark.py --mode loopback --label test
  python bench/run_benchmark.py --mode wan --server-host 192.0.2.60 --server-ssh deploy@192.0.2.60
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


def run_command(cmd: list[str], timeout: float = 300.0) -> tuple[int, str, float]:
    t0 = time.perf_counter()
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        return 124, str(e), (time.perf_counter() - t0)
    return p.returncode, (p.stdout + p.stderr).strip(), (time.perf_counter() - t0)


def main() -> int:
    ap = argparse.ArgumentParser(description="dfs Benchmark runner")
    ap.add_argument("--mode", choices=["loopback", "lan", "wan"], default="loopback")
    ap.add_argument("--label", default=f"bench-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}")
    ap.add_argument("--work", default="/tmp/dfs_bench")
    ap.add_argument("--files", type=int, default=20)
    ap.add_argument("--file-size", type=int, default=131072)
    ap.add_argument("--chunk-count", type=int, default=0)
    ap.add_argument("--wan-server-host", help="WAN サーバのホスト/IP")
    ap.add_argument("--wan-server-ssh", help="WAN サーバへの ssh (user@host)")
    ap.add_argument("--wan-server-key", default="~/.ssh/id_ed25519")
    ap.add_argument("--wan-client-ssh", help="WAN クライアント側の ssh (user@host)")
    ap.add_argument("--wan-client-key", default="~/.ssh/id_ed25519")
    ap.add_argument("--l2-port", type=int, default=19440)
    ap.add_argument("--l3-port", type=int, default=19443)
    ap.add_argument("--local-py", default="python3")
    ap.add_argument("--remote-py", default="python3")
    ap.add_argument("--reset", action="store_true")
    ap.add_argument("--keep", action="store_true")
    args = ap.parse_args()

    work = Path(args.work)
    work.mkdir(parents=True, exist_ok=True)

    # テスト用鍵を生成
    keys_dir = work / "keys"
    keys_dir.mkdir(parents=True, exist_ok=True)
    for name in ("root", "alice"):
        key = keys_dir / name
        if not key.exists():
            rc, out, _ = run_command([
                "ssh-keygen", "-t", "ed25519", "-N", "", "-C", f"bench-{name}@example.com", "-f", str(key)
            ])
            if rc != 0:
                print(f"鍵生成失敗: {out}", file=sys.stderr)
                return 1

    results_dir = Path(__file__).parent / "results"
    results_dir.mkdir(parents=True, exist_ok=True)

    if args.mode == "lan":
        # LAN ベンチマークは ssh 先が必要なのでスキップ（CI 用）
        print("LAN benchmark requires remote host. Skipping.")
        return 0

    elif args.mode == "loopback":
        cmd = [
            sys.executable, "-m", "bench.e2e_lan",
            "--work", str(work),
            "--py", args.local_py,
            "--key", str(keys_dir / "alice"),
        ]
        rc, out, elapsed = run_command(cmd, timeout=600)
        print(out)
        if rc != 0:
            return rc
        # 結果を保存
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        out_path = results_dir / f"{args.label}-{stamp}-loopback.json"
        # 簡易的に実行結果を JSON で保存
        data = {
            "label": args.label,
            "mode": "loopback",
            "elapsed_sec": elapsed,
            "success": rc == 0,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        out_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        print(f"Result saved: {out_path}")
        return 0

    elif args.mode == "wan":
        if not args.wan_server_host or not args.wan_server_ssh:
            print("ERROR: --wan-server-host and --wan-server-ssh required for WAN mode", file=sys.stderr)
            return 2

        cmd = [
            sys.executable, "-m", "bench.e2e_wan",
            "--mode", "wan",
            "--label", args.label,
            "--server-host", args.wan_server_host,
            "--server-ssh", args.wan_server_ssh,
            "--server-key", args.wan_server_key,
            "--l2-port", str(args.l2_port),
            "--l3-port", str(args.l3_port),
            "--work", str(work),
            "--local-py", args.local_py,
            "--remote-py", args.remote_py,
            "--files", str(args.files),
            "--file-size", str(args.file_size),
            "--chunk-count", str(args.chunk_count),
            "--reset",
        ]
        if args.wan_client_ssh:
            cmd += ["--client-ssh", args.wan_client_ssh, "--client-key", args.wan_client_key]

        rc, out, elapsed = run_command(cmd, timeout=1200)
        print(out)
        if rc != 0:
            return rc

        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        out_path = results_dir / f"{args.label}-{stamp}-wan.json"
        data = {
            "label": args.label,
            "mode": "wan",
            "elapsed_sec": elapsed,
            "success": rc == 0,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        out_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        print(f"Result saved: {out_path}")
        return 0

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
