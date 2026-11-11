#!/usr/bin/env python3
"""
bench/e2e_lan.py
PLAN.md 段階 5: Mac と Pi5 の実機で 1 つのツリーを共有する。

前提:
  - Pi5 で `dfs5 serve` が動いている（L2: HTTP 9440 / L3: TLS 9443）
  - 両端末で同じ委譲・同じ tree_secret を使う
  - ssh で Pi5 に鍵を置ける

このスクリプトは Mac 側から操作し、Pi5 側は ssh 経由で dfs5 CLI を呼ぶ。
数値と結果を JSON で残す（環境・RTT・各版の所要時間）。

使い方:
    python bench/e2e_lan.py --pi5 yy@192.168.0.7 --key ~/.ssh/pi-mock-test
"""

from __future__ import annotations

import argparse
import json
import platform
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def sh(cmd: list[str], timeout: float = 120.0) -> tuple[int, str]:
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return p.returncode, (p.stdout + p.stderr).strip()


def ssh(ssh_key: str, target: str, command: str, timeout: float = 120.0) -> tuple[int, str]:
    return sh(["ssh", "-i", str(Path(ssh_key).expanduser()), "-o", "BatchMode=yes", target, command], timeout)


def rtt_ms(host: str, count: int = 10) -> float | None:
    rc, out = sh(["ping", "-c", str(count), host], timeout=30)
    m = re.search(r"min/avg/max/stddev = [\d.]+/([\d.]+)/", out)
    return float(m.group(1)) if m else None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pi5", default="yy@192.168.0.7")
    ap.add_argument("--pi5-host", default="192.168.0.7")
    ap.add_argument("--key", default="~/.ssh/pi-mock-test")
    ap.add_argument("--work", default="/tmp/dfs5_e2e")
    ap.add_argument("--py", default=str(Path.home() / "dfs-venv" / "bin" / "python"))
    ap.add_argument("--remote-py", default="python3")
    args = ap.parse_args()

    work = Path(args.work)
    remote_work = "~/dfs5_e2e"
    result: dict = {
        "schema": "dfs5-e2e-lan-v1",
        "measured_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "environment": {
            "mac_platform": platform.platform(),
            "pi5_target": args.pi5,
            "rtt_avg_ms": rtt_ms(args.pi5_host),
        },
        "steps": [],
    }

    def step(name: str, ok: bool, detail: str = "", ms: float | None = None) -> None:
        row = {"step": name, "ok": ok, "detail": detail[:400]}
        if ms is not None:
            row["elapsed_ms"] = round(ms, 1)
        result["steps"].append(row)
        print(f"{'OK  ' if ok else 'NG  '} {name}" + (f" ({ms:.1f} ms)" if ms else "") + (f"  {detail[:80]}" if detail else ""))

    # 1. L2/L3 への疎通
    t0 = time.perf_counter()
    rc, out = sh(["curl", "-s", "-m", "5", "-X", "POST",
                  f"http://{args.pi5_host}:9440/v1/resolve",
                  "-H", "Content-Type: application/json",
                  "-d", '{"path":"/example.com/alice/notes"}'], timeout=20)
    step("L2 疎通（HTTP）", rc == 0 and '"delegation"' in out, out[:120], (time.perf_counter() - t0) * 1000)

    t0 = time.perf_counter()
    code = (
        "import socket,ssl\n"
        "c=ssl.create_default_context();c.check_hostname=False;c.verify_mode=ssl.CERT_NONE\n"
        f"s=socket.create_connection(('{args.pi5_host}',9443),timeout=8)\n"
        "w=c.wrap_socket(s,server_hostname='" + args.pi5_host + "')\n"
        "print('TLS',w.version());w.close()\n"
    )
    rc, out = sh([args.py, "-c", code], timeout=30)
    step("L3 疎通（TLS）", rc == 0 and "TLS" in out, out[:120], (time.perf_counter() - t0) * 1000)

    # 2. 各版の push / pull
    mac_mount = work / "mac_mount"
    t0 = time.perf_counter()
    rc, out = sh([args.py, "-m", "dfs5.cli", "push", "--mount", str(mac_mount)], timeout=120)
    step("Mac push", rc == 0 and "[dfs5 push] OK" in out, out, (time.perf_counter() - t0) * 1000)

    t0 = time.perf_counter()
    rc, out = ssh(args.key, args.pi5,
                  f"cd ~/src/dfs5 && {args.remote_py} -m dfs5.cli pull --mount {remote_work}/pi5_mount")
    step("Pi5 pull", rc == 0 and "[dfs5 pull] OK" in out, out, (time.perf_counter() - t0) * 1000)

    # 3. 内容の一致（SHA-256）
    rc, out = sh(["sh", "-c", "cd " + str(mac_mount) + "/tree && find . -type f -exec shasum -a 256 {} \\; | sort"])
    mac_digest = out
    rc2, out2 = ssh(args.key, args.pi5,
                    f"cd {remote_work}/pi5_mount/tree && find . -type f -exec sha256sum {{}} \\; | sort")
    step("内容一致（SHA-256）", mac_digest == out2 and mac_digest != "", f"mac={len(mac_digest.splitlines())} files")

    # 4. 同時書き込みの排他
    (mac_mount / "tree" / "todo.md").write_text("# concurrent from mac\n", encoding="utf-8")
    rc, out = sh([args.py, "-m", "dfs5.cli", "push", "--mount", str(mac_mount)], timeout=120)
    mac_won = rc == 0

    rc2, out2 = ssh(args.key, args.pi5,
                    f"cd ~/src/dfs5 && printf '# concurrent from pi5\\n' > {remote_work}/pi5_mount/tree/todo.md && "
                    f"{args.remote_py} -m dfs5.cli push --mount {remote_work}/pi5_mount")
    rejected = rc2 != 0 and "Conflict" in out2
    step("同時書き込みを CAS で拒否", mac_won and rejected, out2, )

    # 5. 衝突コピーが無いこと
    rc, out = ssh(args.key, args.pi5, f"find {remote_work}/pi5_mount/tree -name '*conflict*' | head -5")
    step("衝突コピー 0 件", out.strip() == "", out)

    result["verdict"] = {
        "single_writer_cas": mac_won and rejected,
        "three_way_merge_avoided": out.strip() == "",
        "lan_sync_ok": all(s["ok"] for s in result["steps"][:5]),
    }

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    out_path = ROOT / "bench" / "results" / f"{stamp}-e2e-lan.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"\n保存: {out_path}", file=sys.stderr)
    return 0 if all(s["ok"] for s in result["steps"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
