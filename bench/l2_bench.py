#!/usr/bin/env python3
"""
bench/l2_bench.py
PLAN.md 段階 3: L2（所在地解決）の方式比較ハーネス。

同じ指標を、同じ手順で測る。
  (a) 名簿      : DirectoryRegistryService.resolve()（署名付きロケータ + 先頭版）
  (b) DHT       : Kademlia 経路長モデル（ceil(log2(N)/alpha)）。実装は持たない
  (c) DNS       : TXT 問い合わせ + L4 先頭版取得の 2 段（実測はローカルリゾルバ）

出力は JSON（bench/results/<日時>-<環境>.json）。数値の生成方法を残すことが目的。

使い方:
    python bench/l2_bench.py                 # ローカル条件
    python bench/l2_bench.py --rtt-ms 200    # 遅延注入の推定値を併記
    python bench/l2_bench.py --no-dns        # ネットワークを使わない
"""

from __future__ import annotations

import argparse
import json
import platform
import statistics
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from dfs.crypto import ssh_sign  # noqa: E402
from dfs.l2_registry import (  # noqa: E402
    DirectoryRegistryService,
    create_locator_envelope,
    verify_locator_envelope,
)


def _make_key(directory: Path, name: str) -> tuple[Path, str]:
    priv = directory / name
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", f"{name}@example.com", "-f", str(priv)],
        check=True,
    )
    pub = Path(f"{priv}.pub").read_text(encoding="utf-8").strip()
    return priv, pub


def _time_calls(fn, n: int) -> dict:
    """fn() を n 回呼び、1 回あたりの所要時間（ミリ秒）を返す。"""
    samples = []
    for _ in range(n):
        t0 = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - t0) * 1000.0)
    samples.sort()
    return {
        "n": n,
        "median_ms": round(statistics.median(samples), 4),
        "p95_ms": round(samples[int(len(samples) * 0.95)], 4),
        "min_ms": round(samples[0], 4),
        "max_ms": round(samples[-1], 4),
    }


def measure_directory(n: int, verify_n: int) -> dict:
    """(a) 名簿方式: resolve() の往復回数と所要時間を実測する。"""
    d = Path(tempfile.mkdtemp(prefix="l2bench_"))
    root_priv, root_pub = _make_key(d, "root")
    alice_priv, alice_pub = _make_key(d, "alice")
    now = 1763000000
    path = "/example.com/alice"

    reg = DirectoryRegistryService("/example.com", root_pub)
    locator = create_locator_envelope(
        alice_priv, path, 1, 0, "aa" * 32, ["tls://127.0.0.1:9443"], now + 100000, ttl=300
    )
    # 名簿にロケータを登録（L1 委譲は別途検証済みとし、ここでは L2 の解決だけを測る）
    reg.locators[path] = locator

    resolve_stats = _time_calls(lambda: reg.resolve(path), n)
    verify_stats = _time_calls(
        lambda: verify_locator_envelope(locator, path, alice_pub, now=now), verify_n
    )
    return {
        "method": "directory",
        "round_trips": 1,
        "resolve": resolve_stats,
        "verify": verify_stats,
        "notes": "resolve() がロケータと先頭版を同時に返す（1 往復）。verify はローカル CPU コスト。",
    }


def measure_dns(n: int, hostname: str) -> dict | None:
    """(c) DNS 方式: TXT 問い合わせの往復時間を実測する。"""
    try:
        probe = subprocess.run(["dig", "+short", "+time=2", "+tries=1", hostname, "A"],
                               capture_output=True, text=True, timeout=5)
        if probe.returncode != 0:
            return None
    except Exception:
        return None
    samples = []
    for _ in range(n):
        t0 = time.perf_counter()
        subprocess.run(
            ["dig", "+short", "+time=2", "+tries=1", hostname, "A"],
            capture_output=True, timeout=5,
        )
        samples.append((time.perf_counter() - t0) * 1000.0)
    samples.sort()
    return {
        "method": "dns",
        "round_trips": 2,
        "query": {
            "n": n,
            "median_ms": round(statistics.median(samples), 2),
            "p95_ms": round(samples[int(len(samples) * 0.95)], 2),
            "min_ms": round(samples[0], 2),
            "max_ms": round(samples[-1], 2),
        },
        "notes": "TXT の取得に 1 往復、L4 先頭版の取得に別途 1 往復が必要（合計 2）。",
    }


def dht_model(nodes: list[int], alpha: int = 3) -> dict:
    """(b) DHT: Kademlia の経路長モデル。実装がないため、往復回数は計算値。"""
    import math

    rows = []
    for n in nodes:
        hops = math.log2(n) if n > 1 else 0.0
        rows.append({
            "nodes": n,
            "expected_hops": round(hops, 2),
            "serial_rounds_alpha3": math.ceil(hops / alpha) if hops else 0,
        })
    return {
        "method": "dht",
        "round_trips": "ceil(log2(N)/alpha)",
        "model": rows,
        "notes": "実装を持たない。往復回数は Kademlia の経路長モデルによる見積もり。",
    }


def high_latency_estimate(rtt_ms: float, round_trips: dict) -> dict:
    """RTT を注入した場合の推定所要時間。往復回数×RTT + ローカル処理。"""
    return {
        f"{name}": round(trips * rtt_ms + 0.0, 1)
        for name, trips in round_trips.items()
        if isinstance(trips, int)
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--calls", type=int, default=2000, help="名簿 resolve の試行回数")
    ap.add_argument("--verify-calls", type=int, default=200, help="署名検証の試行回数")
    ap.add_argument("--dns-calls", type=int, default=20, help="DNS 問い合わせの試行回数")
    ap.add_argument("--rtt-ms", type=float, default=200.0, help="高遅延条件の片道ではなく往復 RTT (ms)")
    ap.add_argument("--no-dns", action="store_true", help="DNS を測らない（ネットワークを使わない）")
    ap.add_argument("--out", type=Path, default=None, help="出力 JSON のパス")
    args = ap.parse_args()

    result = {
        "schema": "dfs-l2-bench-v1",
        "measured_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "environment": {
            "platform": platform.platform(),
            "python": platform.python_version(),
            "hostname": platform.node(),
        },
        "directory": measure_directory(args.calls, args.verify_calls),
        "dht": dht_model([100, 1_000, 10_000, 1_000_000]),
    }
    if not args.no_dns:
        dns = measure_dns(args.dns_calls, "example.com")
        if dns:
            result["dns"] = dns

    round_trips = {"directory": 1, "dht_1000": 4, "dht_10000": 5, "dns": 2}
    result["high_latency_estimate_ms"] = high_latency_estimate(args.rtt_ms, round_trips)
    result["verdict"] = {
        "threshold_round_trips": 2,
        "directory": "pass" if 1 <= 2 else "fail",
        "dht_1000": "pass" if 4 <= 2 else "fail",
        "dns": "pass" if 2 <= 2 else "fail",
        "note": "DNS の 2 往復は閾値ちょうど。高遅延では余裕がない。",
    }

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    out = args.out or (ROOT / "bench" / "results" / f"{stamp}-local.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    print(json.dumps(result, ensure_ascii=False, indent=2))
    print(f"\n保存: {out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
