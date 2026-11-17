#!/usr/bin/env python3
"""
bench/compare_results.py
ベンチマーク結果の比較・レグレッション検出。

使い方:
  python bench/compare_results.py
  python bench/compare_results.py --baseline bench/results/baseline.json --current bench/results/latest.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def load_results(path: Path) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def extract_step_metrics(data: dict) -> dict[str, float]:
    """steps から step名 -> elapsed_ms のマッピングを抽出"""
    metrics = {}
    if "steps" not in data:
        return metrics
    for step in data["steps"]:
        if step.get("ok") and "elapsed_ms" in step:
            metrics[step["step"]] = step["elapsed_ms"]
    return metrics


def extract_dfs_metrics(data: dict) -> dict[str, dict]:
    """dfs metrics から direction/version ごとのメトリクスを抽出"""
    metrics = {}
    if "metrics" not in data:
        return metrics
    for m in data["metrics"]:
        if "direction" in m and "version" in m:
            key = f"{m['direction']}_v{m['version']}"
            metrics[key] = m
    return metrics


def compare(baseline: dict, current: dict, threshold_pct: float = 50.0) -> list[str]:
    """2 つの結果を比較し、閾値以上の劣化があれば警告リストを返す"""
    warnings = []

    # steps 比較
    base_steps = extract_step_metrics(baseline)
    curr_steps = extract_step_metrics(current)

    all_steps = set(base_steps.keys()) | set(curr_steps.keys())
    for step in sorted(all_steps):
        if step in base_steps and step in curr_steps:
            base_ms = base_steps[step]
            curr_ms = curr_steps[step]
            if base_ms > 0:
                pct = (curr_ms - base_ms) / base_ms * 100
                if pct > threshold_pct:
                    warnings.append(f"[REGRESSION] {step}: {base_ms:.1f}ms -> {curr_ms:.1f}ms ({pct:+.1f}%)")
                elif pct < -threshold_pct:
                    warnings.append(f"[IMPROVEMENT] {step}: {base_ms:.1f}ms -> {curr_ms:.1f}ms ({pct:+.1f}%)")
                else:
                    print(f"  {step}: {base_ms:.1f}ms -> {curr_ms:.1f}ms ({pct:+.1f}%)")
        elif step in curr_steps:
            print(f"  {step}: NEW ({curr_steps[step]:.1f}ms)")
        elif step in base_steps:
            print(f"  {step}: REMOVED ({base_steps[step]:.1f}ms)")

    # dfs metrics 比較
    base_metrics = extract_dfs_metrics(baseline)
    curr_metrics = extract_dfs_metrics(current)

    all_keys = set(base_metrics.keys()) | set(curr_metrics.keys())
    for key in sorted(all_keys):
        if key in base_metrics and key in curr_metrics:
            base = base_metrics[key]
            curr = curr_metrics[key]
            for metric in ("elapsed_ms", "round_trips", "bytes_sent", "bytes_received", "blob_bytes_sent"):
                if metric in base and metric in curr:
                    base_val = base[metric]
                    curr_val = curr[metric]
                    if base_val > 0:
                        pct = (curr_val - base_val) / base_val * 100
                        if abs(pct) > threshold_pct:
                            label = "REGRESSION" if pct > 0 else "IMPROVEMENT"
                            warnings.append(f"[{label}] {key}.{metric}: {base_val} -> {curr_val} ({pct:+.1f}%)")

    return warnings


def main() -> int:
    ap = argparse.ArgumentParser(description="Compare benchmark results")
    ap.add_argument("--baseline", help="Baseline result JSON file")
    ap.add_argument("--current", help="Current result JSON file")
    ap.add_argument("--threshold", type=float, default=50.0, help="Regression threshold percentage")
    ap.add_argument("--list", action="store_true", help="List available results in bench/results/")
    args = ap.parse_args()

    results_dir = Path(__file__).parent / "results"

    if args.list:
        files = sorted(results_dir.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
        for f in files:
            try:
                data = load_results(f)
                print(f"{f.name}: mode={data.get('mode', '?')} label={data.get('label', '?')} all_ok={data.get('all_ok', '?')}")
            except Exception as e:
                print(f"{f.name}: ERROR - {e}")
        return 0

    if not args.baseline or not args.current:
        print("ERROR: --baseline and --current are required", file=sys.stderr)
        return 2

    baseline_path = Path(args.baseline)
    current_path = Path(args.current)

    if not baseline_path.exists():
        print(f"ERROR: Baseline not found: {baseline_path}", file=sys.stderr)
        return 1
    if not current_path.exists():
        print(f"ERROR: Current not found: {current_path}", file=sys.stderr)
        return 1

    baseline = load_results(baseline_path)
    current = load_results(current_path)

    print(f"Comparing:")
    print(f"  Baseline: {baseline_path.name} (mode={baseline.get('mode')}, label={baseline.get('label')})")
    print(f"  Current:  {current_path.name} (mode={current.get('mode')}, label={current.get('label')})")
    print()

    warnings = compare(baseline, current, args.threshold)

    print()
    if warnings:
        print("⚠️  REGRESSION DETECTED:")
        for w in warnings:
            print(f"  {w}")
        return 1
    else:
        print("✅ No significant regressions detected")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
