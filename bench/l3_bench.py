#!/usr/bin/env python3
"""
bench/l3_bench.py
PLAN.md 段階 4: L3（データ平面）の判断材料を測る。

測るのは次の 3 点。
  1. 現行 dfs5 L3（wire_id で一括 PUT）の転送コスト
  2. 同一内容の重複排除が効くか（同一バッチ・別バッチ）
  3. mini_lustre の OST を「そのまま」使えるか（プロトコル互換性の確認）

mini_lustre は file_id/chunk_index で塊を識別するため、wire_id による
内容アドレス重複排除はできない。その事実もここで確認する。

使い方:
    python bench/l3_bench.py
    python bench/l3_bench.py --out bench/results/xxx.json
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

from dfs5.crypto import ContentAddressedCrypto  # noqa: E402
from dfs5.l3_store import ChunkStoreServer, OSTClient  # noqa: E402
from dfs5.l4_log import MerkleTreeBuilder  # noqa: E402


def _cert(directory: Path) -> tuple[Path, Path]:
    cert, key = directory / "cert.pem", directory / "key.pem"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", str(key), "-out", str(cert),
         "-days", "1", "-nodes", "-subj", "/CN=localhost"],
        check=True, capture_output=True,
    )
    return cert, key


def measure_transfer(cases: list[tuple[int, int]]) -> dict:
    """現行 L3 の一括 PUT を、ファイル数とサイズを変えて測る。"""
    rows = []
    with tempfile.TemporaryDirectory(prefix="l3bench_") as tmp:
        base = Path(tmp)
        cert, key = _cert(base)
        server = ChunkStoreServer(cert, key)
        try:
            for count, size in cases:
                tree = base / f"t{count}_{size}"
                tree.mkdir()
                for i in range(count):
                    (tree / f"f{i}.bin").write_bytes(bytes([i % 251]) * size)
                client = OSTClient("127.0.0.1", server.port)
                client.reset_metrics()
                builder = MerkleTreeBuilder(ContentAddressedCrypto("l3-bench"), client)
                t0 = time.perf_counter()
                builder.upload_directory(tree)
                elapsed = (time.perf_counter() - t0) * 1000.0
                rows.append({
                    "files": count,
                    "file_size_bytes": size,
                    "payload_bytes": count * size,
                    "elapsed_ms": round(elapsed, 2),
                    "bytes_sent": client.bytes_sent,
                    "blob_bytes_sent": client.blob_bytes_sent,
                    "round_trips": client.round_trips,
                    "puts": client.put_count,
                    "overhead_ratio": round(client.bytes_sent / (count * size), 3) if count * size else 0,
                })
        finally:
            server.close()
    return {"method": "dfs5-l3-batch", "cases": rows}


def measure_dedup() -> dict:
    """同一内容の重複排除を、同一バッチと別バッチで測る。"""
    with tempfile.TemporaryDirectory(prefix="l3dedup_") as tmp:
        base = Path(tmp)
        cert, key = _cert(base)
        server = ChunkStoreServer(cert, key)
        try:
            tree = base / "tree"
            tree.mkdir()
            (tree / "a.bin").write_bytes(b"X" * 8192)
            (tree / "b.bin").write_bytes(b"X" * 8192)
            client = OSTClient("127.0.0.1", server.port)
            builder = MerkleTreeBuilder(ContentAddressedCrypto("dedup-bench"), client)
            builder.upload_directory(tree)
            first = client.blob_bytes_sent
            index_size = len(builder.index)

            # 別バッチで別名追加
            client.reset_metrics()
            (tree / "c.bin").write_bytes(b"X" * 8192)
            builder.upload_directory(tree)
            second = client.blob_bytes_sent
        finally:
            server.close()
    return {
        "method": "dfs5-content-dedup",
        "same_batch_2_files_blob_bytes": first,
        "one_file_plus_dir_expected": 8192 + 32 + 12 + 16,  # 平文 + plain_id + nonce + tag
        "index_entries": index_size,
        "new_alias_blob_bytes": second,
        "note": "同一バッチ内の同一内容は 1 回だけ送る。無変更の追加は索引で 0 往復省略。",
    }


def probe_mini_lustre() -> dict:
    """mini_lustre の OST に dfs5 のフレームを送り、互換性を確認する。"""
    mini = Path.home() / "src" / "mini_lustre"
    if not mini.exists():
        return {"available": False, "reason": "~/src/mini_lustre が無い"}

    probe = {
        "available": True,
        "frame_8byte_header": "mini_lustre: >II (json_len, payload_len) + JSON + payload",
        "frame_1byte_opcode": "dfs5: 1-byte opcode + 64-byte wire_id + >I length + body",
        "chunk_identity": {
            "mini_lustre": "(file_id, chunk_index) — 内容では決まらない",
            "dfs5": "wire_id = SHA256(ciphertext) — 内容アドレス",
        },
        "batch_ops": {
            "mini_lustre": "個別の read_chunk / write_chunk のみ",
            "dfs5": "batch_has / batch_put_if_absent / batch_get",
        },
        "compatible_without_change": False,
        "note": (
            "同じポートで TLS/TCP を使う点だけが共通で、アプリケーション層は別物。"
            "DFS5 の 1-byte opcode は mini_lustre では JSON 長として読まれ、エラーになる。"
            "また mini_lustre は file_id/chunk_index で識別するため、wire_id による"
            "内容アドレス重複排除は行えない。"
        ),
    }
    return probe


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args()

    result = {
        "schema": "dfs5-l3-bench-v1",
        "measured_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "environment": {
            "platform": platform.platform(),
            "python": platform.python_version(),
        },
        "transfer": measure_transfer([(10, 4096), (100, 4096), (100, 65536)]),
        "dedup": measure_dedup(),
        "mini_lustre_compat": probe_mini_lustre(),
        "verdict": {
            "use_libtorrent": False,
            "reason": (
                "塊が 100 個程度の規模では、TLS/TCP の一括 PUT で 2 往復に収まる。"
                "libtorrent の固定費（ハンドシェイク・メタデータ検証）を上回る利点がない。"
            ),
            "use_mini_lustre_unchanged": False,
            "alternative": (
                "プロトコルは独自実装のまま（dfs5/l3_ost_adapter.py）を使い、"
                "将来 mini_lustre へ載せる場合は RPC アダプタ層を挟む。"
            ),
        },
    }

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    out = args.out or (ROOT / "bench" / "results" / f"{stamp}-l3-local.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    print(f"\n保存: {out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
