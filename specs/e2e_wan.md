# WAN Hardware Tests (Scaleway / Sakura) and Latency Tolerance (`specs/e2e_wan.md`)

> **English** | [日本語](e2e_wan.ja.md)

## 0. Purpose and Scope

Verify on real hardware whether `dfs`, which worked over LAN (RTT 2ms), also works over WAN (RTT 20–285ms), and how well it tolerates WAN latency and round-trip counts.

- Harness: `bench/e2e_wan.py`
- Raw data:
  - `bench/results/20261111-205551-mac-to-scaleway-wan.json`
  - `bench/results/20261111-205831-sakura-to-scaleway-wan.json`
  - `bench/results/20261111-205952-mac-to-sakura-wan.json`
- Execution date: 2026-11-11
- Connection: 3 sites over WireGuard (Mac / Scaleway / Sakura)

---

## 1. Setup

```text
[Mac]                [Sakura (192.0.2.254)]                 [Scaleway (192.0.2.60)]
clayfs (L5)          dfs serve （比較用サーバ）              dfs serve
  └ tree/ ──push──▶  L3 ChunkStore (TLS 19443) ─┐             L3 ChunkStore (TLS 19443)
  .clayfs/                                       │             L2 名簿 (HTTP 19440)
       ▲──pull──── L4 追記ログ ◀── L2 名簿 ───────┴─────────────┘
```

| Site | Connection | RTT (measured avg) | Environment |
|---|---|---|---|
| Mac | Origin | — | macOS arm64, Python 3.12 |
| Scaleway | `deploy@192.0.2.60` | **278.5ms** | x86_64, 1vCPU/950MB |
| Sakura | `deploy@example.com` (192.0.2.254) | **22.4ms** | x86_64, 2core/960MB |

| Item | Value |
|---|---|
| L2 | `http://<host>:19440` (Symbolic Registry, HTTP) |
| L3 | `tls://<host>:19443` (TLS 1.3) |
| State directory | `~/dfs_wan/server_state` on each site |
| Existing service on host | Separate ports from Scaleway's `dfs4` assets. **Not stopped** |
| Shared across 3 sites | Shared `tree_secret` and delegation key (single-writer test) |

---

## 2. Pre-Test Fixes (WAN Support)

The previous code failed over WAN for two reasons: "hardcoded timeouts" and "round-trip count proportional to chunk count."

### 2.1 Environment Variables for Timeouts

| Location | Old | New (default) | Env Var |
|---|---|---|---|
| L2 HTTP | Fixed 5.0 s | 10 s | `DFS_L2_TIMEOUT` |
| L3 server socket | Fixed 2.0 s | 30 s | `DFS_OST_SOCKET_TIMEOUT` |
| L3 client connect | Fixed 3.0 s | 10 s | `DFS_OST_CONNECT_TIMEOUT` |

Invalid or negative values revert to the default (never wait indefinitely).

### 2.2 Reducing Round Trips (push Side)

`MerkleTreeBuilder._stage` previously **called `batch_has` per chunk**.
This was changed to accumulate index hits and issue **a single batched HAS at the end**.
Uploads also use `batch_put_if_absent(..., assume_absent=True)` to PUT in 1 round trip.

As a result, pushes within client limits (1,024 items / 64 MiB) take **1 HAS round trip + 1 PUT round trip**. Larger batches are split at the limits.

| Scenario | Old | New |
|---|---|---|
| push (20 chunks) | Proportional to chunk count (~20+ round trips) | **1 round trip** |

### 2.3 Reducing Round Trips (pull Side / Batching)

`download_directory` previously **called `get` per chunk** (`batch_get` with 1 chunk each).
This was changed to a two-stage batched fetch:

- **Directory chunks**: Traverse breadth-first, batching **1 level into 1 `batch_get`**.
- **File chunks**: Fetch at the end in batches per store and per limit via `batch_get`.
  Because the size upper bound is known upfront from `size` in the manifest, responses never grow too large.

Thus, round trips depend only on "depth + batch count," not "file count."

| Structure | Old | New |
|---|---|---|
| Flat directory (20 / 100 / 500 files) | 21 / 101 / 501 round trips | **2 round trips** (1 root + 1 files) |
| 3 nested levels + 53 files | 56 round trips | **4 round trips** |

Batches can be tuned with `DFS_BATCH_CHUNKS` (default 1024) and `DFS_BATCH_BYTES` (default 16 MiB).
Identical chunks are fetched only once (deduplication also applies on read).

---

## 3. Results

### 3.1 Comparison Across 3 Sites (20 × 128KB = 2.13MB)

Measurements after introducing batching (§2.2 push, §2.3 pull).

| Path | RTT | push RTs | push time | pull RTs | pull time | Content match | CAS | Conflict copies | Disconnect |
|---|---|---|---|---|---|---|---|---|---|
| Mac → Scaleway | 275.8ms | **1** | 4,299ms | **2** | 4,010ms | Match | Rejected | 0 | Fail-fast |
| Sakura → Scaleway | 275.1ms | **1** | 3,699ms | **2** | 3,644ms | Match | Rejected | 0 | Fail-fast |
| Mac → Sakura | 22.1ms | **1** | 910ms | **2** | 534ms | Match | Rejected | 0 | Fail-fast |

- All `ALL OK`. All `verdict` fields in `bench/results/*-batch-wan.json` are `true`.
- **push round trips are fixed at 1**, independent of RTT and chunk count.
- **pull round trips are fixed at 2**, independent of file count (1 root + 1 files).
- pull time was cut in half on every link (8,025 → 4,010ms, 7,692 → 3,644ms, 953 → 534ms).
  The remaining time is mainly the raw transfer time of 2.1MB, not round-trip count.

#### 3.1.1 Before vs. After Batching

| Path | push RTs | push time | pull RTs | pull time |
|---|---|---|---|---|
| Mac → Scaleway | 1 → 1 | 4,391 → 4,299ms | **21 → 2** | **8,025 → 4,010ms** |
| Sakura → Scaleway | 1 → 1 | 3,937 → 3,699ms | **23 → 2** | **7,692 → 3,644ms** |
| Mac → Sakura | 1 → 1 | 923 → 910ms | **21 → 2** | **953 → 534ms** |

push was already fixed at 1 round trip so it did not change. pull round trips dropped by more than 10x, cutting elapsed time in half. What remains is the product of transfer volume (2.1MB) and RTT; round-trip count is no longer dominant.

### 3.2 Round-Trip Breakdown

```text
push : [HAS 1] + [PUT 1]                                  = 1 (both new and unchanged)
pull : [Root GET 1] + [Files GET 1]                       = 2 (flat directory)
       Nested: "1 level = 1 round trip" + 1 for files     = depth + 1
```

`round_trips` is `OSTClient.round_trips` (L3 only) output via the CLI `--metrics` flag.
L2 round trips are not included.

### 3.3 Fault Tolerance (Network Outage)

Pushed while the server process was stopped.

| Path | Behavior | Elapsed | Exception |
|---|---|---|---|
| Mac → Scaleway | Fail-fast (no hang) | 399ms | `ServiceUnavailableError` |
| Sakura → Scaleway | Fail-fast | 938ms | `ServiceUnavailableError` |
| Mac → Sakura | Fail-fast | 138ms | `ServiceUnavailableError` |

Connection failures, read timeouts, and TLS failures are normalized into `ServiceUnavailableError`.
Callers can decide on retries the same way as for "server down."

### 3.4 Single-Writer Mutual Exclusion

On all 3 paths, a later push from the same parent version failed with `ConflictError`, and 0 conflict copies were created. The same behavior as LAN (`specs/e2e_lan.md`) holds over WAN.

---

## 4. What Was Verified

- **dfs works over WAN.** push/pull completed across 3 sites up to 285ms RTT.
- **push round trips are constant.** Finishes in 1 round trip regardless of chunk count or RTT.
- **Single-writer semantics hold under high latency.** Later arrivals are rejected and no 3-way merge occurs.
- **Does not hang on disconnect.** All failures return explicit exceptions.
- **Testable without stopping existing services.** Coexisted with `dfs4` assets on separate ports.

---

## 5. Unmeasured Items / Remaining Work

| Item | Status |
|---|---|
| pull round-trip reduction (batching) | **Done**. 2 round trips for flat structures, `depth + 1` for nested |
| 100+ chunk pull benchmark (WAN) | Not run (this test used 20 files; locally verified 2 round trips for 500 files) |
| Effective throughput | Not measured (only rough estimates from duration and byte count) |
| Artificial high-latency injection (`tc qdisc`) | Not run. Used Scaleway's actual ~285ms as the WAN condition |
| 3+ concurrent participants | Not run (only 1 server + 1–2 clients) |
| Long-running / continuous push/pull degradation | Not run |
| WireGuard path stability | Mac→Scaleway WG briefly dropped during testing (did not recur after recovery). Path availability itself is out of scope |

---

## 6. Reproduction

```bash
# Server side (e.g. Scaleway)
cd ~/src/dfs
nohup python3 -m dfs.cli serve --bind 0.0.0.0   --registry-port 19440 --ost-port 19443   --root-anchor /example.com --root-pubkey ~/dfs_wan/keys/root.pub   --state-dir ~/dfs_wan/server_state   > ~/dfs_wan/serve.log 2>&1 < /dev/null &

# Mac → Scaleway (harness handles deployment, delegation, and measurement)
python bench/e2e_wan.py --mode wan --label mac-to-scaleway \
  --server-host 192.0.2.60 --server-ssh deploy@192.0.2.60 \
  --server-key ~/.ssh/pi-mock-test --reset

# Sakura → Scaleway (runs client over ssh)
python bench/e2e_wan.py --mode wan --label sakura-to-scaleway \
  --server-host 192.0.2.60 --server-ssh deploy@192.0.2.60 \
  --server-key ~/.ssh/pi-mock-test \
  --client-ssh deploy@example.com --client-key ~/.ssh/id_ed25519_sakura --reset

# Self-check of the harness itself (contained within Mac)
python bench/e2e_wan.py --mode loopback --label selfcheck --server-host 127.0.0.1
```

- Test data totals under 20MB (accounting for 1.6GB free space on Scaleway).
- `--reset` deletes **only server state and mounts**. Keys are preserved.
- No artificial latency injection; Scaleway's actual ~285ms is used as the WAN condition.

---

## 7. Harness Design Notes

Key differences from `e2e_lan.py`:

- `--server-host` / `--server-ssh` / `--client-ssh` switch between sites.
- `--mode loopback` runs a self-check contained within Mac (for verifying nothing is broken in CI).
- Records round trips and bytes sent/received for each push/pull in JSON (parses CLI `--metrics`).
- Failures are recorded as `{"ok": false, "detail": ...}` instead of raising exceptions.
- Separates startup and health checks. Because ssh channels over WAN can fail to close and time out, startup commands are kept short and the controller polls L2 responses to determine success.
