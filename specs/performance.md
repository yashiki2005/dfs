# Performance Benchmarks (2026-11-12)

> **English** | [日本語](performance.ja.md)

## Environment

| Item | Value |
|---|---|
| Machine | workstation (Apple A18 Pro) |
| OS | macOS 27.3 arm64 |
| Python | 3.12.16 (`~/dfs-venv`) |
| Measurement | local / loopback |

Raw data is stored in `bench/results/20261112-current-*.json`.
WAN numbers use the existing `specs/e2e_wan.md` (2026-11-11).

## L2 / L3

| Item | Result |
|---|---:|
| L2 `resolve` (in-process dict lookup) | median **0.0006 ms** |
| Ed25519 SSHSIG verification (optimized) | median **0.043 ms** / p95 0.045 ms |
| DNS query | median **13.05 ms** |
| L3 100 × 64KiB | **29.56 ms** / 1 round trip / ~**222 MB/s** |
| L3 100 × 4KiB | 9.14 ms / 1 round trip |
| Ciphertext body for 2 identical-content files | 8,757 B (1 file worth) |
| Adding an alias for existing content | 697 B |

`resolve` is a dict lookup inside the registry service and does not include an HTTP round trip.
In a real network, L2 HTTP, signature verification, and L3 TLS costs are added.

## CLI

Results of push / read / pull of 20 files × 128KiB (2.62MB) against a local server.

| Operation | Before optimization | After optimization |
|---|---:|---:|
| Initial copy (whole command) | 59.2 ms | **52.5 ms** |
| Initial copy (inside push) | 35.3 ms | **24.5 ms** |
| Unchanged copy | 48.1 ms | **16.9 ms** |
| Normal 128KiB read | 20.0 ms | **7.3 ms** |
| Cache read after all registries down | 19.8 ms | **9.5 ms** |
| `list_remote` after all registries down | 18.5 ms | **6.3 ms** |
| Pull after all registries down (2.62MB) | 37.8 ms | **37.9 ms** |

Initial copy throughput is about **50 MB/s**, and inside push is about **107 MB/s**.
Pull is dominated by L3 transfer, so optimizing signature verification barely changes it.

Note that when stopping a local registry, connection refused is returned immediately.
In an actual network outage, it may wait up to `DFS_L2_TIMEOUT` (default 10s) per registry.

## DNSSEC

Results of running `discover_domain("example.com")` 20 times in the same process.

| Item | Before optimization | With zone key cache |
|---|---:|---:|
| Median | 187.5 ms | **12.7 ms** |
| p95 | 1,022 ms | **497 ms** |
| Min | 52.4 ms | **8.9 ms** |
| Max | 1,022 ms | **497 ms** |

The first run takes about 0.5 s to fetch DNSKEY and DS records for root / TLD / domain.
From the second run onward, verified zone keys are reused within their TTL, bringing the median to ~13ms.

Because the CLI only runs discovery once per process, this speedup targets repeated in-process
use (servers, tests, future monitoring). Speeding up initial CLI startup as well would require
a persistent cache of verified zone keys.

## zstd level 10

Measured `zstandard` level 10 on 16MiB of data.

| Data | Ratio | Compress time | Compress speed | Decompress time |
|---|---:|---:|---:|---:|
| Text-like | 1.22% | 57.1 ms | 280 MiB/s | 2.5 ms |
| Random | 100% | 4.7 ms | 3,381 MiB/s | 0.7 ms |

While compressible data can greatly reduce transfer volume, random data stays at a 1.0 ratio
and only consumes CPU. Because zstd:10 adds non-negligible cost compared to the local L3 hot path
(tens of ms), compression is not enabled by default and must be explicitly specified based on
data type or transport path.

Measurement results: `bench/results/20261112-zstd10-local.json`.

## Persistent Writer Index

After pushing 20 × 128KiB (2.62MB), only 1 file was modified and pushed again from a separate process.

| Run | Bytes sent |
|---|---:|
| Initial push | 2,628,420 B |
| Push after modifying 1 file | **5,731 B** |

The index is stored in `.clayfs/ost_index.json`. If the content-addressing key derived from
`tree_secret` changes, `address_key` will not match and the old index is invalidated.

Measurement results: `bench/results/20261112-ost-index-local.json`.

## WAN (Existing Measurements)

20 × 128KB (2.13MB) from `specs/e2e_wan.md`:

| Path | RTT | push | pull |
|---|---:|---:|---:|
| Mac → Scaleway | 275.8 ms | 4.30 s | 4.01 s |
| Sakura → Scaleway | 275.1 ms | 3.70 s | 3.64 s |
| Mac → Sakura | 22.1 ms | 0.91 s | 0.53 s |

WAN is dominated by RTT and transfer volume; optimizing L2 signature verification does not reduce
the number of round trips.

### 3 Sites (Re-measured 2026-11-12)

Across 3 nodes — Mac (primary) / Sakura / Scaleway — 20 × 128KiB (2.62MB) was pushed,
and primary and Sakura were stopped in sequence to switch the read target.

| Operation | Elapsed | Content match |
|---|---:|---|
| copy to primary (including replication to 2 secondaries) | **9.98 s** | — |
| pull from primary (`--force`) | **2.12 s** | Match |
| pull from Sakura after stopping primary (`--force`) | **0.82 s** | Match |
| pull from Scaleway after stopping Sakura (`--force`) | **4.15 s** | Match |

Because push writes to the local OST and then also sends to the Sakura / Scaleway replica OSTs,
it waits serially for two WAN transfers. Reads fail over to the remaining replica OSTs,
and contents matched across all 3 sites.

## How to Re-measure

```bash
python bench/l2_bench.py --dns-calls 50 --calls 5000 --verify-calls 500
python bench/l3_bench.py
python bench/e2e_wan.py --mode loopback --server-host 127.0.0.1
```

Do not run `e2e_wan.py` in a shared environment, as it runs `pkill` on existing dfs servers.
