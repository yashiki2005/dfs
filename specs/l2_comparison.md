# L2 Location Resolution Comparison and Specification (`specs/l2_comparison.md`)

> **English** | [日本語](l2_comparison.ja.md)

## 0. Purpose and Scope

This document records the comparison results and specification for Phase 3 of `dfs` (L2: Location Resolution — from name to address).
It answers Question 3 of `DESIGN.md` §10: "Where should locators be placed?"

The conclusion first:

> **The initial implementation uses (a) the Registry approach.** Even under high latency, it fits within 2 round trips and can return both the locator and head version in 1 round trip. DHT path lengths grow with node count and exceed 3 round trips under high latency, so it is not adopted for the initial implementation. DNS can reuse existing infrastructure, but is subject to censorship and TTL constraints.

---

## 1. Common Data Format: Signed Locator

Regardless of which backend (Registry / DHT / DNS) implements L2, the exchanged data structure is standardized as a pair of a single canonical JSON payload and an OpenSSH Ed25519 detached signature.
Implemented in `create_locator_envelope` / `verify_locator_envelope` in `dfs/l2_registry.py`.

### 1.1 Payload (Signed Data)

A single-line UTF-8 JSON object with keys sorted lexicographically and no extra whitespace (`dfs.crypto.canonical_json()`, trailing 1-byte LF).

```json
{"delegation_epoch":1,"endpoints":["tls://198.51.100.50:9443"],"expires_at":1763086400,"head_hash":"b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9","head_version":2,"path":"/example.com/alice","ttl":300}
```

| Field | Meaning |
|---|---|
| `path` | Target subtree. Must be `normalize_path`-normalized. |
| `endpoints` | Candidate data locations (`tls://host:port`), ordered by priority. |
| `head_version` / `head_hash` | L4 head version at this point. Including the head version in the resolution result decouples the 1-RT L2 lookup from L4 verification. |
| `delegation_epoch` | L1 epoch. Used to reject locators from stale epochs. |
| `expires_at` / `ttl` | Signed expiration time and recommended cache TTL. `ttl` does not exceed `expires_at`. |

**Important distinction**: `ttl` is a caching hint, whereas **the signed `expires_at` is authoritative**.
Even if a cached entry is within its `ttl`, a locator past `expires_at` is rejected.

### 1.2 Envelope

```json
{"payload":{...上記...},"signature":"-----BEGIN SSH SIGNATURE-----\n...\n-----END SSH SIGNATURE-----\n"}
```

The signature namespace is `dfs-l2-locator-v1`. Always include the namespace so it cannot be confused with L1 (`dfs-delegation-v1`) or L4 signatures.

---

## 2. Comparison of the 3 Approaches

### 2.1 Measurement Conditions

| Item | Details |
|---|---|
| Harness | `bench/l2_bench.py` (measures the same metrics with the same procedure) |
| Raw data | `bench/results/20261111-195032-local.json` |
| Environment | macOS-27.3-arm64, Python 3.12 |
| Registry | `DirectoryRegistryService.resolve()` 2,000 times, in-process |
| Signature verification | `verify_locator_envelope` 100 times (including `ssh-keygen -Y verify` process spawns) |
| DNS | `dig +short +time=2 +tries=1 example.com A` 10 times via local resolver |
| DHT | No implementation; estimated via Kademlia path-length model `ceil(log2(N)/alpha)` (`alpha=3`) |

**These numbers are reference values under local conditions.** LAN hardware and 200ms RTT conditions are treated as estimates in §2.4; if actual measurements are needed, re-run the same harness in that environment.

### 2.2 Round Trips (Protocol Hops)

| Approach | Round trips for resolution | Head version fetch | Total |
|---|---|---|---|
| **(a) Registry** | 1 (`resolve` returns locator and head version together) | Same | **1** |
| **(b) DHT** | `ceil(log2(N)/alpha)` (α=3) | Typically 1 | **4–7** |
| **(c) DNS** | 1 (TXT query) | **Separate 1** (from L4) | **2** |

DHT estimates (`dht.model` in `bench/results/20261111-195032-local.json`):

| Node count | Expected hops | Serial steps (α=3) |
|---|---|---|
| 100 | 6.64 | 3 |
| 1,000 | 9.97 | 4 |
| 10,000 | 13.29 | 5 |
| 1,000,000 | 19.93 | 7 |

### 2.3 Local Measurements

| Approach | Measured value | Notes |
|---|---|---|
| Registry `resolve` | Median **0.0005 ms** (p95 0.0005) | In-process dict lookup. Excludes network round trips |
| Locator signature verification | Median **7.35 ms** (p95 9.13) | Includes `ssh-keygen -Y verify` process spawn |
| DNS query | Median **13.62 ms** (p95 15.91) | Local resolver, cache hit |

The 7ms for signature verification is **local CPU cost, not a resolution round trip**.
With 1 locator per response it happens once, but becomes dominant as the count grows.

### 2.4 High-Latency Estimate (RTT 200ms)

`high_latency_estimate_ms` in `bench/results/20261111-195032-local.json` is a simple `round_trips * RTT` calculation. Local CPU cost for signature verification is added separately.

| Approach | Round trips | Estimated time | Verdict |
|---|---|---|---|
| **(a) Registry** | 1 | **200 ms** + 7ms verify | **Pass** (within 2 round trips) |
| **(b) DHT (1,000 nodes)** | 4 | **800 ms** | **Fail** (caching mandatory) |
| **(b) DHT (10,000 nodes)** | 5 | **1,000 ms** | **Fail** |
| **(c) DNS** | 2 | **400 ms** | Right on the threshold; no margin under high latency |

DNS takes 2 round trips because fetching TXT and fetching the L4 head version are separate.
Embedding the head version in the DNS record itself could make it 1 round trip, but would require rewriting DNS on every update, and stale versions would be visible during the TTL.

### 2.5 Behavior Under Failure

| Approach | 1 node down | Central node down |
|---|---|---|
| (a) Registry | **Total outage** (single point of failure) | Total outage |
| (b) DHT | Continues (if replicated) | Limited impact |
| (c) DNS | Depends on resolver | Depends on domain authority |

**This is the weakness of (a).** If the registry goes down, resolution fails. Even in `PLAN.md` Phase 5 evaluation, this is treated as "if availability is needed, follow up; if not, fail cleanly (as designed)."

**Current status (2026-11-12)**: Multi-registry fallback in L2 and signed bundle replication from primary to replica registries are implemented. Furthermore, primary OST chunks are copied to read-only replica OSTs, and locators carry multiple endpoints. Even if either the primary registry or primary OST goes down, reads can continue as long as an alternate registry and replica OST are alive. Writes remain single-writer, handled by the primary registry and primary OST.

- Implemented registry-untrusted verification (verifying delegation chains against the root anchor). Even if a registry returns a forged delegation, it is rejected (`specs/delegation.md` §3.5).
- This is a prerequisite for "running multiple registries and reading from any of them." Because any registry's answer can be verified with the root public key, selecting any registry is safe.

**Implemented A (Read availability)**: Configure multiple registries in the remote definition and try `resolve` / `paths` / `ost` in order. Writes (`announce`) are sent to a single "primary" and fail if the primary is down (promotion is handled in B). The primary pushes signed delegation chains, logs, and locators to replica registries.
See `TODO.md` and `tests/test_availability.py` for details.

## 3. Chosen Approach and Path for Adding DHT Later

### 3.1 Chosen: Registry Approach

- Resolution is 1 round trip. Returns locator and head version together (`resolve` returns a 3-tuple).
- Responses are signed and can be verified without trusting the registry itself.
- Resolution fails if the registry goes down, which is acceptable for initial private clusters.

### 3.2 Boundary for Adding DHT Later

As decided in `PLAN.md`, **separate endpoint resolution from head version retrieval**:

```text
resolve(path) -> { locator_envelope, head_log_envelope }
```

- `locator_envelope` holds only "which endpoints hold the data."
- `head_log_envelope` holds "the L4 head version retrieved from that endpoint."
- While a registry returns both in 1 round trip, DHT requires 2 steps: fetch only the locator from the DHT, then query the endpoint directly for the head version.
- Therefore, the implementation **keeps the return types separated from the start**, so a 1-RT implementation can be swapped for a 2-RT implementation without special-casing.

### 3.3 Read Cache (Implemented)

To continue reads even if all registries go down, verified responses are saved in the remote's `.clayfs/l2_cache.json`.

- Storage unit: `path -> (delegation, locator, head_log)`
- Only responses whose delegation chain, head signature, and locator signature were verified by L4 are stored
- Used as a fallback only when all registries are unreachable
- On read, the locator's `expires_at` and delegation expiration are still checked
- Versions older than `local_head.json` are rejected as B6 even when read from cache

Updates occur when an online `resolve` succeeds or when post-push B7 verification succeeds.
Repeatedly resolving unchanged paths only updates the cache and does not add L2 round trips.

---

## 4. Implementation Status and Remaining Work

| Item | Status |
|---|---|
| Signed locator format | Implemented (`l2_registry.py`) |
| Registry `resolve` (1 round trip) | Implemented |
| Head version CAS (`announce_and_append`) | Implemented |
| DHT implementation | **Not implemented** (deemed unnecessary for initial release) |
| DNS approach | **Not implemented** (not adopted due to censorship and TTL) |
| Cache | Implemented (`.clayfs/l2_cache.json`, read fallback when all registries are down) |
| Benchmark harness | Implemented (`bench/l2_bench.py`) |
| Raw data | `bench/results/20261111-195032-local.json` |

**Remaining work (by priority)**:

1. **Read availability (A, L2 / OST implemented)**: Run multiple registries and replicate OSTs. Since all nodes hold the same root public key, any answer can be verified.
2. **Write replication and promotion (B)**: Replicate primary-to-secondary and promote secondary if primary fails. "Which is primary" is statically configured; manual secondary promotion and fencing via `role_epoch` are implemented. Automatic election, quorum, and leases are not yet implemented.
3. **Consensus (C, deferred for now)**: Single-writer means only one writer writes at a time. B is usually sufficient and C tends to be overkill.
4. **Fallback to DNS/DHT**: For large-scale deployments (see `TODO.md` policy).
