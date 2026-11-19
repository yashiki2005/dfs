# dfs Resumption Status Notes (`TODO.md`)

> **English** | [日本語](TODO.ja.md)

This document records the state of work when paused **as of 2026-11-12**. When
resuming, read this first to grasp what is already working and what to do next.

- Repository: `~/src/dfs` (symlink to `/Volumes/ExtSSD/src/dfs`)
- Baseline commit: `1562f01 feat: add fuse-t mount support`
- Tests: **160 passed, 1 skipped** (`~/dfs-venv/bin/python -m pytest tests -q`)
- Working tree: uncommitted changes present (checksum format, folder compression, B3 chunks)

---

## 1. Current State (What Works)

### 1.1 Layer Implementation

| Layer | Status | Implementation |
|---|---|---|
| L1 Delegation | Implemented & verified | `l1_delegation.py` (5 invariants, chain verification) |
| L2 Registry | Implemented | `l2_registry.py` (signed locators, CAS append, chain restoration to root) |
| L3 Data Plane | Implemented & WAN-measured | `l3_ost_adapter.py` (TLS/TCP, batch_has / put / get) |
| L4 Consistency | Implemented & evil-tested | `l4_log.py` (append-only log, Merkle chunks, HeadPin, B6/B7 defenses) |
| L5 Materialization | Implemented | `l5_clayfs.py` (snapshot integration via `dfs.fs`) |
| L5 CoW Abstraction | Implemented | `dfs/fs/` (uses CoW when available, falls back to real copy) |

### 1.2 Two CLIs

| Command | Role | Implementation |
|---|---|---|
| `./dfscli` | Local CLI (`rclone`-like). `ls` / `cat` / `copy` / `sync` / `pull` / `rm` / `mkdir`, etc. | `dfs/cli_main.py` |
| `./dfssvc` | Spin up local servers (2 free ports + delegation automated) | `dfs/svc.py` |
| `python -m dfs.cli` | Raw server-side operations (`serve` / `delegate` / `push` / `pull`) | `dfs/cli.py` |

**Note**: The previous names were `dfsr` / `rclone_cli.py`. Any `./dfsr` references in
notes or runbooks prior to `122afcf` should be read as `./dfscli`.

### 1.3 Capabilities (Verified on Real Machines)

- Spin up a local server and push / pull files (Mac)
- Sync over LAN (Mac ↔ Pi5) and WAN (3 sites: Mac / Sakura / Scaleway)
- Reject concurrent pushes from the same parent version via CAS (0 conflict copies)
- Raise `ServiceUnavailableError` on network disconnection instead of hanging

### 1.4 Speed (Measured)

| Scenario | Round-trips | Reference |
|---|---|---|
| push | **1 round-trip** (independent of chunk count) | `specs/e2e_wan.md`, `specs/l3_data_plane.md` |
| pull (flat structure) | **2 round-trips** (root 1 + files 1) | Same as above. 2 round-trips locally even for 500 files |
| pull (nested) | depth + 1 | Same as above |

Over WAN (RTT 285ms, 20 × 128KB), push took 4.3s / pull took 4.0s. Before batch
operations were introduced, pull took 8.0s (21 round-trips).

In local re-measurements on 2026-11-12, an initial 2.62MB copy took 52.5ms, an
unchanged copy took 16.9ms, and a 128KiB read took 7.3ms. Speedups came from
in-process Ed25519 verification and DNSSEC zone key caching. See `specs/performance.md`
for details.

In the 3-site (Mac / Sakura / Scaleway) 2.62MB test, push with 2 replicas took
9.98s, secondary pull after primary shutdown took 0.82s, and Scaleway pull after
Sakura shutdown took 4.15s, with identical contents across all paths.

---

## 2. Next Steps (In Priority Order)

### 2.1 Implemented: A (L2 Read Availability)

On 2026-11-12, L2 registry read fallback and primary → replica replication were implemented.

- `Remote.registry_alternates` can hold alternate registries
- Reads try primary → alternates in order; writes go only to primary
- `dfs serve --replica` / `dfssvc start --replica` replicates signed bundles from primary
- Replicas re-verify the root anchor, delegation chain, L4 signature, and CAS, refusing rollback via stale bundles
- Regression test: `tests/test_availability.py`

**OST Replication**: Added support for copying chunks from the primary OST to a
read-only replica OST and storing multiple endpoints in locators. Even if the
primary OST goes down, `pull` / `cat` can continue as long as a replica OST is alive.
Spooling is not used; writes complete on the primary OST. See `specs/ost-replica.md`.

**Why**: If the L2 registry goes down, **everything stops** (single point of failure).
`specs/l2_comparison.md` §2.5. `ls` / `cat` / `pull` all halt simply because the
registry is unreachable.

**Prerequisites are ready**: `122afcf` implemented "untrusted registry verification".
Even if a registry returns a forged delegation, it is rejected (chain verified from
the root anchor). Thus, **running multiple registries is safe regardless of which
registry answers**.

**Tasks**:

1. Allow holding multiple registries in remote definitions. Idea: make `registry`
   an array, or have `registry` + `registry_alternates`.
2. Try `resolve` / `paths` / `ost` **in order and use the first readable response**.
   All responses are verified with the root public key, so any registry's answer is fine.
3. Send writes (`announce`) to a single "primary". Fail if the primary is down (promotion is B).
4. Test: run 2 registries, stop one, and verify `ls` / `cat` / `pull` continue.
   Running two `dfssvc` instances on different ports lets you test on one machine (see §4 below).

**Design Notes**:

- **Never fetch and trust the root public key from the registry** (`specs/delegation.md` §3.5.1).
  Fetch it via TOFU only on first use, and thereafter use the local record (`root_pubkey` in `remotes.json`).
- When selecting a registry, there is no need to compare "which one is right" because signatures verify it.

### 2.2 B (Write Replication and Promotion)

Implemented primary/secondary roles, role epochs, write rejection on secondary,
and manual promotion. Stop the old primary first, promote the secondary state, and
update the writer's `role_epoch`. See `specs/promotion.md`.

No automatic election, quorum, or lease is implemented. Making both nodes primary
without stopping the old primary causes split-brain, so add leases / consensus if
robust automatic promotion is required. C (consensus) will not be done for now.

### 2.3 CLI Additions (Usability)

On 2026-11-12, the following CLI features were implemented.

| Command | Description | Status |
|---|---|---|
| `mv` | Move/rename within the same remote in 1 version. Rejects existing destinations; `--overwrite` allowed for files only | Implemented |
| `--exclude` / `--include` | Relative path filters for `copy` / `sync` / `pull`. `sync --delete` does not delete filtered-out paths | Implemented |
| `lsd` | List only immediate subdirectories | Implemented |
| `import_tar` | Safely import `.tar` / `.tar.gz` / `.tar.xz` / `.tar.bz2` in 1 version | Implemented |
| `mount` | Mount a remote locally via fuse-t / fusepy | Implemented |
| `--checksum` | Change detection via `size` / `crc32` / `sha1` / `plain_id` | Implemented |
| Folder compression | `user.dfs.compression` xattr and `DFSB3` codec header | Implemented |

The writer's content-addressed index is persisted to `.clayfs/ost_index.json`. If
`tree_secret` changes, `address_key` no longer matches, so old index entries are
automatically invalidated.

`mv` treats the destination as the exact new name (no automatic placement into an
existing directory or merging). See `specs/cli.md` §3.2.1–3.2.2.

### 2.4 Packaging (For Distribution)

Added `pyproject.toml` so it can be distributed via pip / pipx.

- Console scripts: `dfscli = dfs.cli_main:main`, `dfssvc = dfs.svc:main`
- Required dependencies: `cryptography` / `dnspython`
- Optional extra: `libp2p`
- Built a wheel via `pip install --no-deps --target ... .` and verified both entrypoints launch
- Root-level shell wrappers remain as compatibility entrypoints for development

The current Mac OST is placed under `/Volumes/ExtSSD/dfs/ost/`, and `ost_chunks`
in each state dir is a symlink to it. New services can specify `dfssvc start --ost-dir ...`,
and direct launches can use `dfs serve --ost-dir ...`.

### 2.5 Root Anchor Distribution (For Large-Scale Operations)

Implemented fetching the root public key and registry list from DNSSEC
`_dfs.<domain>` TXT records. Used via `dfscli discover <domain>` and
`config create --dnssec-domain <domain>`.

DNSSEC is strictly limited to **distributing the root key and initial registry list**,
and is not used for L4 head or primary promotion decisions. Primary / secondary
roles are determined by DNSSEC records or static configuration; "first server to
start becomes root" is not used.

See `specs/dnssec.md`. The client verifies the DNSKEY/DS chain from the root trust
anchor and checks the TXT RRSIG. The AD bit is only used in the legacy fallback path
with `validate=False`.

### 2.5.1 BitTorrent archive (MVP Implemented)

Implemented `archive create` to save the current head version as signed metadata +
all chunks + `.torrent`. BitTorrent is not on the hot path; it is for long-term
archival of past versions and last-resort recovery. `archive verify` and
`archive extract` are also available.

Added L2 publication of signed archive descriptors, propagation to replica
registries, and `archive fetch`. `fetch` retrieves data via external `aria2c` /
`transmission-cli` DHT/trackers, and after retrieval re-verifies the descriptor's
L4 binding, bundle signature, and chunk hashes. It works with standard `--registry`
configuration alone; DNSSEC is not required.

See `specs/bittorrent.md`. SHA-1 in v1 torrents is for transport; chunk authenticity
is verified with DFS SHA-256. BitTorrent v2, L4 integration of archive descriptors,
and erasure coding are not yet implemented.

### 2.5.2 libp2p/QUIC chunk source (Experimental)

Implemented libp2p as an additional `ChunkSource` for OST. The initial TCP prototype
failed to run custom streams across separate processes, but `enable_quic=True` with
`/ip4/.../udp/.../quic-v1` was confirmed to work.

`dfscli libp2p-serve` serves a chunk directory over QUIC, and clients add it as a
read candidate with `--libp2p-peer`. Writes continue to go to the traditional primary
OST. See `specs/libp2p.md`.

### 2.6 Items Needing More Verification

| Item | Status | How |
|---|---|---|
| 3+ nodes participating simultaneously | Automated tests and 3 real sites (Mac / Sakura / Scaleway) done | Run multiple on 1 machine (§4); Docker if insufficient |
| Long-running / continuous push/pull degradation | Not tested | — |
| WAN measurement with 100+ chunks | Not tested | 20 files only; 500 verified locally |
| Effective throughput | Not measured | Only rough estimates from duration and byte counts |
| Artificial high-latency injection (`tc qdisc`) | Not tested | Used Scaleway's actual 285ms instead |
| 2 OSTs over LAN (striping) | Not tested | Local verification only (`TestL3Striping`) |
| Re-measurement with 1,000+ chunks | Not tested | — |
| pytest on Pi5 | Not tested | Mac only |

### 2.7 Unimplemented (When Needed)

| Item | Status |
|---|---|
| RPC adapter for mini_lustre | Not implemented. mini_lustre itself is a prototype, so consider replacing it if needed |
| Node discovery via DHT | Not implemented. Post-discovery exclusion design is documented in `specs/delegation.md` §3.5.5 |
| Registry cache | Implemented (`.clayfs/l2_cache.json`, read fallback when all registries are down) |
| Retrieving past versions (rollback) | Implemented. `/v1/history` / `/v1/resolve?version` / `dfscli history` / `archive create --version` |

### 2.8 2026-11-16 Code Review Findings

Baseline commit is `d0700d1`. All existing tests pass in `.venv/bin/pytest -q`
with **319 passed, 10 skipped** (Python 3.13 / macOS).
The items below include issues not caught by dynamic tests.

#### High Priority

- [ ] **Stream or bound cumulative size of libp2p responses instead of buffering all in memory**
  - Target: `Libp2pChunkServer._handle_stream()` and `Libp2pHostManager._handle_stream()` in `dfs/libp2p_chunk.py`.
  - Current state: `G` responses join up to 65,536 chunks with `b"".join(parts)` into a single `bytes` object.
    Each chunk has a 256MiB cap, and total response size is not checked before sending.
  - Aggravating factor: All peers are allowed when no allowlist is configured, and `libp2p-serve` defaults to no allowlist / PSK.
  - Fix: Cap the total response to `MAX_FRAME_BYTES` or less. Stream large responses.
    Add read timeouts. Require an allowlist or PSK by default on public binds.
  - Regression test: Large `G` requests are rejected before constructing the response, unauthorized peers are rejected,
    and closing mid-response does not exceed the memory cap.

- [ ] **Enforce size limits on HTTP responses read from untrusted L2 registries**
  - Target: `RemoteRegistryClient._post_one()` in `dfs/cli.py`.
  - Current state: `read()` is unbounded for both normal and error responses.
    The server enforces an 8MiB limit, but the client does not.
  - Impact: Under the threat model where L2 is compromised or down, a huge response can OOM the client.
  - Fix: Check `Content-Length` and stream-read the body up to `MAX_REGISTRY_BODY_BYTES + 1` bytes.
    Fix other paths using unbounded `read()`, such as `discovery.fetch_candidacy()`.
  - Regression test: Return oversized normal and error responses from a local HTTP server and verify
    they are rejected as `RegistryError` or `ServiceUnavailableError`.

#### Medium Priority

- [ ] **Replicate all chunks from their correct source OST when multi-OST striping is enabled**
  - Target: `MerkleTreeBuilder._replicate_chunks()` in `dfs/l4_log.py`.
  - Current state: All `wire_id`s are fetched from the default OST's `self.ost.batch_get()`.
    Chunks present only on other OSTs are silently omitted from the result without warning.
  - Reproduction: Distributing 3 chunks across 2 OSTs produced
    `ost1=2`, `ost2=1`, `replica=2`, `missing_on_replica=1`, `warnings=`.
  - Fix: Retain the `wire_id -> store_id` mapping from the current version and call `batch_get()` per source OST.
    Emit a warning or raise an error if fetched results do not satisfy all requested IDs.
  - Regression test: Enable 2-OST striping and replica OST together, and verify all primary OST chunks exist on the replica.

- [ ] **Fix `NameError` in `dfscli listremotes --no-check`**
  - Target: `cmd_listremotes()` in `dfs/commands/remote.py`.
  - Current state: Calls `re.fullmatch()` for 16-character share-ID subtree names, but `re` is not imported.
  - Reproduction: `[dfscli] 予期しないエラー: NameError: name 're' is not defined`.
  - Fix: Add `import re`.
  - Regression test: Register a path like `/example.com/AbCdEfGhIjKlMnOp` and verify `listremotes --no-check` exits cleanly.

- [ ] **Limit web server connections, read timeouts, and upload memory**
  - Target: `make_web_handler()` / `start_web_server()` in `dfs/web.py`.
  - Current state: Uses an unbounded `ThreadingHTTPServer` with no socket timeout for reading headers or bodies.
    Upload bodies up to 256MiB are read into memory at once.
  - Impact: With `--bind 0.0.0.0`, slowloris, excessive concurrent connections, or parallel large uploads can exhaust the process.
  - Fix: Use a connection-limited HTTP server and set a read timeout in `setup()`.
    Stream uploads to temporary files and limit concurrent uploads.
  - Regression test: 503 on connection limit exceeded, timeout on stalled partial headers,
    and max-size uploads not buffering the entire payload in memory.

- [ ] **Enforce extraction limits on tar/archive unpacking**
  - Target: `_extract_tar_safely()` in `dfs/cli_main.py`.
  - Current state: Rejects path traversal, symlinks, hardlinks, and special files,
    but has no limits on total extracted size, entry count, single-file size, or compression ratio.
  - Impact: Importing an untrusted tar can exhaust disk space or time.
  - Fix: Enforce max entry count, max total extracted bytes, max single-file size, and max compression ratio.
    Check available disk space before extracting.
  - Regression test: Create tars with many small files, a single huge file, or a high compression ratio,
    and verify they are rejected before extracting to the destination.

#### Low Priority / Maintainability

- [ ] **Standardize secret-bearing config writes on `write_private_json()`**
  - Target: `RemoteStore.save()` in `dfs/remotes.py` and similar places.
  - Current state: Writes JSON containing `tree_secret` to a predictable `*.tmp` file before calling `chmod 0600`.
    On crash or replacement race, secrets may remain or be written to another file.
  - Fix: Use existing `dfs/private_io.py` to standardize on `mkstemp`, `0600`, `fsync`, and `os.replace`.
  - Regression test: After creating or updating config, file mode is `0600` and temp files do not use predictable names.

- [ ] **Pin and verify packages and downloaders installed by bootstrap**
  - Target: `scripts/bootstrap.sh` and `scripts/bootstrap_ro.sh`.
  - Current state: `uv tool install --force dfs` does not pin version or hash.
    When `uv` is missing, it executes `curl ... | sh` directly.
  - Fix: Pin the release version and verify the distribution SHA256. Add signature verification if needed.
  - Regression test: Installation proceeds only when the pinned version and hash match; tampered artifacts are rejected.

- [ ] **Add static analysis and type checking to CI and clean up existing diagnostics**
  - Current state: Even Ruff's `F` rules report many unused imports and undefined names.
    `Callable` / `Set` in `dfs/cli.py` and `Any` in `dfs/svc.py` do not fail at runtime only because of `from __future__ import annotations`.
  - Fix: Add minimal Ruff rules and mypy or pyright to CI.
    First pass `F401`, `F821`, `F811`, `F841`, then gradually enable more rules.
  - Acceptance criteria: All existing pytest cases and static analysis pass in CI.

---

## 3. Key Design Points (Useful When Resuming)

### 3.1 Do Not Trust the Registry

The root of trust is **a single root anchor public key**. `resolve` returns the leaf
delegation together with the **full chain** and `root_anchor`, and the client
verifies from root using `verify_delegation_chain`. Only the **"verified writer"**
is used to verify signatures (never the writer claimed by the registry).

```
Registry returns attacker's key as root public key → mismatches local record → rejected
```

Details in `specs/delegation.md` §3.5. Tests in `tests/test_root_anchor.py` (7 cases).

**Limitation**: Before TOFU (when root is unset), an attacker can spoof the first
response (same as SSH `known_hosts`). In production, pin from the start with
`--root-pubkey`. This "passes before TOFU" behavior is also kept in tests.

### 3.2 Empty Directories Persist in Versions

Directory chunks are represented as `{"entries": [], "format": "dfs-dir-v1"}`, and
readers materialize them accordingly. Deleting files with `rm` leaves the directory,
and `pull` downloads empty directories as well. To clean them up, use `rm --rmdirs`
or `sync --delete`. See `specs/cli.md` §3.4.

### 3.3 Pin Source Port

The WireGuard spoke (Scaleway) has `ListenPort` pinned. With an ephemeral port,
the source port changes and the hub (Sakura) temporarily loses connectivity because
it learns from the last received port. Hub keepalive is also configured symmetrically
(`specs/e2e_wan.md`).

### 3.4 Pitfalls Encountered

| Symptom | Cause | Fix |
|---|---|---|
| `ls` says "touch first" | Read commands called with `create=False` | Create working dir for read commands too |
| `create` says "no delegation" | `dfssvc start` did not register delegation | Included it in `start` |
| Missed occupied ports | `bind` with `SO_REUSEADDR` bypassed `0.0.0.0:N` | Two-step check that also tries connecting |
| Multi-hop delegation failed on clock skew | Intermediate and leaf had the same validity | Made intermediate 1 day longer |
| Orphaned server on delegation failure | `start` did not stop on exception | Always stop on failure |
| Servers left running after tests | `addCleanup` ordering | Stop all recorded servers in `tearDown` |

---

## 4. How to Test (Multiple Nodes on One Machine)

You can simulate "multiple sites" on one machine by running multiple `dfssvc` instances
on different ports.

```bash
cd ~/src/dfs

# Start 2 registries (for testing A; different ports will be used)
./dfssvc start --name node-a --port 20000
./dfssvc start --name node-b --port 20010
./dfssvc list

# Stop them
./dfssvc stop node-a --forget
./dfssvc stop node-b --forget
```

- `--port` is the starting port to search for two consecutive free ports: 1st for L2, 2nd for L3.
- Each name gets its own state directory (`~/dfssvc/<name>/`) and keys.
- `--advertise` overrides the advertised host (defaults to inferring from `--host`).
- To test network partitions or latency, use Docker (`docker network create` +
  `tc netem` in each container); different ports alone cannot simulate those.

Server-side timeouts can be configured via environment variables (`DFS_L2_TIMEOUT`,
`DFS_OST_SOCKET_TIMEOUT`, `DFS_OST_CONNECT_TIMEOUT`). Both `dfscli` and `dfssvc`
read `os.environ` directly.

---

## 5. Current Environment (2026-11-12)

### 5.1 Local (Mac)

| Item | Status |
|---|---|
| launchd server | `com.example.dfs-local` (L2 19440 / L3 19443, `~/dfs-local/`) **running** |
| `dfssvc` service | `local` (L2 19441 / L3 19442, `~/dfssvc/local/`) **running** |
| `dfscli` remote | `local` (`http://127.0.0.1:19441`) only |
| Python | `~/dfs-venv/bin/python` (3.12, with `cryptography`) |

**Note**: Both servers above were started with code prior to `122afcf`. Since
returning the root public key requires the new code, restart them before testing
`root_pubkey` (`launchctl bootout` → `bootstrap`, `./dfssvc stop local` → `start`).

### 5.2 Remote (WireGuard)

| Site | Connection | Notes |
|---|---|---|
| Scaleway | `deploy@192.0.2.60` (public `203.0.113.162`) | RTT ~285ms. `ListenPort` pinned |
| Sakura | `deploy@example.com` (192.0.2.254) | Hub. RTT ~21ms. Symmetric keepalive |
| Pi5 | `operator@198.51.100.7` | RTT ~0.5ms |

**Note**: WireGuard routes can be unstable at times. During testing, Mac → Scaleway
became unreachable for several minutes (reachable via public IP and via Sakura).
Recording timestamps when drops occur makes them easier to trace.

All dfs servers on **all sites are stopped** (verified). Restart them when resuming.

---

## 6. Resumption Steps

```bash
cd ~/src/dfs

# 1. Check state
git log --oneline -3
git status --short          # clean if empty
~/dfs-venv/bin/python -m pytest tests -q   # 160 passed, 1 skipped (~171s)

# 2. Start server (with new code)
./dfssvc list               # check existing services
./dfssvc start --name work --port 20000
./dfssvc env work           # prints dfscli config lines

# 3. Connect and use
./dfscli create work --registry http://127.0.0.1:20001 \
    --key ~/dfssvc/work/keys/writer --secret <tree_secret>
./dfscli ls work:
./dfscli config show work   # root_fingerprint should be recorded
```

Then proceed to §2.1 (A: Read Availability).
