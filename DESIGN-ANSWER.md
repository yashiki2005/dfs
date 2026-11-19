# Pre-Verification Results and Finalized Design (Stages 0–5 Summary)

> **English** | [日本語](DESIGN-ANSWER.ja.md)

This document records the **L0–L5 specifications and answers to §10 (Open Questions)** finalized through Stages 0–5 of verification.
Performance measurements whose generating scripts and raw logs no longer exist were removed from §2.2.

---

## 1. Finalized Specification per Layer (L0–L5)

Pre-verification confirmed that existing assets (`clayfs`, `mini_lustre`, `dfs3` Merkle structure, evil tests) can be combined unmodified or with minimal extraction.

| Layer | Role | Finalized Approach / Component | Boundary Invariants |
|---|---|---|---|
| **L0 / L1** | Identifiers & Authority Delegation | Canonical JSON (`jq -cnS`) + OpenSSH Ed25519 detached signatures (`ssh-keygen -Y`, namespace `dfs-delegation-v1`) | Parent-child path prefix match · expiration containment (`child.expires_at <= parent.expires_at`) · immediate revocation via monotonically increasing `epoch` (`specs/delegation.md`) |
| **L2** | Location Resolution | Signed locators (`dfs-l2-locator-v1`).<br>Initial implementation is a **registry (MDSAnnouncer style)**, with a 2-tier cache when DHT is added later | Embed L4 head version (`head_version`, `head_hash`) in the locator so resolution and head check complete in **1 RTT** |
| **L3** | Data Plane | Custom TLS/TCP OST (`ChunkStoreServer`, `l3_store.py`). Protocol differs from `mini_lustre`'s OST and **cannot be reused unmodified** (`specs/l3_data_plane.md` §3).<br>Chunk encryption uses **standard AEAD (ChaCha20-Poly1305, fresh random nonce)** | Deduplication is judged before encryption by plaintext address `plain_id = HMAC(K_addr, P)`, owned by the writer's own index (reconstructible from signed history). OST verifies only `wire_id = SHA256(C)` |
| **L4** | Consistency & Append-Only Log | Per-subtree single-writer append-only log (`dfs-l4-log-v1`) + directory chunks (`dfs-dir-v1`) | Reject concurrent writes via **CAS (Compare-And-Swap)** on head version (eliminating three-way merge), B6 defense via `HeadPin`, B7 defense via Read-after-Write |
| **L5** | Local Materialization | `dfs.fs` (`dfs/fs/`) auto-detects OS CoW and falls back to real copy if absent. `ClayFSAdapter` is a thin wrapper | Snapshots (`/.clayfs/snapshots/<id>/`) are the L4 I/O boundary; normalize/exclude recursive `.clayfs` inclusion and OS-specific metadata (NFD/NFC drift, `.DS_Store`) at the boundary. Snapshots use independent inodes regardless of CoW |

---

## 2. Verification & Measurement Summary for Stages 0–5

### 2.0 Real-Device Integration (Stage 5)

Shared one tree between two machines: Mac and Pi5 (`specs/e2e_lan.md`, `bench/results/20261111-200812-e2e-lan.json`).

- L2 (HTTP 9440) and L3 (TLS 1.3, 9443) ran over LAN. Average RTT 2.25ms.
- Bidirectional push / pull between Mac ↔ Pi5 succeeded, with contents matching down to SHA-256.
- Concurrent pushes from the same parent version had the later one rejected with `ConflictError`. 0 conflict copies.
- Tested on separate ports without stopping existing `mini_lustre` (9001/9002).
- Unverified: 3+ machines, long-running operation, 2 OSTs over LAN.

#### 2.0.1 WAN (High-Latency) Real Devices (`specs/e2e_wan.md`)

Measured across 3 sites over WireGuard (Mac / Scaleway / Sakura) with RTT 20–285ms.

- **Push round trips fixed at 1.** One push completes in "1 HAS round trip + 1 PUT round trip." Measured 1 round trip even at RTT 278ms; sending 2.13MB finished in 3.9–4.4 seconds.
- **Pull round trips also decoupled from file count (`batch` operations).** Directory chunks take 1 round trip per level; file chunks are fetched in bulk per store. For a flat 20-file structure: **21–23 → 2 round trips**, duration **8,025 → 4,010ms** (285ms path), **953 → 534ms** (22ms path). Locally, even 500 files take 2 round trips. What remains is transfer volume itself; round-trip count is no longer dominant.
- **Single-writer works even under high latency.** Across all 3 paths, the later concurrent push hit `ConflictError`, with 0 conflict copies.
- **Does not hang on network outage.** Pushing while the server was stopped failed with `ServiceUnavailableError` in 138–938ms.
- For WAN support, added env-var timeouts (`DFS_L2_TIMEOUT` / `DFS_OST_SOCKET_TIMEOUT` / `DFS_OST_CONNECT_TIMEOUT`) and round-trip reductions (batch HAS, `assume_absent`).
- Still unverified: 100+ chunks on WAN, effective throughput, 3+ concurrent participants, long-running operation.

#### 2.0.2 Local CLI (`dfscli`, `specs/cli.md`)

Separate from the layer-testing CLI (`dfs/cli.py`), added a CLI for daily file operations (`dfscli`). It reuses `dfs/cli.py` components (L2 registry client, server, node setup) and layers a remote-named operation model on top.

- Remote = write boundary (subtree). The core is just the L2 registry; **L3 OST and subpath are resolved by querying L2** (locator `endpoints` and writer public key in delegation records). Minimal registration needs only `--registry` (hostname alone suffices; defaults to port 9440).
  - If `--key` is omitted, a writer key is generated on the spot (`~/.config/dfs/keys/<name>_ed25519`, OpenSSH format). If a provided path does not exist, it errors out (does not silently create a new one on typo).
  - `tree_secret` is a shared secret never stored on the server, so when `--secret` is omitted it is read **twice without echo** from the terminal (Python `getpass`, since macOS lacks `pinentry`/`dialog`). A typo would produce an undecryptable tree, so it prompts a second time for confirmation and accepts only matching inputs. Writing an empty secret stops as a usage error.
  - Registration uses `dfscli create` (short alias for `config create`).
  - `--path` does not need a leading `/`.
- Reads (`ls` / `lsl` / `lsjson` / `size` / `cat` / `check`) do not advance versions. Listings traverse only directory chunks without fetching file contents (`l4_log.py::list_tree`).
- Deletion uses `rm` / `rmdir` / `purge`, directory creation uses `mkdir`. Because `dfs` **preserves empty directories in versions** (`{"entries": []}` directory chunks), `rm` leaves empty directories by default and cleans them up only with `--rmdirs`. `sync --delete` always cleans them up since it mirrors state.
- Writes (`copy` / `copyto` / `sync`) "align the copy to head, apply changes, and push as 1 version." **If there are no changes, no version is created** (idempotent).
- Single-writer conflicts are distinguished by exit codes (7: CAS failure, 8: B6, 9: B7, 6: unreachable, 2: usage error).
- `--key` expects an OpenSSH-format Ed25519 private key (`crypto.py`'s signing path assumes OpenSSH format).
- Measured (Mac local): copying 4 files (4,027B) took 69.9 ms. Without `--ost` / `--path`, `config create` → `touch` → `copy` → `cat` → `pull` succeeded, and `pull` output matched via `diff`.
- Regression suite: 31 cases in `tests/test_cli_main.py` (idempotency, dry-run, `--delete` on/off, exit codes, direct-children-only listing, omitting `--ost`/`--path`, rejecting empty `tree_secret`, delete + empty-dir round-trip, hostname-only registry, auto key creation, `--no-prompt`, `create` alias, double secret prompt).

#### 2.0.3 Starting a Local Server (`dfssvc`)

`dfs serve` requires manually preparing a state directory, root public key, and two ports. That is fine for testing layers, but tedious for quick local trials, so `dfssvc` (`dfs/svc.py`) was added.

- **Finds 2 consecutive free ports**, assigning the first to L2 and the second to L3.
- Prepares the root Ed25519 key and **writer key**, creates the state directory, starts `dfs serve`, and registers delegation to the writer (including intermediate levels). A single `start` makes `dfscli` ready to use. For multi-level delegation, identical expiration times can fail Invariant 3 due to clock skew, so intermediate levels are given +1 day.
- Waits for startup, verifies L2 response, and records connection details in `~/.config/dfs/services.json` (mode 600).
- `stop` / `list` / `status` / `env` / `logs` handle cleanup and inspection. `stop` sends SIGTERM → 10s → SIGKILL.
- Free-port detection uses 2 steps (attempt connect → `bind` without `SO_REUSEADDR`), because on macOS `bind` with `SO_REUSEADDR` passes right through a `0.0.0.0:N` listener.
- Measured (Mac local): with a `launchd` server already using 19440/19443, `start` selected the consecutive pair 19441/19442 and succeeded through delegation → `dfscli` registration (no `--ost`) → `copy` → `cat`.
- Regression suite: 12 cases in `tests/test_svc_cli.py` (port discovery, recording, start/stop, auto-delegation, `ls` before writes, `--no-delegate`, multi-level `--path`).

### 2.1 Security & Consistency Verification (Stages 1 & 2)

Confirmed across all evil tests and boundary tests that three-way merges and history rollbacks never occur, and invalid operations halt cleanly with the intended exceptions (`tests/test_evil_suite.py`, `tests/test_integration.py`).

| Verification Item | What Was Tested | Result | Mechanism |
|---|---|---|---|
| **L1 Authority Delegation** | 5 cases: valid delegation, forgery rejection, out-of-scope rejection, expiration, re-delegation | **All Passed** | 5 invariants in `specs/delegation.md` + `allowed_signers` chain |
| **Single-Writer Exclusion** | Concurrent writes from 2 devices (Mac / Pi5) with the same key | **Passed (0 conflicts)** | Strict match of `parent_version` and `parent_hash` (CAS) immediately rejects later write with `ConflictError` |
| **Writer Rotation & Revocation** | Immediate revocation of old key via `epoch` bump and history continuation from `base_version` | **Passed** | `delegation_epoch` stamped in L4 log + `version > base_version` constraint |
| **evil A2** | Tampering or overwriting chunk data on storage (OST) with different content | **Passed (Detected)** | `wire_id` check on fetch and `plain_id` recomputation check after decryption |
| **evil A5** | Replaying eavesdropped valid signed write requests | **Passed (Rejected)** | Rejected by strict monotonic version increase (`head_ver + 1`) |
| **evil B6** | Relay presenting an old index (old version) as latest (rollback attack) | **Passed (Detected)** | Version & hash comparison against client's local `HeadPin` (`local_head.json`) |
| **evil B7** | Relay responding success to a write request while silently dropping it | **Passed (Detected)** | Local pin is not advanced until Read-after-Write verification completes right after `commit` |

### 2.2 About Measurements

Performance, round-trip, and transfer-volume numbers from Stages 2–5 (elapsed times, RTT counts, transfer ratios) **were removed from this document because their generating scripts and raw logs no longer exist.** Unreproducible numbers cannot serve as evidence for design decisions.

Only design decisions independent of those numbers remain:

- **L4 subtree updates are confined to changed subtrees.** Because directory chunks are named by content, unchanged subtrees are reused (`dfs/l4_log.py::upload_directory`).
- **L2 uses a registry as its initial implementation.** See `specs/l2_comparison.md` for round-trip comparisons. Even when DHT is added, use a 2-tier architecture separating endpoint resolution from head version retrieval.
- **L3 uses a custom TLS/TCP OST.** Its framing and chunk identifiers differ from `mini_lustre`'s OST, so it cannot be reused unmodified (`specs/l3_data_plane.md` §3). While chunk counts remain small, libtorrent's fixed overhead is relatively heavy, so it is not introduced.
- **Deduplication is performed by the writer's own index.** Unchanged subtrees are neither re-encrypted nor re-transmitted. Rather than raw measurements, `tests/test_integration.py` verifies "0 ciphertext payload bytes sent when unchanged."

---

## 3. Finalized Answers to Open Questions (§10)

### Question 1: Can L1 ride on DNSSEC?
- **Answer: Yes, but only the "root anchor public key" is placed in DNS.**
- **Details**: Only `/example.com`'s root public key (and initial registry URL) is placed in a DNSSEC-protected TXT record (or local trust anchor config). Delegations below it (`/example.com/alice`, etc.) bypass DNS and are distributed/verified over L2/L4 as a Canonical JSON + Ed25519 signature chain defined in `specs/delegation.md`. This enables instant delegation and revocation without DNS TTL delays.

### Question 2: Who decides the "boundaries" of write boundaries?
- **Answer: The parent subtree's writer (Owner/Writer).**
- **Details**: Wherever the parent signs an L1 delegation record for a child path and places `{"type": "delegated_mount", "mount_path": "..."}` inside its L4 directory chunk becomes the single-writer boundary. Parent and child Merkle trees are cryptographically decoupled; child writes never propagate to parent hash calculations or locks.

### Question 3: Where should L2 locators live?
- **Answer: Start with a registry (MDSAnnouncer style), abstracting the L2 interface into `resolve` / `announce` so DHT can be added later.**
- **Details**: There is no need to trust the registry server—locators returned by the registry carry the writer's Ed25519 signature (`dfs-l2-locator-v1`). The registry only handles "distributing signed locators" and "CAS arbitration of head versions."

### Question 4: How to enforce single-writer exclusion across multiple devices of the same person?
- **Answer: No inter-device lock communication; enforce via CAS (optimistic concurrency) on L2/L4 head versions.**
- **Details**: Even if the same person keeps the same private key on Mac and Pi5, writes must present the expected parent version (`parent_version`) and hash (`parent_hash`). Once the first write succeeds, the head advances, so the later write is reliably rejected with CAS mismatch (`ConflictError`). The rejected device simply `pull`s to update its snapshot and retries (zero automatic three-way merging).

### Question 5: How to reconcile content addressing and encryption?
- **Answer: Deduplicate before encryption. Content addresses use a plaintext keyed-hash (`plain_id`), encryption uses standard AEAD (ChaCha20-Poly1305 with a fresh random nonce), and the `plain_id` derivation key is separated from encryption key rotation.**
- **Details**:
  - Because there is a single writer, deduplication is performed by **the writer itself**, not the OST. The writer maintains a `plain_id -> wire_id` index and neither re-encrypts nor re-sends identical plaintext. The index can be reconstructed from signed history (each version's `root_plain_id`/`root_wire_id` and directory chunk entries).
  - `plain_id = HMAC-SHA256(K_addr, "dfs-plain-id-v1:" || plaintext)`. `K_addr` is long-lived and decoupled from encryption key rotation (`epoch`); mixing them would destroy deduplication across key rotations.
  - Ciphertext `C = ChaCha20Poly1305(K_enc(plain_id), nonce=os.urandom(12), plaintext)`. Even with a fresh random nonce every time, deduplication occurs first on `plain_id`, so **deduplication remains 100% effective**. Deterministic encryption is unnecessary.
  - `wire_id = SHA256(C)` is the OST storage key. `plain_id` is embedded in the ciphertext and included in AAD, so mismatches are caught by the AEAD tag.
  - Thus, deduplication and confidentiality are orthogonal. Nonce reuse never occurs, and known-plaintext dictionary attacks cannot cross into other users' subtrees (confined to writers holding `K_addr`).

### Question 6: Should `clayfs` be used as-is?
- **Answer: Do not port `clayfs` itself; reimplement only snapshot I/O as `dfs.fs`.**
- **Reason**: `clayfs` is written in Swift and assumes macOS APFS sparsebundle / Linux Btrfs. It does not run on Windows, and ReFS is barely deployed on consumer PCs (restricted to Dev Drive on Windows 11; block clone requires 24H2+). To satisfy "works anywhere Python runs," CoW must be treated as an **optimization**, falling back to real copies when absent.
- **Details**: `dfs/fs/core.py` splits a root into `root/tree` and `root/.clayfs/snapshots`, providing `snapshot()` / `clone()` / `materialize()`. Backends are `copy` (default, works everywhere) / `reflink` (macOS `clonefile(2)`, Linux `FICLONE`) / `fast_clone` (Windows `FSCTL_DUPLICATE_EXTENTS_TO_FILE`). Detection tests cloning an actual file, so NFS and exFAT automatically fall back to `copy`. `ClayFSAdapter` became a thin wrapper calling this `FileSystem`.
- **Bug in old implementation**: Snapshots previously used `shutil.copytree(..., copy_function=os.link)`, causing the working tree and snapshot to share inodes so overwriting a source file mutated the snapshot (breaking rollback safety). `tests/test_fs_cow.py` locks down that both `copy` and `reflink` produce independent inodes.

### Question 7: Is it okay to keep economics, moderation, and first-contact trust out of scope?
- **Answer: Yes, keep them out of scope (do not introduce them into the design).**
- **Details**: Introducing token economies or public swarms that rely on arbitrary untrusted nodes invites illegal data mixing (accomplice liability risks), Sybil/DoS attacks, and bloated incentive mechanisms. By closing `dfs` as a protocol for sharing trees between "writers delegated by an L1 trust chain" and "owned or trusted-peer OSTs," these problems do not arise in the architecture.

---

## 4. Migration Guidelines to Production Code

With pre-verification complete, structure the production repository (`dfs`) as follows. Implement each layer as an independent CLI / module, and keep the Stage 0–5 verification scripts as CI regression tests.

```text
dfs/
├── DESIGN.md                  # Main design document
├── DESIGN-ANSWER.md           # Stage 0–5 verification results & finalized design (this document)
├── PLAN.md                    # Per-stage plan and criteria
├── TODO.md                    # Resumption status notes (unimplemented, unverified, next steps)
├── specs/
│   ├── delegation.md          # L1 authority delegation spec (incl. root anchor verification & TOFU)
│   ├── l2_comparison.md       # L2 3-way measurement comparison table
│   ├── fs-cow.md              # L5 CoW abstraction (backend selection & unsupported environments)
│   ├── l3_data_plane.md       # L3 measurements & decisions (batch ops, WAN round trips)
│   ├── e2e_lan.md             # Mac ↔ Pi5 real-device integration (LAN)
│   ├── e2e_wan.md             # 3-site WAN real devices & latency tolerance
│   ├── cli.md                 # dfscli (local CLI)
│   └── svc.md                 # dfssvc (local server launcher)
├── dfs/
│   ├── crypto.py              # Signatures + content addressing + standard AEAD + fingerprints (shared L1/L3/L4)
│   ├── l1_delegation.py       # Delegation chain verification (5 Invariants)
│   ├── l2_registry.py         # Registry service & signed locators (chain reconstruction to root)
│   ├── l3_ost_adapter.py      # Content-addressed chunk storage (batch_has / batch_put / batch_get)
│   ├── l4_log.py              # Single-writer append-only log, Merkle chunks, HeadPin (B6/B7 defense)
│   ├── l5_clayfs.py           # clayfs snapshot integration adapter (NFC normalization, non-recursive)
│   ├── fs/                    # CoW abstraction (CoW if available, real copy fallback)
│   ├── cli.py                 # Server-side CLI (serve / delegate / init / push / pull / status)
│   ├── remotes.py             # dfscli remote definitions (name -> connection info, root anchor)
│   ├── cli_main.py            # dfscli core (ls/cat/copy/sync/pull/rm/mkdir, etc.)
│   └── svc.py                 # Local server launcher (2 free ports + serve startup)
├── dfscli                     # dfscli entry point
├── dfssvc                     # dfssvc entry point
├── bench/                     # Benchmark harness (l2_bench / l3_bench / e2e_lan / e2e_wan) & raw data
└── tests/
    ├── test_evil_suite.py     # Regression tests for A2, A5, B6, B7 + single-writer exclusion + revocation
    ├── test_integration.py    # Regression tests for 2-node sharing & round-trip reduction
    ├── test_root_anchor.py    # Chain verification via root anchor (without trusting registry)
    ├── test_cli_main.py       # dfscli regression tests
    └── test_svc_cli.py        # dfssvc regression tests
```
dfs/
├── DESIGN.md                  # Main design document
├── specs/
│   ├── delegation.md          # L1 authority delegation spec (finalized)
│   └── l2_comparison.md       # L2 3-way measurement comparison table
├── dfs/
│   ├── crypto.py              # Signatures (cryptography / ssh-keygen fallback) & content addressing + standard AEAD (shared L1/L3/L4)
│   ├── l1_delegation.py       # Delegation chain verification (5 Invariants)
│   ├── l2_registry.py         # Signed locator registry client & server
│   ├── l3_ost_adapter.py      # Content-addressed chunk storage (batch_has / batch_put / batch_get)
│   ├── l4_log.py              # Single-writer append-only log, Merkle chunks, HeadPin (B6/B7 defense)
│   ├── l5_clayfs.py           # clayfs snapshot integration adapter (NFC normalization, non-recursive)
│   ├── fs/                    # CoW abstraction (CoW if available, real copy fallback)
│   ├── remotes.py             # rclone-like CLI remote definitions (name -> connection info)
│   ├── cli_main.py            # Local CLI (dfscli) core (ls/cat/copy/sync/pull/rm/mkdir, etc.)
│   └── svc.py                 # Local server launcher (2 free ports + serve startup)
├── dfscli                     # rclone-like CLI entry point
├── dfssvc                     # Local server launcher CLI entry point
└── tests/
    ├── test_evil_suite.py     # Regression tests for A2, A5, B6, B7 + single-writer exclusion + revocation
    └── test_integration.py    # 2-node sharing & automated measurement tests for final 5 metrics
