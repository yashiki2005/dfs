# dfs Test Plan

> **English** | [日本語](PLAN.ja.md)

## 0. Purpose of This Document

A plan to **verify before implementation** the design proposal in `DESIGN.md` (the L0–L5 layered architecture).

Of the design proposal, two parts are risky. Test these first:

1. **L1 (Authority Delegation)**: Can it truly close under a DNSSEC-like model?
   → If not, the entire design collapses.
2. **Single-Writer Boundaries (§5)**: Can they be enforced in practice?
   → If not, we fall back to three-way merge (repeating `dfs`).

Conversely, **L3 and L5 use things that already work**, so they are not the subject of verification. Call `mini_lustre` (L3) and `clayfs` (L5) as-is and only check whether the layer boundaries hold.

## Policy

- **Build each layer as an independent command.** Cross-layer integration comes last.
- **Decide "what to do on failure" at each stage beforehand.** Do not build features where this cannot be decided (`DESIGN.md` §11 guideline).
- **Do not discard existing artifacts.** Use or adapt `dfs3` Format 4 (Merkle tree), the 11 evil tests, `clayfs`, and `mini_lustre` directly.
- **Verify with numbers.** Not "it worked," but measure round trips, transfer volume, capacity, and time.

---

## Stage 0: Verify L5 (Local Materialization) Works As-Is

**Purpose**: Can `clayfs` be used unmodified as L5? If modifications are needed, determine their scope up front.

**Steps**

1. Create and mount a virtual drive with `clayfs` (macOS).
2. Place `~/src/dfs/scratch/tree/` as the working tree and take 3 snapshots.
3. Confirm each snapshot directory can be read directly from outside (`/.clayfs/snapshots/<id>/` is a normal folder).
4. Send a snapshot elsewhere with `rsync -a` and confirm it is readable there.
5. Confirm `.clayfs` is not inside the snapshots (no recursion).

**Criteria**

- If 3 and 4 pass, **L5 is "readable as a normal folder."** This becomes the interface with L4.
- If 5 passes, placing L4 metadata inside L5 will not collide.

**What to measure**: Snapshot creation time, total capacity growth across 3 snapshots (whether CoW is effective).

**Fallback on failure**: Do not modify `clayfs`; absorb outside L5 (add a thin layer that only reads snapshots). Do not touch `clayfs` itself.

---

## Stage 1: L0 and L1 (Identifiers & Authority Delegation) — Minimal Verification

**Purpose**: Answer Questions 1 and 2 of `DESIGN.md` §10: "Does domain authority align with storage ownership?" and "Can delegation be declared unilaterally?"

**Premise**: **Do not implement** here. Verify on paper and with signatures (`openssl` and existing Ed25519 keys suffice).

**Steps**

1. Create 3 keys:
   - `root.json` (your root key; reuse `~/.ssh/id_ed25519`)
   - `alice.json` (for `alice@example.com`)
   - `bob.json` (for `bob@example.com`)
2. Define and write a **minimal format** for delegation records. Example:

   ```json
   {
     "path": "/example.com/alice",
     "writer": "ssh-ed25519 AAAA... alice",
     "parent": "/example.com",
     "issued_at": 1762900000,
     "expires_at": 1794436000,
     "signature": "<signature by parent's key>"
   }
   ```

3. Hand-craft and verify the following 4 cases:
   - (a) Valid delegation: Parent's signature verifies.
   - (b) Forged delegation: `bob` tries to delegate `/example.com/alice` to himself → **Can it be rejected?**
   - (c) Expired delegation: Past `expires_at` → **Can it be rejected?**
   - (d) Re-delegation: Owner of `/example.com/alice` delegates `/example.com/alice/shared` beneath it to `bob` → **Should it be allowed?**

**Criteria**

- If (b) and (c) can be rejected and (d) can be allowed, **L1 closes**—same shape as DNSSEC delegation.
- If (b) cannot be rejected, **redesign L1** (if this breaks, everything breaks).

**Deliverable for this stage**: `specs/delegation.md` (format and judgments for the 4 cases). Write no code.

**Why write no code**: L1 is consensus on "who may claim a name"; implementation can wait. **Writing code before the format is settled leads to the same unfixable trap as `dfs`.**

---

## Stage 2: L4 (Consistency) — Single-Writer Append-Only Log

**Purpose**: Verify that write boundaries from `DESIGN.md` §5 can actually be enforced. Build on `dfs3` Format 4 Merkle trees.

**Steps**

1. Reuse `layout.py` from `dfs3` (or `dfs4`), extracting only reading/writing of **per-directory chunks**. Do not attach sync, encryption, or storage nodes (L4 only this time).
2. Build an append-only log. One version per line: `{version, timestamp, root_chunk_name, parent_version, signature}`.
3. Write the following tests (following `dfs` evil test style):
   - **Single writer**: Two writers cannot write concurrently to the same subtree (a lock suffices).
   - **Writer handoff**: When the writer changes via a delegation record (Stage 1 format), **the new writer can continue from the old version as parent**.
   - **Rollback detection**: Even if shown an old version, stay on the newer version (same test as `dfs` evil B6—**must be reimplemented**).
   - **Silently dropped writes**: Read back and verify; never report success (same as `dfs` evil B7—**must also be reimplemented**).
4. Confirm double writes **do not occur**. If they do, the design is wrong—stop there.

**Criteria**

- If "two writers cannot write concurrently to the same subtree" holds, **three-way merge becomes unnecessary**. This is the crux of the design.
- If it fails, **change how write boundaries are drawn** (increase subtree granularity).

**What to measure**: Write volume per version (only changed directory chunks?), read round trips (levels traversed from root to chunk).

**What to port (use as-is)**: These 4 items from `dfs` evil tests:

| `dfs` Test | Counterpart in This Stage |
|---|---|
| A2 Cannot overwrite chunk with different content | Verify chunk name against content (same idea) |
| A5 Replaying eavesdropped signed requests fails | Handled by version monotonicity |
| B6 Relay showing old index does not roll back | **Reimplement as-is** |
| B7 Relay silently dropping writes does not report success | **Reimplement as-is** |

---

## Stage 3: L2 (Location Resolution) — From Name to Address

**Purpose**: Answer Question 3 of `DESIGN.md` §10: "Where should locators live?"

**Revised Premise**: Previously stated "deliverable is a table, not code," which was a mistake. Leaving only a table loses how numbers were generated, making them unreproducible (indeed, Stage 2–5 measurements had to be deleted from `DESIGN-ANSWER.md` because generating scripts were missing). **Keeping measurement code and raw data in the repository is the deliverable of this stage.** Tables are generated as outputs from them.

**Steps**

1. Compare 3 options using **the same benchmark harness**:
   - (a) **Registry**: Centralized. Fast. Single point of failure.
   - (b) **DHT**: Decentralized. Longer path lengths. Not implemented in initial version; measure via model and minimal implementation.
   - (c) **DNS reuse**: Existing infrastructure. TTL and censorship constraints.
2. Place the benchmark harness in `bench/` and measure the same metrics under 3 conditions:
   - **Local** (loopback)
   - **LAN** (real devices: Mac and Pi5)
   - **High latency** (inject 200ms RTT via `tc qdisc` or proxy)
3. Record for each approach and condition:
   - Resolution round trips (protocol hops, counted from implementation)
   - Resolution latency (median, p95)
   - Resolution success rate with 1 node down
   - Blast radius when central registry goes down ((a) only)
4. Save raw data in `bench/results/<date>-<env>.json` and generate tables by aggregating them.
5. Following `DESIGN.md` §9, **build with a registry first in a form that allows adding DHT later**.

**Criteria**

- If high-latency round trips ≤ 2, practical as L2.
- If ≥ 3 round trips needed, **design caching first** (include in L2 design).
- Explicitly document whether the single point of failure is acceptable.

**What to measure**: Round trips, latency, failure-case success rate. **Keep measurement code and raw data.** When citing numbers in prose, always state "which harness, which environment, and when measured."

**Deliverables**

| File | Contents |
|---|---|
| `bench/l2_bench.py` | Common benchmark harness for 3 approaches × 3 conditions |
| `bench/results/*.json` | Raw data (environment, timestamp, per-trial values) |
| `specs/l2_comparison.md` | Comparison table and adoption decision generated from raw data |

**What not to do**: Fully implementing all 3 approaches. Keep (b) and (c) minimal for decision-making; implement (a) Registry for real.

---

## Stage 4: L3 (Data Plane) — Use Existing

**Purpose**: Confirm no new transport needs to be written. Question 5 of `DESIGN.md` §10 (content addressing).

**Steps**

1. Start `mini_lustre`'s OST **as-is** and store chunks pointed to by L4.
   - Here `mini_lustre`'s lack of authentication (`DESIGN.md` §1.2) becomes an issue.
   - **Mitigation**: Restrict OST to LAN and substitute authentication with L4 signatures. Do not add auth into OST itself.
2. Change chunk naming to **content addressing** (current `dfs` uses SHA-256 of ciphertext, so identical content gets different names—directly hurting distributed placement efficiency).
   - Include plaintext SHA-256 in the name, and **perform encryption outside the name** (`DESIGN.md` §10 Question 5).
   - Confirm chunks with identical content get identical names (deduplication and rarity work).
3. Measure transfer efficiency with `bench/l3_bench.py` and keep raw data:
   - Batch PUT round trips, bytes sent, elapsed time (varying file count and size).
   - Whether deduplication works for identical content (same batch and separate batches).
   - Compatibility with `mini_lustre`'s OST (framing and chunk identifiers).
   Do not introduce libtorrent until these measurements show it is needed.

**Criteria (Updated with Measurements)**

- At ≤ 100 chunks, **do not add libtorrent**. Current L3 batch PUT fits in 2 round trips (100 files × 64KB in 24.7ms).
- At ≥ 1000 chunks or when pulling from many peers becomes necessary, consider libtorrent.
- **`mini_lustre`'s OST cannot be used unmodified.** Both framing and chunk identifiers differ (`specs/l3_data_plane.md` §3). Using it requires an RPC adapter.

**Note**: Building on libtorrent here brings back **the Tor/anonymity debate from `DESIGN.md` §3**. If anonymity is needed, do not put data over Tor/I2P (collapses under congestion). **Do not bring anonymity into this stage.**

---

## Stage 5: Integration — Share One Tree Between Two Machines

**Purpose**: Confirm layers actually connect in a **minimal configuration**.

**Architecture**

```text
[Mac]                                      [Linux / Pi5]
clayfs (L5) ←→ L4 append log ←→ L2 registry ←→ L4 append log ←→ clayfs (L5)
                                     ↕
                              L3 data (ChunkStore)
```

**Steps**

1. Hold **the same subtree of the same user** on two machines (e.g., `/example.com/alice/notes`).
2. Write on one → arrives on the other → confirm **both can take `clayfs` snapshots**.
3. **Write concurrently.** → Confirm that via single-writer boundaries (Stage 2), **one waits or one is rejected**. **No three-way merge occurs** is the passing condition.
4. Drop one node and confirm the other continues reading/writing (availability; if rejected here, that is by design).
5. Transfer writer via delegation (Stage 1) to `bob`, and confirm **`bob` can continue writing**.

**Criteria**

- If step 3 yields "rejected" or "waits" with **0 conflict copies**, the design succeeds.
- If conflict copies appear, write boundaries are broken. **Return to Stage 2.**

**Results (2026-11-11, Mac ↔ Pi5 Real Devices)**

- Harness: `bench/e2e_lan.py`, raw data: `bench/results/20261111-200812-e2e-lan.json`
- Details: `specs/e2e_lan.md`
- L2 (HTTP 9440) and L3 (TLS 1.3, 9443) ran over LAN. Average RTT 2.25ms.
- Bidirectional Mac push → Pi5 pull and Pi5 push → Mac pull matched down to SHA-256.
- Concurrent pushes from the same parent version had the later one rejected with `ConflictError`.
- 0 conflict copies. No three-way merge occurred.
- **Unverified**: High latency (RTT 200ms), 3+ machines, long-running operation, 2 OSTs over LAN.

**What to measure (Final)**

| Metric | Target |
|---|---|
| Time from write on one side to readable on the other | Within 1 second on LAN |
| Transfer volume per version | Within 2× size of changed subtree |
| Behavior on concurrent writes | Wait or reject (0 conflict copies) |
| Read/write with 1 node down | Continues if availability required; rejects if not (by design) |
| Writer identity after delegation | New writer can continue |

---

## Stage Order and Non-Goals

```text
Stage 0 (L5 check)     → Stage 1 (L1 spec)     ← Crucial. No code
                       → Stage 2 (L4 impl)     ← Single writer. Port evil B6/B7
                       → Stage 3 (L2 compare)  ← Build table
                       → Stage 4 (L3 reuse)    ← Use existing
                       → Stage 5 (2-node integration)
```

**Non-Goals (Same as `DESIGN.md` §8)**

- Global three-way merge
- Global POSIX consistency
- Custom DHT / custom peer exchange
- Remote rollback
- Automatic bidirectional sync
- Bringing anonymity into the data plane

## "Stop" Criteria per Stage

| Stage | Stop Condition | Mitigation When Stopped |
|---|---|---|
| 0 | `clayfs` requires modification | Do not modify; absorb externally |
| 1 | Cannot reject forged delegation | Redesign L1 (halt everything) |
| 2 | Single-writer cannot be enforced | Increase subtree granularity; if still failing, revisit design |
| 3 | ≥ 3 round trips under high latency | Design caching first |
| 4 | libtorrent becomes necessary | **Stop here and return to the anonymity discussion** |
| 5 | Conflict copies appear | Return to Stage 2 |

## Open Questions (Carried Over from `DESIGN.md` §10)

Answer as stages progress. **Do not decide answers beforehand.**

1. Can L1 ride on DNSSEC? → **Answer in Stage 1**
2. Who decides write boundary borders? → **Answer in Stages 1 & 2**
3. Where should L2 locators live? → **Answer in Stage 3**
4. Single-writer exclusion (multiple devices of same user) → **Answer in Stages 2 & 5**
5. Reconciling content addressing and encryption → **Answer in Stage 4**
6. Use `clayfs` as-is? → **Answer in Stage 0**
7. Keep economics, moderation, first contact out of scope? → **Answer after Stage 5**
