# L3 Data Plane Specification and Decisions (`specs/l3_data_plane.md`)

> **English** | [日本語](l3_data_plane.ja.md)

## 0. Purpose and Scope

This document records the measurements and design decisions for Phase 4 of `dfs` (L3: Data Plane).
Question 5 of `DESIGN.md` §10 (reconciling content addressing and encryption) is already solved in §1; here we decide "what to build on and how much to own ourselves."

- Harness: `bench/l3_bench.py`
- Raw data: `bench/results/20261111-195612-l3-local.json`
- Measurement environment: macOS arm64, Python 3.12, local (loopback)

---

## 1. Cryptography and Content Addressing (Solved)

Deduplication is decided **before encryption**. Because `dfs` is single-writer, the writer itself—not the OST—performs the check.

| Component | Method |
|---|---|
| Content address | `plain_id = HMAC(K_addr, "dfs-plain-id-v1:" \|\| plaintext)`. `K_addr` is long-term fixed |
| Encryption | ChaCha20-Poly1305. **Nonce is `os.urandom(12)` every time** |
| Encryption key | `K_enc = HMAC(tree_secret, "dfs-chunk-key-v1:" \|\| plain_id)`. May rotate per epoch |
| Storage key | `wire_id = SHA256(ciphertext)` |
| Verification | `wire_id` check → AEAD tag → recompute `plain_id` after decryption (3-stage A2 detection) |
| Compression | Store codec and original size in `DFSB3` header. Compress plaintext before encrypting |

Because the `plain_id` derivation key and encryption key are separated, deduplication against past chunks still works after key rotation.
Random nonces do not degrade deduplication (matching does not use the nonce).

The KDF for string `tree_secret` is versioned. New remotes use `scrypt-v1`, while legacy remotes, invites, and archives without a KDF identifier are decrypted as `legacy-sha256-v1` as before. The KDF identifier is stored in remote config, working config, invite tokens, and archive `meta.json`.

---

## 2. Transfer Efficiency Measurements

Sent bytes and round-trip counts when batch-PUTting a file tree.

| Files × Size | Payload | Elapsed | Sent bytes | Ciphertext body | Round trips | Sent / Payload |
|---|---|---|---|---|---|---|
| 10 × 4KB | 40KB | 15.3 ms | 45,303 B | 43,713 B | **2** | 1.106 |
| 100 × 4KB | 400KB | 7.0 ms | 449,763 B | 436,293 B | **2** | 1.098 |
| 100 × 64KB | 6.4MB | 24.7 ms | 6,593,863 B | 6,580,393 B | **2** | **1.006** |

- **For normal scales, round trips do not depend on file count.** It takes 2 round trips—existence check (HAS) and body upload (PUT)—even for 100 files. Clients split a single HAS at 1,024 items and PUT at 1,024 items or 64 MiB, so exceeding those limits takes multiple round trips.
- Fixed overhead is ~64 bytes per file (`plain_id` 32 + `nonce` 12 + `tag` 16 + framing) plus directory chunks. The ratio approaches 1 for larger files.

### 2.1 Deduplication

| Scenario | Ciphertext body sent |
|---|---|
| 2 files with identical content (same batch) | **8,757 B** (1 file 8,192 B + directory chunk 565 B) |
| Re-sending the same tree (unchanged) | **0 B** (index and HAS only) |
| Adding identical content under another name (separate batch) | **697 B** (directory chunk only; body not re-sent) |

Fixed a bug where identical content in the same batch was sent twice (`l4_log.py::_stage`), caused by misclassifying pending chunks as "unsent," and added regression test `TestL3ContentDedup`.

The index is persisted in `.clayfs/ost_index.json`. Even across separate CLI process invocations, `plain_id -> (wire_id, store_id, codec)` can be reused. The index records the fingerprint of the content-addressing key (`address_key`), invalidating old entries after a `tree_secret` change.
After pushing 20 × 128KiB, modifying 1 file and re-pushing from a separate process reduced sent bytes from 2,628,420 B to 5,731 B.

---

## 2.2 WAN Round Trips

LAN measurements (§2) alone hid the round-trip issue. Over a 285ms RTT WAN, "1 round trip per chunk" is fatal. We fixed `l4_log.py::upload_directory` to decouple round trips from chunk count.

| Scenario | Old round trips | New round trips |
|---|---|---|
| push (N index-hit chunks) | N `batch_has` calls + 1 PUT | **1 `batch_has` (batched) + 1 PUT** |
| push (N new chunks) | — | **1 `batch_has` + 1 PUT** (`assume_absent=True`) |
| pull (N files, flat) | 1 root + N files | **1 root + 1 files = 2 round trips** |
| pull (nested D levels + files) | directory chunks + per file | **D round trips + 1 file round trip** |

Key implementation points:

- Stopped firing `batch_has` per chunk; accumulate index hits in `reused` and send a single batch at the end.
- Newly encrypted chunks are known not to exist on the server, so `batch_put_if_absent(..., assume_absent=True)` skips the internal `batch_has`. Uploads themselves are split by client limits (1,024 items / 64 MiB).
- Only when the batched HAS finds chunks that disappeared from the server do we re-traverse and rebuild (directory chunks embed child `wire_id`s, so partial replacement is inconsistent).
- Reads split `download_directory` into two stages: **directory chunks are fetched breadth-first, 1 round trip per level**, and **file chunks are fetched at the end in batches per store and per limit**. To keep responses from growing too large, batches are split using upfront estimates from manifest `size` (`DFS_BATCH_CHUNKS` = default 1024, `DFS_BATCH_BYTES` = default 16 MiB). Each unique `wire_id` is fetched at most once.

File bodies are split into independent 8 MiB chunks. Legacy "whole-file as 1 chunk" manifests are still readable. New-format file entries store `plain_id`, `wire_id`, `offset`, `size`, and placement `store` for each chunk under `chunks`. This allows storing files exceeding L3's 256 MiB single-chunk limit and deduplicating parts of large files.

WAN measurements (20 × 128KB, RTT 278–285ms, `specs/e2e_wan.md`):

| Path | push RTs | push time | pull RTs | pull time |
|---|---|---|---|---|
| Mac → Scaleway (278.5ms) | **1** | 4,391ms | **21** | 8,025ms |
| Sakura → Scaleway (279.8ms) | **1** | 3,937ms | **23** | 7,692ms |
| Mac → Sakura (22.4ms) | **1** | 923ms | **21** | 953ms |

Because push round trips are fixed, elapsed time is governed mainly by RTT and transfer volume.
After introducing batching, pull round trips also became independent of file count (below).

Before vs. after batching (20 × 128KB = 2.13MB):

| Path | RTT | pull RTs | pull time |
|---|---|---|---|
| Mac → Scaleway | 275.8ms | **21 → 2** | **8,025 → 4,010ms** |
| Sakura → Scaleway | 275.1ms | **23 → 2** | **7,692 → 3,644ms** |
| Mac → Sakura | 22.1ms | **21 → 2** | **953 → 534ms** |

In local regression tests, even a flat 500-file tree takes 2 round trips, and 3 nested levels + 53 files takes 4 round trips. What remains is raw transfer volume; round-trip count is no longer dominant.

Regression tests:

- `TestWanRoundTrips::test_assume_absent_skips_has` — `assume_absent=True` does not send HAS.
- `TestWanRoundTrips::test_push_round_trips_do_not_scale_with_chunks` — at most 2 round trips even with 100 chunks.
- `TestWanRoundTrips::test_ost_timeout_env_vars_are_honored` — timeouts honor environment variables.
- `TestWanRoundTrips::test_server_socket_timeout_is_actually_applied` — actually applied to server sockets.
- `TestWanRoundTrips::test_l2_timeout_env_var_is_honored` — L2 HTTP timeout changes.
- `TestPullBatch::test_flat_pull_is_two_round_trips` — pulling 100 files takes 2 round trips.
- `TestPullBatch::test_nested_pull_is_one_round_trip_per_level` — nested trees take 1 round trip per level.
- `TestPullBatch::test_same_chunk_fetched_once` — identical chunks are fetched only once.
- `TestPullBatch::test_batch_get_split_by_size_cap` — batches can be capped via `DFS_BATCH_CHUNKS`.
- `TestPullBatch::test_missing_chunk_is_reported` — missing chunks raise an exception rather than being silently omitted.

---

## 3. Can `mini_lustre`'s OST Be Used "As-Is"?

**Conclusion: No, not as-is.** The statement "reuse unmodified" in `DESIGN-ANSWER.md` was incorrect.

| Item | `mini_lustre` OST | `dfs` L3 |
|---|---|---|
| Framing | `>II` (JSON len, payload len) + JSON + payload | 1-byte opcode + 64-byte `wire_id` + `>I` len + body |
| Request | `{"action":"write_chunk","args":{...}}` | Custom binary `H`/`P`/`G`/`B`/`M`/`F` |
| Response | Same 8-byte header + JSON + payload | 1-byte status (`O`/`E`/`U`) |
| Chunk identity | `(file_id, chunk_index)` | `wire_id` (SHA-256 of ciphertext) |
| Batch operations | None (individual `read_chunk` / `write_chunk`) | `batch_has` / `batch_put_if_absent` / `batch_get` |

Observed: sending a `dfs` `H` frame to `mini_lustre`'s OST causes the first 4 bytes (`H` + first 3 bytes of `wire_id`) to be parsed as JSON length, failing with `RPC JSON length exceeds limit`.
Conversely, a valid `mini_lustre` frame succeeds and returns `{"status":"ok","bytes_written":5}`.

**Even more importantly**: because `mini_lustre` identifies chunks by `(file_id, chunk_index)`, placing a chunk with the same `wire_id` under another file **stores it as a separate chunk**.
That is, OST-side content-addressed deduplication is not possible on top of `mini_lustre`.

---

## 4. Decisions

### 4.1 Do Not Adopt `libtorrent`

- Transferring 100 files / 6.4MB finishes in 2 round trips / 24.7ms.
- `libtorrent` incurs fixed overhead for handshakes and metadata verification, offering no benefit at this scale.
- Re-evaluate when we need 1,000+ chunks or parallel downloads from many peers (as decided in `PLAN.md`).

### 4.2 Insert an RPC Adapter for `mini_lustre`

Unmodified reuse is not possible. If `mini_lustre` OSTs are used as storage backends in the future, place **an adapter layer that maps `dfs`'s `wire_id` to `file_id`/`chunk_index`**.

However, because `mini_lustre`-side identifiers do not depend on content, deduplication will rely **solely on the writer's index (byte-level omission)**; the OST itself cannot share identical chunks.

### 4.3 Keep the Current Custom L3

The initial implementation uses TLS/TCP in `dfs/l3_ost_adapter.py` (class `ChunkStoreServer`, module alias `dfs/l3_store.py`).

Reasons:

- Completes in 2 round trips and supports batch operations (`batch_has` / `batch_put_if_absent` / `batch_get`).
- Chunks are identified by `wire_id`, matching the writer's index directly.
- Lack of authentication is compensated operationally (restricted to LAN or WireGuard, with integrity guaranteed by L4 signatures).

**Never exposing this OST to the public network** is a mandatory operational requirement.

---

## 5. Remaining Work

| Item | Status |
|---|---|
| Standard AEAD + random nonce | Implemented |
| Writer-index deduplication | Implemented (same-batch bug fixed, persisted in `.clayfs/ost_index.json`) |
| Batch PUT / Batch GET / Batch HAS | Implemented |
| RPC adapter for `mini_lustre` | **Not implemented** (when needed) |
| `libtorrent` | **Not adopted** (while scale is small) |
| Large-scale (1,000+ chunks) re-benchmark | **Not run** |
| WAN (RTT 285ms) hardware benchmark | **Done** (1 RT push, 2 RT pull; `specs/e2e_wan.md`) |
| pull round-trip reduction (batched `batch_get`) | **Implemented** (2 RTs for flat structure) |

---

## 6. Striping

Chunks can be distributed across multiple OSTs. **Default is 1 OST**; striping is used only when 2 or more are provided.

```python
# Default (1 OST)
builder = MerkleTreeBuilder(crypto, ost0)

# Striped (round-robin)
builder = MerkleTreeBuilder(crypto, ost0, stores={"ost0": c0, "ost1": c1})
```

| Item | Behavior |
|---|---|
| Assignment | Round-robin in `stores` order. With 1 store, always uses default |
| Placement metadata | Each entry in a directory chunk carries `store`. Omitted for the default OST (compatible with older readers) |
| Reading | Reads `store` from the entry and fetches from that OST. Root chunk is passed via `root_store` (default if omitted) |
| Deduplication | Index stores `plain_id -> (wire_id, store_id)`. Also reads legacy `str` format |

**Measured (local, 2 OSTs, 10 files)**: 6 chunks placed on OST0 and 5 on OST1, with no duplicates between them. A fresh reader without an index was able to restore the entire tree.

Regression tests are in `TestL3Striping` (1 OST default, 2 OST striping, restoration).
