# Architecture Overview

> **English** | [日本語](architecture.ja.md)

**dfs** separates trust, discovery, encrypted chunk storage, filesystem state, and user interfaces into clean layers (**L0–L6**). Each layer has a narrow responsibility and relies only on cryptographic proofs or explicitly configured trust anchors from the layers below.

---

## Layered Stack

| Layer | Name | Primary Modules | Responsibility |
|---|---|---|---|
| **L0** | Root Trust & Discovery | `dfs/dnssec.py`, `dfs/discovery.py` | Domain root identity (`_dfs.<domain>` DNSSEC TXT), explicit root public keys, and endpoint discovery |
| **L1** | Authority & Delegation | `dfs/l1_delegation.py` | Signed delegation records granting one writer key authority over a subtree (with epoch & revocation) |
| **L2** | Signed Locator Registry | `dfs/l2_registry.py`, `dfs/l2_cache.py` | HTTP registry tracking subtree heads, sequence numbers, signed locator updates, and available OST endpoints |
| **L3** | Convergent AEAD Object Store (OST) | `dfs/l3_ost_adapter.py`, `dfs/l3_store.py`, `dfs/crypto.py`, `dfs/compression.py` | Content-addressed encrypted chunk store over TLS binary frames, HTTP/relay, or libp2p/QUIC |
| **L4** | Single-Writer Log & Merkle Tree | `dfs/l4_log.py` | Signed append-only revision log, directory/file Merkle snapshots, monotonic sequence verification |
| **L5** | Local Workspace & Snapshot Adapter | `dfs/l5_fs.py`, `dfs/fs/` | Syncing between L4 trees and local workspaces using CoW snapshots (APFS `clonefile` / Linux Btrfs) or fallback copies |
| **L6** | User Interfaces & Bundles | `dfs/cli_main.py`, `dfs/commands/`, `dfs/svc.py`, `dfs/web.py`, `dfs/fuse_mount.py`, `dfs/archive.py`, `dfs/invite.py` | `rclone`-style CLI (`dfscli`), service manager (`dfssvc`), Web UI, FUSE mount, invite tokens, and `tar.gz`/PAR2/BitTorrent bundles |

---

## Data Flow

### Write / Push Path

```text
Local work tree (L5)
  │
  ├─► Chunking + Zstandard compression + Convergent AEAD (ChaCha20-Poly1305)
  │     └─► Batch HAS / PUT encrypted blobs to L3 OST (TLS / HTTP / Relay)
  │
  ├─► Build Merkle directory & file manifest, sign L4 log entry (writer Ed25519 key)
  │
  └─► Publish signed head + L1 delegation chain to L2 Registry (POST /v1/paths)
```

1. **Chunking & Encryption (`L3` + `L4`)**: Files are split into chunks, compressed with Zstandard, and encrypted client-side with `ChaCha20-Poly1305` using keys derived via `HMAC-SHA256` from `tree_secret`.
2. **Blob Upload (`L3`)**: Only missing `wire_id`s (determined via batch `HAS`) are uploaded with batch `PUT` to L3 OST.
3. **Log Commit (`L4` → `L2`)**: A new L4 revision entry referencing the root Merkle chunk and monotonically increasing `seq` is signed by the writer key (`dfs-l4-log-v1`) and published to the L2 registry along with its L1 delegation (`dfs-delegation-v1`).

### Read / Pull Path

```text
L2 Registry (GET /v1/paths, /v1/ost)
  │
  ├─► Verify root trust (L0 DNSSEC / pinned root_pubkey / explicit TOFU)
  ├─► Verify L1 delegation chain & L4 writer signature + monotonic seq
  │
  ├─► Fetch Merkle tree & file chunks from L3 OST (TLS / HTTP / Relay / libp2p)
  │
  └─► Verify AEAD tag & plain_id, decompress, materialize to L5 workspace (CoW snapshot)
```

1. **Trust & Log Verification**: Readers verify the L2 response against the configured `root_pubkey` (or DNSSEC / explicit TOFU), validate the L1 delegation for the target subtree, and verify the L4 entry signature and sequence number.
2. **Blob Retrieval & Decryption**: Required chunks are fetched in batches from L3 OST (or local cache / archive / libp2p peer), decrypted with `tree_secret`, and verified against their `plain_id` / `wire_id` and AEAD authentication tags.
3. **Workspace Materialization (`L5`)**: Verified files are written into a staging snapshot and atomically switched into the local working tree.

---

## Module Map

- **Core Cryptography & Safety**:
  - `dfs/crypto.py`: UTF-8 NFC path normalization, SSH Ed25519 signing/verification, `ConvergentAEAD`
  - `dfs/path_safety.py`: Path traversal and symlink escape protection for local restores and archive imports
  - `dfs/compression.py`: Zstandard framing and decompression size guards
- **Control & Data Plane**:
  - `dfs/l1_delegation.py`: Delegation records (`dfs-delegation-v1`) and epoch checks
  - `dfs/l2_registry.py`, `dfs/l2_cache.py`: Registry state, signed locator records, failover/promotion
  - `dfs/l3_ost_adapter.py`: TLS framing (`H`, `G`, `P`, `B`, `M`, `F`, `Q`), disk chunk store (`.blk`), `DFS_OST_MAX_BYTES` quota, HTTP/relay batch adapters
  - `dfs/l4_log.py`: `L4LogClient`, `L4Manifest`, directory/file tree traversal, diff/sync
  - `dfs/l5_fs.py`, `dfs/fs/`: `DFSNode`, `ClayFS` CoW adapters
- **Networking & Sharing**:
  - `dfs/relay.py`: WebSocket-like HTTP upgrade relay and ICE candidate discovery (`/_ice/candidates`)
  - `dfs/libp2p_chunk.py`: Optional libp2p/QUIC chunk server and client
  - `dfs/invite.py`: Read-only Base64 invite tokens and bootstrap scripts
  - `dfs/web.py`: Browser file manager, upload/download, and Web CLI with session auth & rate limiting
- **CLI & Service**:
  - `dfs/cli.py`: `dfs serve`, HTTP registry handler, OST + relay endpoint hosting
  - `dfs/cli_main.py` & `dfs/commands/`: `dfscli` command router and remote config store (`dfs/remotes.py`)
  - `dfs/svc.py`: `dfssvc` lifecycle manager (`start`, `stop`, `status`, `list`, `env`, `dnssec`, `logs`)
  - `dfs/archive.py`: `tar.gz` bundle export/import, PAR2 parity, BitTorrent descriptor support
