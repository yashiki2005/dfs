# Security & Cryptography

**dfs** is designed around an untrusted-infrastructure threat model: storage nodes (L3 OST), locator registries (L2), and WebSocket relays may be observed, compromised, or replaced by an active attacker. Confidentiality and integrity are enforced end-to-end on clients.

---

## Threat Model

- **Untrusted Storage & Relays**: L3 OST servers and relays see only opaque `wire_id`s (64-hex hashes) and AEAD ciphertexts. They cannot read filenames, directory structures, or file contents without `tree_secret`.
- **Untrusted Network / MITM**:
  - L2 registry entries, L1 delegations, and L4 revision logs are cryptographically signed with Ed25519 keys.
  - Direct TLS OST connections verify the server certificate SHA-256 fingerprint (`ost_cert_sha256`) when pinned (or announced via L2 `/v1/ost` and matched against the selected endpoint).
- **No Silent Key Downgrades**: Strict verification requires a configured `root_pubkey` (via DNSSEC, explicit `--root-pubkey`, or explicit `--allow-tofu`), preventing silent acceptance of unauthenticated roots.

---

## Key Hierarchy

1. **Root Key (L0)**:
   - An Ed25519 SSH keypair representing the domain authority (e.g., `/example.com`).
   - Signs L1 delegation records (`dfs-delegation-v1`) and L2 locator records (`dfs-l2-locator-v1`).
   - Distributed via DNSSEC `_dfs.<domain>` TXT records, explicit `--root-pubkey` files, or explicit TOFU.
2. **Writer Key (L1/L4)**:
   - An Ed25519 SSH keypair authorized by an L1 delegation to write to a specific subtree (e.g., `/example.com/alice`).
   - Signs L4 log entries (`dfs-l4-log-v1`), archive descriptors (`dfs-archive-descriptor-v1`), and candidacy records (`dfs-candidacy-v1`).
3. **Tree Secret (`tree_secret`, L3/L4)**:
   - A shared secret held by writers and authorized readers of a subtree.
   - Never sent to L2 registries or L3 OST servers.
   - Used to derive `address_secret` and per-chunk encryption keys.
   - String secrets use the versioned `scrypt-v1` KDF. Configs, invites, and
     archives without an explicit KDF version retain the legacy SHA-256
     derivation so existing data remains readable.

---

## Convergent AEAD (`dfs/crypto.py`)

To achieve both client-side confidentiality and cross-client deduplication within the same subtree, `dfs` uses convergent encryption built from standard primitives:

- **Compression**: Plaintext payloads are compressed with Zstandard (`dfs/compression.py`) with bounded decompression guards.
- **Deterministic Plain ID**:
  - `plain_id = HMAC-SHA256(address_secret, b"dfs-plain-id-v1:" + plaintext)`
- **Deterministic Chunk Key**:
  - `chunk_key = HMAC-SHA256(tree_secret, b"dfs-chunk-key-v1:" + plain_id)`
- **Authenticated Encryption**:
  - `ChaCha20-Poly1305` (16-byte authentication tag) encrypts the compressed payload with header/AAD binding to prevent chunk substitution or tampering (`ChunkIntegrityError`).
- **Content Addressing**:
  - `wire_id = SHA-256(serialized_blob)` (64-character lowercase hex).
  - L3 OST servers verify `SHA-256(blob) == wire_id` on storage and clients verify both `wire_id` and AEAD integrity on retrieval.

---

## Signatures & Namespaces

Signatures use OpenSSH Ed25519 (`SSHSIG`) with explicit domain-separation namespaces:

| Namespace | Purpose |
|---|---|
| `dfs-delegation-v1` | L1 subtree delegation from root key to writer key (includes `epoch` for rotation/revocation) |
| `dfs-l2-locator-v1` | Signed L2 endpoint / locator announcement |
| `dfs-l4-log-v1` | L4 append-only revision entry (`seq`, root Merkle chunk, timestamp) |
| `dfs-archive-descriptor-v1` | Signed `dfscli archive` bundle descriptor |
| `dfs-candidacy-v1` | Signed candidacy record for small-scale failover/discovery |

- Verification supports both fast in-memory `cryptography` verification and `ssh-keygen -Y verify` fallback.
- Identities containing control characters (`\r`, `\n`, `\0`) are rejected to prevent `allowed_signers` injection, while legitimate subtree paths containing spaces are supported.

---

## Path Safety (`dfs/path_safety.py`, `dfs/crypto.py`)

- Path components are normalized to UTF-8 NFC.
- `..`, `.`, NUL bytes, path separators inside components, and Windows reserved device names (`CON`, `PRN`, `AUX`, `NUL`, `COM1`–`COM9`, `LPT1`–`LPT9`) are rejected.
- Local materialization and archive imports (`dfscli pull`, `dfscli import`) enforce strict containment checks so extracted files and symlinks cannot escape the target directory.

---

## Transport Pinning & Web Security

- **OST Certificate Pinning**: `matching_ost_cert_pin` matches `ost_cert_sha256` against the selected OST endpoint and clears stale pins when switching to an unrelated endpoint.
- **Web UI (`dfs/web.py`)**:
  - Supports token-based login, HttpOnly session cookies, and per-IP/global authentication rate limiting.
  - Read-only / scoped shares restrict access to the configured subtree.
