# BitTorrent archive

> **English** | [日本語](bittorrent.ja.md)

## Role

BitTorrent does not replace the dfs hot path. It is used as a **per-version read-only archive** and as a last-resort recovery path when the OST / registry are completely lost.

- Primary OST: writes and normal reads
- Replica OST: read availability
- BitTorrent archive: long-term retention of past versions and last-resort recovery

BitTorrent does not guarantee the latest version. Only versions whose infohash and bundle are known can be restored.

## Bundle

`dfscli archive create` creates the following directory for the current head version:

```text
<bundle>/
  meta.json
  chunks/<wire_id>
```

`meta.json` stores:

- Subtree path, version number
- Root `plain_id` / `wire_id`
- Verified delegation chain
- Signed locator and head log
- Root public key
- List of included chunks (`wire_id`, `plain_id`, `size`)

Chunks are stored as encrypted blobs. Plaintext paths and filenames are never used as filenames in the bundle.

## Torrent

Generates `<bundle>.torrent`. The current implementation uses BitTorrent v1 file mode.

- Bundles `meta.json` and `chunks/*` into a single torrent
- Piece length is 256 KiB
- The torrent infohash is SHA-1 (v1)
- Authenticity of the chunks themselves is re-verified using the DFS `wire_id` (SHA-256)

SHA-1 in v1 is only for BitTorrent transport and is not used for DFS's final integrity verification. Migrating to BitTorrent v2 is future work.

## Creation, Verification, and Restoration

```bash
# Archive the current head version
dfscli archive create scw: --out ./scw-v1

# Archive a specific past version
dfscli archive create scw: --version 3 --out ./scw-v3

# Verify bundle signatures, chunk hashes, and sizes
dfscli archive verify ./scw-v1

# Restore locally (requires tree_secret)
dfscli archive extract ./scw-v1 ./restored

# List archives from descriptors
dfscli archive catalog .
```

`archive create` displays the torrent's infohash and magnet link. With `--publish`, it registers a writer-signed archive descriptor in L2. The descriptor binds the path, version, infohash, L4 entry hash, and root wire ID together.

```bash
# Create and publish to L2 simultaneously
dfscli archive create scw: --version 3 --out ./scw-v3 --publish

# Publish an already-created bundle
dfscli --remote scw archive publish ./scw-v3

# Fetch descriptor from L2, download via external BT CLI DHT/tracker, then verify and decrypt
dfscli archive fetch scw: --version 3 \
  --out ./downloads --secret <tree_secret> ./restored
```

Actual peer discovery and downloading use `aria2c` or `transmission-cli`.
`archive fetch` auto-detects both and uses standard DHT/tracker functionality.
DFS does not implement its own DHT or peer exchange.

`archive create --version N` fetches the signed head for the specified version from L4 history in L2.
For past versions, the current locator is not reused; the bundle is created without a locator. `meta.json` in the bundle contains the selected version's head / delegation.

## Restoration Conditions

A past version can be restored only when all of the following are satisfied:

- A seeder exists that holds the complete bundle for that version
- The infohash / torrent for that version is known
- The L1/L2/L4 signatures in `meta.json` can be verified
- The SHA-256 of all chunks matches
- `tree_secret` is available

"As long as at least one seeder exists" requires that the seeder holds the complete bundle and is reachable. It is positioned as a best-effort archive, not an availability guarantee.

## Security and Operations

- BitTorrent exposes IP addresses and swarm information. Consider private trackers, authenticated swarms, or alternative transports
- Once distributed, a torrent cannot be deleted. Revocation is handled by rotating `tree_secret`
- Distribute the mapping between infohash and bundle together with signed metadata
- Turning many small versions into separate torrents incurs high overhead. Group by version or by a fixed time interval
- When no tracker is available, use DHT or manual peer configuration. DHT does not guarantee seeder presence
- DHT only provides peer candidates for a known infohash and must not be used to determine the latest version
- Descriptors can be fetched from L2, but always verify the writer signature and binding to the L4 head

## Limitations

- Infohash distribution relies primarily on L2 signed descriptors. Integration of archive descriptors into L4 is not yet implemented
- Torrents are v1. v2, erasure coding, and k-of-n recovery are not yet implemented
- Automatic bundle retention / garbage collection is not yet implemented

## Regression Tests

- `tests/test_archive.py`: bundle creation, signature verification, chunk tampering detection, restoration
- `tests/test_archive.py`: `archive verify` CLI
