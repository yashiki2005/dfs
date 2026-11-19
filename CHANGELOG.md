# Changelog

> **English** | [日本語](CHANGELOG.ja.md)

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.1.0] - 2026-11-15

Initial public release.

### Added

- Distributed file system using single-writer signed delegation, append-only logs, and Merkle trees
- CLI via `dfscli` including `copy`, `sync`, `pull`, `ls`, `cat`, `archive`, and more
- Local operation of L2 registry and L3 chunk store via `dfssvc`
- Chunk encryption with ChaCha20-Poly1305, Zstandard compression, and content-addressed deduplication
- FUSE / macFUSE / FUSE-T mounting
- Root public key distribution via DNSSEC and TOFU, verified locators, and read replication
- NAT traversal via ICE, libp2p QUIC, and direct-first relay
- Read-only invites, output-only ephemeral keys, and Web UI
- Archives with PAR2, BitTorrent metadata, and `zstd:chunked` archives
- CI and release builds for macOS, Linux, and Windows

### Security

- Verification of root, delegations, logs, and archive descriptors via Ed25519 signatures
- Rejection of path traversal, symlink escape, and dangerous archive members
- Versioned `scrypt-v1` KDF for new remotes
- Backward-compatible loading of existing remotes, invites, and archives without a KDF identifier
- History retention and replication verification during delegation epoch rotation
- Web UI token authentication, session cookies, and rate-limited login attempts

### Known limitations

- No independent third-party security audit has been performed
- Writes assume a single writer; multi-master writes are not supported
- Invite tokens must be strictly protected as Bearer credentials containing `tree_secret`
- Exposing L2/L3 directly to the public internet requires a firewall, rate limiting, and storage quotas

[Unreleased]: https://github.com/yashiki2005/dfs/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/yashiki2005/dfs/releases/tag/v0.1.0
