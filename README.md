# dfs

[![CI](https://github.com/yashiki2005/dfs/actions/workflows/ci.yml/badge.svg)](https://github.com/yashiki2005/dfs/actions/workflows/ci.yml)

> **English** | [日本語](README.ja.md)

**Sync encrypted datasets to cloud GPUs in one line—without trusting the server, the relay, or the rented GPU with your master key.**

**dfs** is an end-to-end encrypted, deduplicated distributed file system with a single-writer trust model and an `rclone`-style CLI (`ls`, `copy`, `sync`, `pull`, `mount`). Every chunk is compressed, encrypted, and signed on your machine before leaving it.

> **Project status:** `0.1.x` is an experimental initial-release series. It has not
> undergone an independent security audit. Review the threat model before using
> it with valuable data.

---

## Why dfs? (Core Use Cases)

1. **One-Line Cloud GPU / Ephemeral Worker Sync (RunPod, Lambda, Colab)**
   - Stop `scp`-ing tarballs or leaving your personal SSH/S3 keys on rented GPUs.
   - Run `dfscli share mydata --write-path out` on your laptop to generate a one-line `curl | bash` bootstrap command (hosted on `raw.githubusercontent.com`, cloning and syncing via `uv`).
   - For NAT traversal, `dfs start` uses the `yashiki.top` relay hub by default (zero-trust: the relay never sees your keys or plaintext), and you can disable it with `--no-hub` or self-host your own hub on a VPS with `dfssvc start --hub ...`.
   - The GPU worker pulls the dataset read-only (over direct LAN/ICE, multi-seed libp2p/QUIC, or encrypted relay) and can only write results back to the delegated `out` subpath.
2. **Zero-Trust `rclone`-Style Sync Across Mac, Linux, and Windows**
   - Keep a home server / Raspberry Pi / VPS as an untrusted encrypted chunk store (`dfssvc start`) and sync from your laptop with `dfscli sync`, `dfscli pull`, or `dfscli mount`.
   - Storage servers and relays never see plaintext filenames, file contents, or keys.
3. **Verifiable Single-Writer Integrity (No Silent Rollbacks or Drops)**
   - Unlike naive object-store sync, every update is chained in a signed append-only log and Merkle tree. Clients automatically reject server-side version rollbacks (**B6**) and silent write drops (**B7**).

---

## Try It in 60 Seconds

```bash
# 0. One-line install (macOS / Linux)
curl -sSL https://raw.githubusercontent.com/yashiki2005/dfs/main/scripts/install.sh | bash
```

```powershell
# 0. One-line install (Windows PowerShell)
irm https://raw.githubusercontent.com/yashiki2005/dfs/main/scripts/install.ps1 | iex
```

```bash
# 1. Start a local server and auto-configure 'local' (or use ./cli from repo)
dfs start

# 2. Push, list, and pull back
dfs push ./dataset
dfs ls
dfs pull ./restored
```

---

## Key Features

- **End-to-End Encrypted & Deduplicated**: Files are chunked, compressed with Zstandard, and encrypted on the client using convergent ChaCha20-Poly1305 before leaving your machine.
- **Single-Writer Integrity**: Each subtree has one authorized writer key backed by a signed delegation chain from a domain root key. Every update is recorded in a signed append-only log and Merkle tree.
- **Familiar `rclone`-like CLI (`dfscli`)**: Manage remote trees with commands you already know—`ls`, `cat`, `copy`, `sync`, `pull`, `mv`, `rm`, `check`, and `mount` (FUSE / FUSE-T).
- **One-Command Local Service (`dfssvc`)**: Spin up a local registry and storage server in one command, inspect status, and export connection settings or DNSSEC records.
- **Easy Sharing & Web UI**:
  - `dfscli web`: Start a browser-accessible file sharing & Web CLI UI (great for phones or quick transfers).
  - `dfscli invite` / `dfscli share`: Generate read-only invite tokens or one-line `curl | bash` bootstrap scripts for ephemeral workers (e.g., RunPod).
- **NAT Traversal & Flexible Transport**: Connects directly over LAN/ICE when possible, supports multi-seed libp2p/QUIC chunk distribution out of the box (required core dependency due to ~4x multi-seed throughput gains in 512 MiB benchmarks), and falls back to an encrypted WebSocket/HTTP relay across strict NATs.
- **Archive & Offline Bundles**: Export/import portable `tar.gz` bundles (with optional PAR2 recovery blocks or BitTorrent metadata) via `dfscli archive` and `dfscli import`.
- **Copy-on-Write Snapshots**: Integrates with APFS (`clonefile`) on macOS and Btrfs subvolumes on Linux for fast local snapshots (`dfscli fs`).

---

## Requirements

- Python `3.11+`
- [OpenSSH](https://www.openssh.com/) (`ssh-keygen`) for Ed25519 key generation and signing
- [OpenSSL](https://github.com/openssl/openssl) (`openssl`) for TLS certificate generation
- Core Python libraries:
  - [cryptography](https://github.com/pyca/cryptography) (ChaCha20-Poly1305 AEAD, HKDF, scrypt, TLS/X.509)
  - [dnspython](https://github.com/rthalley/dnspython) (DNS / DNSSEC record lookup)
  - [py-libp2p](https://github.com/libp2p/py-libp2p) (QUIC/TCP P2P chunk distribution & DHT; promoted to a required dependency after multi-seed benchmarks showed ~4x speedup)
  - [python-zstandard](https://github.com/indygreg/python-zstandard) (Zstandard compression)
- Optional:
  - **FUSE mount (`dfscli mount`)**: [fusepy](https://github.com/fusepy/fusepy) + [macFUSE](https://github.com/macfuse/macfuse) / [FUSE-T](https://github.com/macos-fuse-t/fuse-t) (macOS) or [libfuse](https://github.com/libfuse/libfuse) (Linux)
  - [par2cmdline](https://github.com/Parchive/par2cmdline) (`par2`) for PAR2 parity in `dfscli archive`
  - [libqrencode](https://github.com/fukuchi/libqrencode) (`qrencode`) for terminal QR codes in `dfscli web`

---

## Quick Start

### 1. Install

Using [`uv`](https://docs.astral.sh/uv/) (recommended):

```bash
git clone https://github.com/yashiki2005/dfs.git dfs
cd dfs
uv sync
```

Or with `pip`:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

#### Prebuilt Python wheels

Each GitHub Release includes a platform-independent
`dfs-<version>-py3-none-any.whl` containing the complete `dfs` package,
CLI entry points, and localization data. It requires Python 3.11 or newer:

```bash
python -m pip install dfs-<version>-py3-none-any.whl
```

Third-party dependencies are resolved as usual for Python wheels. `dfs`
requires `fastecdsa==4.0.0` and overrides the stale transitive pin in
`py-libp2p 0.8.1`; this removes the former macOS GMP build requirement:

```bash
uv pip install \
  --overrides fastecdsa-overrides.txt \
  dfs-<version>-py3-none-any.whl
```

`py-libp2p 0.8.1` metadata still declares `fastecdsa==2.3.2`, which
conflicts with the DFS-required 4.0.0 pin. Plain `pip` therefore cannot
resolve the wheel until py-libp2p updates that declaration. Use the
override file shipped with the wheel with uv.

### 2. Start a Local Server (`dfssvc`)

```bash
# Start a local registry + encrypted object store (L2 + L3)
dfssvc start

# Check status and connection details
dfssvc status

# Print ready-to-run dfscli configuration command
dfssvc env
```

### 3. Configure a Remote & Sync Files (`dfscli`)

Run the `dfscli config create ...` command printed by `dfssvc env` (using the generated writer key and your chosen tree secret), or create a remote directly:

```bash
# List configured remotes
dfscli listremotes

# Copy local files or a directory to the remote
dfscli copy ./my-notes local:notes

# Sync a local directory to the remote
dfscli sync ./dataset local:dataset

# List remote files
dfscli ls local:dataset

# Pull remote files to another directory
dfscli pull local:dataset ./restored-dataset
```

### 4. Share with Another Machine or Browser

- **Web UI** (for phones or browsers):
  ```bash
  dfscli web local:
  ```
- **Read-only invite** (for a teammate or cloud GPU instance):
  ```bash
  dfscli invite create local:dataset
  # On the target machine:
  dfscli invite join <token>
  ```
- **Join a domain hub** (with optional relay / NAT traversal):
  ```bash
  dfscli join https://hub.example.com --name team --path /example.com/alice --key ~/.ssh/id_ed25519 --secret <tree_secret>
  ```

---

## Compression & Filesystem Behavior

### Compression (`auto`, `zstd`, `none`)
- **Transparent zstd Compression**: File chunks are compressed using Zstandard (level 10) on the client **before** AEAD encryption.
- **Deduplication Preserved**: Plaintext content identifiers (`plain_id`) are derived from uncompressed data, ensuring cross-version and cross-remote deduplication remains unaffected by compression state.
- **Smart Adaptive Thresholds (`auto`)**: Chunks smaller than 4 KB or those achieving less than a 5% size reduction (e.g., pre-compressed media like MP4, JPEG, ZIP) automatically bypass compression to avoid CPU and storage overhead.
- **Hierarchical Policy via xattr**: Set directory policies using `user.dfs.compression` (e.g. `xattr -w user.dfs.compression zstd ./src`), which children inherit automatically. Effective policies are preserved in signed manifests across machines.

### Filesystem & OS Differences (macOS vs. Linux / ext4)
- **Copy-on-Write (CoW) Snapshots**:
  - **macOS (APFS)**: Uses `clonefile(2)` for instant, zero-byte copy-on-write workspace snapshots.
  - **Linux (Btrfs / XFS / ZFS)**: Automatically probes and uses `ioctl(FICLONE)` for block-level reflinks.
  - **Linux (ext4)**: **Fully supported.** When CoW is unavailable on ext4, `dfs` automatically falls back to standard file copying (`CopyBackend`). All synchronization, encryption, and CLI features work 100% identically, with standard copying during snapshot staging.
  - **Windows (ReFS)**: Leverages `FSCTL_DUPLICATE_EXTENTS_TO_FILE` block cloning where supported.
- **FUSE Mount (`dfscli mount`)**:
  - **Linux**: Mounts directly via kernel FUSE ([libfuse](https://github.com/libfuse/libfuse), `libfuse.so`).
  - **macOS**: Probes and falls back in order: **[macFUSE](https://github.com/macfuse/macfuse) (FSKit backend)** → **[FUSE-T](https://github.com/macos-fuse-t/fuse-t)** (NFS/SMB loopback) → **[macFUSE](https://github.com/macfuse/macfuse) (legacy)**, selectable via `--backend`.
- **Extended Attributes (xattr)**:
  - **Linux**: Interacts through standard Linux `user.*` xattrs.
  - **macOS**: Preserves `user.*` as well as macOS-specific `com.apple.*` metadata attributes via native libc hooks.

---

## Command Overview

### `dfscli` (Client)

| Category | Commands |
|---|---|
| Remotes & Discovery | `listremotes`, `create`, `config`, `discover`, `join`, `quit`, `about` |
| File Operations | `ls`, `lsd`, `lsl`, `lsjson`, `size`, `cat`, `copy`, `copyto`, `mv`, `rm`, `rmdir`, `purge`, `mkdir`, `touch` |
| Sync & Mount | `sync`, `pull`, `check`, `mount`, `history`, `fs` |
| Sharing & Bundles | `web`, `invite`, `share`, `archive`, `import` |
| Server & Authority | `serve`, `delegate`, `promote`, `candidacy`, `libp2p-serve` |

### `dfssvc` (Local Service Manager)

| Command | Description |
|---|---|
| `dfssvc start` | Start a local L2 + L3 service (supports custom ports, paths, hub/relay join, `--foreground`) |
| `dfssvc stop` | Stop a running service cleanly |
| `dfssvc status` | Show running state, endpoints, and paths |
| `dfssvc list` | List all configured services |
| `dfssvc env` | Print `dfscli config create` command for the service |
| `dfssvc dnssec` | Generate `_dfs.<domain>` TXT record JSON for DNSSEC discovery |
| `dfssvc logs` | Tail service logs |

---

## Documentation

For technical details on the layered architecture, cryptography, protocols, and operations, see `docs/`:

- [Architecture Overview](docs/architecture.md) ([日本語](docs/architecture.ja.md)) — L0–L6 layered design, data flow, and module map
- [Security & Cryptography](docs/security-and-crypto.md) — Threat model, key hierarchy, Convergent AEAD (ChaCha20-Poly1305), SSH Ed25519 signatures, DNSSEC/TLS pinning/TOFU
- [Protocol & Operations](docs/protocol-and-operations.md) — L2 Registry HTTP API, L3 OST protocol & disk persistence, NAT traversal/relay, `dfssvc`, archive bundles, and Web UI

Additional component-level specifications are available in [`specs/`](specs/).

---

## Running Tests

```bash
uv run --extra test pytest -q
```

---

## Project Policies

- [Security policy](SECURITY.md)
- [Contributing](CONTRIBUTING.md)
- [Changelog](CHANGELOG.md)

## License

Released under the [MIT License](LICENSE).
