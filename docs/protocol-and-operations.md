# Protocol & Operations

> **English** | [日本語](protocol-and-operations.ja.md)

This guide covers the runtime protocols, transport selection, service management (`dfssvc`), and operational workflows in **dfs**.

---

## L2 Registry & L3 OST Protocols

### L2 Registry (HTTP)

The L2 registry (`dfs/cli.py`, `dfs/l2_registry.py`) exposes HTTP endpoints for coordination and discovery:

- `GET /v1/paths` / `POST /v1/paths`: Query or publish signed L4 heads and L1 delegation records for subtrees.
- `GET /v1/ost`: Discover the active L3 OST endpoint and optional TLS certificate SHA-256 fingerprint (`cert_sha256`).
- `GET /_ice/candidates`: Advertise direct host / server-reflexive / relay candidates for NAT traversal.
- `POST /v1/ost/batch-has`, `POST /v1/ost/batch-get`, `POST /v1/ost/batch-put`: HTTP/relay batch object-store endpoints.

### L3 OST (TLS Binary Protocol & Disk Persistence)

- **TLS Framing (`dfs/l3_ost_adapter.py`)**:
  - Uses explicit framing opcodes (`H` = batch HAS, `G` = batch GET, `P` = batch PUT, `B`/`M`/`F` = streaming/metadata ops, `Q` = explicit quit frame to prevent recv deadlocks).
  - Bounded frame sizes (`MAX_BATCH_ITEMS = 65,536`, `MAX_BLOB_BYTES = 256 MiB`) and chunked client batching (`CLIENT_BATCH_ITEMS = 1024`, `CLIENT_BATCH_BYTES = 64 MiB`).
- **Disk Persistence & Quota**:
  - Chunks are persisted on disk as `.blk` files via atomic write + `fsync` (including parent directory `fsync`).
  - Both TLS and HTTP/relay OST handlers share the same `_has_chunk` / `_get_chunk` / `_put_chunk` path, enforcing `DFS_OST_MAX_BYTES` consistently across transports.

---

## Transport Selection & NAT Traversal

When connecting to a remote (`dfs/remotes.py`, `dfs/relay.py`):

1. **Direct LAN / ICE**: `dfscli join` and `dfscli discover` query `/_ice/candidates` and prefer direct reachable endpoints when available.
2. **Encrypted WebSocket Relay**: When peers sit behind NAT, traffic routes through a hub relay (`/relay/...`) while preserving end-to-end encryption and signatures.
3. **Optional libp2p / QUIC (`dfs/libp2p_chunk.py`)**: `dfscli libp2p-serve` serves OST chunks over libp2p/QUIC for peer-to-peer distribution.

---

## Service Management (`dfssvc`)

`dfssvc` (`dfs/svc.py`) manages local L2 + L3 server instances under `$DFS_HOME/dfssvc/<name>` (defaulting to `~/.dfs` or platform data dir):

- **Service Naming**: Names must match `^[A-Za-z0-9][A-Za-z0-9_.-]*$`.
- **Restart Preservation**: Stopping and restarting (`dfssvc stop <name>` → `dfssvc start <name>`, or `--force`) preserves previously resolved ports, state/OST directories, keys, `root_anchor`, `sub_path`, and hub/relay settings unless explicitly overridden on the CLI.
- **Foreground & Background Modes**: Both `dfssvc start` and `dfssvc start --foreground` wait for L2 readiness, register L1 delegations (unless `--no-delegate`), and persist service metadata in `services.json`.
- **DNSSEC Record Generation**: `dfssvc dnssec` outputs the JSON payload to publish in a `_dfs.<domain>` DNS TXT record so clients can verify root keys and discover endpoints via `dfscli discover`.

---

## Operational Workflows

### Failover & Promotion

If a primary registry goes offline, a standby replica state can be promoted with:

```bash
dfscli promote ...
```

### Archive Bundles & Offline Transfer

Export a verified snapshot as a portable `tar.gz` bundle (optionally with PAR2 recovery blocks or BitTorrent metadata) and import it elsewhere:

```bash
dfscli archive create local:dataset -o dataset-bundle.tar.gz
dfscli import dataset-bundle.tar.gz remote:dataset
```

### Ephemeral Workers (RunPod / Cloud GPUs)

Generate a scoped read-only invite token or a one-line bootstrap script:

```bash
dfscli invite create local:dataset
dfscli share local:dataset
```

### Browser Access (`dfscli web`)

Launch a local or LAN-accessible Web UI for browsing, uploading, downloading, and running Web CLI commands:

```bash
dfscli web local: --host 0.0.0.0 --port 8080
```
