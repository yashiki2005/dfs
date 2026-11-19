# libp2p P2P Integration Design

> **English** | [日本語](libp2p-p2p-design.ja.md)

**dfs** positions `libp2p` as a **mandatory (standard dependency) and highest-priority P2P read transport and peer discovery layer**.

### Background on Making It Mandatory
Originally positioned as an optional dependency, a **512 MiB real-world benchmark** using multi-seed parallel retrieval (Endgame racing, Rarest-First, dynamic batch sizing, multi-stream, etc.) demonstrated an **approximately 4x speedup**, going from 1 seed (`1.36 MiB/s`, 327/512 chunks in 240 seconds) to 2-seed distributed retrieval (`5.39 MiB/s` on Pi5, completing all 512/512 chunks in 94.92 seconds). Based on these results, `libp2p` was promoted to a required dependency in `pyproject.toml` / `requirements.txt` so that every node reliably benefits from P2P distributed transfer.

As a safety net for strict networks where UDP/QUIC is blocked, when `DFS_LIBP2P=0` is specified, or upon connection drops, the transparent fallback mechanism to the `TLS/TCP + HTTP + ICE + RelayHub` path is still maintained.

---

## Core Principles (Three Pillars)

### 1. Peer Discovery: Kademlia DHT First + Existing Hub Fallback
- In environments where `libp2p` (`KadDHT`) is available, **Kademlia DHT** is enabled from startup.
  - `root dfs` / `domain dfs` (`dfssvc`) operate in `DHTMode.SERVER`, while regular nodes (`DFSNode`) operate in `DHTMode.CLIENT`.
  - A deterministic CIDv1 (`domain_cid("dfs:domain:<key>")`) is generated from the domain identifier (`root_pubkey` or `sub_path`), and peers in the same domain are discovered via `provide_domain()` / `find_domain_providers()`.
- If peers cannot be found or reached via DHT, it automatically falls back to the existing HTTP hub (`/_p2p/peers` and `/_ice/candidates`) to fetch the candidate list.

### 2. NAT Traversal & Data Transfer: Circuit Relay v2 / DCUtR First + RelayHub Fallback
- When connecting over `libp2p`, **direct connections (QUIC / TCP)** are attempted with highest priority; if those fail, **Circuit Relay v2 (`/p2p-circuit/p2p/<target_peer_id>`) and DCUtR (Direct Connection Upgrade through Relay)** are used with priority.
  - A `dfssvc` hub with `enable_relay=True` serves as the hop relay via `CircuitV2Protocol(..., allow_hop=True)`.
- When neither a direct `libp2p` connection nor Circuit Relay v2 / DCUtR can be established, or when `libp2p` itself is not installed, it falls back to the existing `RelayHub` (HTTP reverse relay `/relay/<node_id>`).
- Note that `/dfs/chunk/1.0.0` over `libp2p` is **read-only (`H`: batch inventory check / `G`: batch fetch)**; writes (chunk PUTs from a single writer / L4 publishing) continue to use the TLS/HTTP/RelayHub path.

### 3. Zero-Config Authorization: Per-Domain `PeerID` Allowlist
- Each `root dfs` / `domain dfs` hub (`RelayHub`) maintains an **authorized `PeerID` list (allowlist)**.
- During `join` / `announce` / `pull`, nodes automatically register their own `PeerID` and multiaddrs to `/_p2p/peers` or `/_ice/announce`, and simultaneously fetch the domain's allowlist to sync it to their local `Libp2pHostManager` (protected by `X-DFS-Relay-Token` when `DFS_RELAY_TOKEN` is set).
- The stream handler for `/dfs/chunk/1.0.0` verifies the incoming `stream.muxed_conn.peer_id` and immediately rejects requests from any `PeerID` not in the allowlist by calling `reset()` / `close()`.
- Upon revocation or departure, `POST /_p2p/peers/revoke` removes the peer from the hub's allowlist, and the `on_allowlist_change` callback immediately reflects the change in the server-side allowlist.

---

## Execution Architecture & Load Balancing

### Persistent Trio Host & Connection Reuse (`Libp2pHostManager`)
- Because `py-libp2p` runs on Trio, recreating the event loop and host per batch from synchronous code (`SwarmOSTClient` / `DFSNode` / `dfssvc`) would incur excessive QUIC handshake overhead.
- `Libp2pHostManager` **maintains a Trio event loop and a single `Host` on a single persistent background thread**, bridging synchronous calls via `trio.from_thread.run`. Existing connections to a `PeerID` are reused from `host.get_network().connections`.

### Per-Peer Adapter & Proportional Parallel Load Balancing (`Libp2pPeerClient` + `SwarmOSTClient`)
- A `Libp2pPeerClient` (`endpoint_uri = "libp2p://<peer_id>"`) is created for each discovered libp2p peer and registered with `SwarmOSTClient`.
- `SwarmOSTClient` treats `libp2p` peers and `TLS/HTTP/Relay` peers uniformly without distinction, measuring RTT and EWMA observed throughput, and balances load via weighted proportional parallel retrieval (initial batch assignment + work stealing).

---

## Fallback & Environment Compatibility

| Component | When `libp2p` is available | When `libp2p` is not installed / disabled (`DFS_LIBP2P=0`) |
|---|---|---|
| **Peer Discovery** | `KadDHT` first → `/_p2p/peers`, `/_ice/candidates` | `/_ice/candidates` only (`type == "libp2p"` is ignored) |
| **NAT Traversal** | Direct QUIC/TCP → `CircuitV2` + `DCUtR` → `RelayHub` | `RelayHub` (HTTP reverse relay) |
| **Chunk Retrieval** | Proportional parallel across `Libp2pPeerClient` + `TLS/HTTP` | Proportional parallel across `TLS/HTTP` + `RelayHub` |
| **Authorization** | Domain `PeerID` allowlist + `X-DFS-Relay-Token` | TLS certificate pinning + `X-DFS-Relay-Token` |
