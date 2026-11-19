# Transport Evolution and "Best-of-All-Worlds" Swarm Design

> **English** | [日本語](transport_history.ja.md)

## 1. Background and History

1. **TLS/TCP custom frames (`OSTClient` / `ChunkStoreServer`)**
   - Achieves high throughput with minimal overhead and explicit disconnect (`QUIT_FRAME`).
   - However, it cannot connect directly behind `443/tcp` HTTP proxies or CDNs.
2. **Switching `libp2p` from TCP to QUIC ([dfs/libp2p_chunk.py](../dfs/libp2p_chunk.py))**
   - The `py-libp2p` TCP path initially tested had unstable connections and multiplexing and failed, so it was switched to **QUIC (`/udp/.../quic-v1`)**.
   - It works as an auxiliary read `ChunkSource`, but `py-libp2p` + `trio` is a heavy dependency, and UDP (QUIC) can be restricted in cloud GPU containers such as RunPod.
3. **BitTorrent archive ([dfs/archive.py](../dfs/archive.py))**
   - Effective for distributing huge datasets of fixed versions, but UDP/DHT/inbound listening ports do not play well with restricted environments, and it is not suited for small incremental updates.
4. **HTTPS OST + Direct-first HTTP relay ([dfs/l3_ost_adapter.py](../dfs/l3_ost_adapter.py), [dfs/relay.py](../dfs/relay.py))**
   - Reliably traverses `443/tcp` using only the Python standard library, and avoids the relay (`dfs.example.com`) whenever direct communication is possible.

---

## 2. "Best-of-All-Worlds" (`SwarmOSTClient`) Policy

Combine only the strengths of the three approaches without introducing heavy external dependencies (such as making `libtorrent` mandatory):

- **Best of BitTorrent (multi-peer parallelism and partial completion)**:
  - When multiple read candidates exist (direct OST, replica OST, `libp2p/QUIC` peers), instead of concentrating on a single node, check availability with `batch_has` and **fetch chunks in parallel round-robin across peers**.
  - Even if one peer is missing some chunks, only the missing ones can be filled in from another peer.
- **Best of `libp2p` (optional P2P/QUIC peers)**:
  - In environments where `dfs[libp2p]` is installed, `Libp2pChunkClient` can also participate directly in the Swarm pool.
- **Best of HTTPS / HTTP relay (reliable last resort)**:
  - Separate `/relay/` endpoints into a **fallback tier (Relay Tier)** so that only chunks that could not be fetched from any direct peer, replica peer, or QUIC peer are retrieved via the relay.
  - This keeps load on the public relay (`dfs.example.com`) low while guaranteeing completion even in restricted environments.
