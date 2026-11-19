# libp2p/QUIC chunk source

> **English** | [日本語](libp2p.ja.md)

## Positioning

libp2p does not replace OST. It is used as a **read-only additional ChunkSource**
following the existing primary OST and replica OST.

- Primary OST: writes and normal reads
- Replica OST: read availability
- libp2p/QUIC: fetch only the required chunks from peers
- BitTorrent: per-version long-term archive

libp2p is neither HTTP-only nor QUIC-only, but dfs uses the **QUIC transport**.
TCP is not used because custom streams between separate processes did not work in this environment.

## Protocol

```text
/dfs/chunk/1.0.0

request    = op(1) + count(4, BE) + wire_id[count](64 bytes)
H response = "O" + flags[count](1 byte each)
G response = "O" + (length(4, BE) + blob)[count]
```

`wire_id` is SHA-256. The client must always re-verify the SHA-256 of every fetched blob.
There is no write op.

## Server

The py-libp2p host runs in a per-process Trio loop. Rather than sharing threads with
`dfs serve`, it is launched as a dedicated process.

```bash
dfscli libp2p-serve \
  --chunks-dir ~/.dfs_server/ost_chunks \
  --listen /ip4/0.0.0.0/udp/0/quic-v1
```

On startup, it prints `peer: /ip4/.../udp/.../quic-v1/p2p/...`. Pass this multiaddr
to `--libp2p-peer` on the reader side.

`--chunks-dir` reads `<wire_id>.blk` files saved by `PersistentRegistryState.save_ost_chunks`.
Because it does not directly share the in-memory state of OST, only chunks persisted after
the most recent announce are available.

## Client

```bash
dfscli create scw \
  --registry http://primary:9440 \
  --libp2p-peer /ip4/203.0.113.10/udp/19443/quic-v1/p2p/12D3KooW...
```

The read candidates for `DFSNode` are tried in the following order:

1. Primary OST
2. Replica OST
3. libp2p peer

Even if all OST endpoints in the locator are down, `cat` / `pull` can continue as long as
a libp2p peer has the chunks. Writes still go to the primary OST.

## Private Swarm

When `--libp2p-psk` is set on both server and client, a pre-shared key for a private swarm
is passed to the libp2p host. The PSK is treated as a secret inside the configuration file.

## Limitations

- Peer discovery is still statically configured. Kademlia provider records / mDNS are not implemented.
- The libp2p server is an independent process. Automatic startup from `dfs serve` is not implemented.
- The server reads from the chunk directory. Serving directly from an in-memory OST would require IPC.
- Requires operating QUIC UDP ports, NAT, firewalls, and relays.
- libp2p itself does not provide retention or seeding incentives.
- Writes, CAS, and L4 consistency remain the responsibility of OST / L2 / L4 as before.

## Regression Tests

- `tests/test_libp2p_chunk.py`: HAS / GET from a separate-process QUIC server
- `tests/test_libp2p_chunk.py`: rejection of missing chunks, verification of read-only behavior
