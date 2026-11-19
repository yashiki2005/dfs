# Distributed Single-Writer `dfssvc` Deployment and Root Relay (`dfs-relay-v1`)

> **English** | [日本語](relay.ja.md)

## Rationale

`dfs` adopts a model where **each write boundary has a single writer and its own `dfssvc` (L2 registry + L3 OST)**. This allows each host to autonomously manage its own data, snapshots, and chunk storage, but in real deployments the following network constraints arise:

1. **Writer hosts such as a home Mac are behind NAT**
   - Outbound IPv4/IPv6 (especially HTTPS 443/tcp) works, but inbound connections from outside to the home host are blocked.
2. **Compute hosts such as RunPod / vast.ai restrict `scp` and inbound listening**
   - They also cannot be connected to directly from outside; only outbound HTTP/HTTPS connections work reliably.
3. **Actual data should remain on each host's `dfssvc`**
   - Rather than replicating and aggregating all data from all hosts onto the root host (`dfs.example.com`), each host's `dfssvc` should hold the authoritative source of actual data and state, and `dfs.example.com` should **only transparently relay encrypted L3 chunks and signed L2/L4 metadata**.
   - Because all chunks are AEAD-encrypted (`tree_secret`) on the writer device, the root relay cannot decrypt or tamper with the relayed traffic.

Based on this, we adopt a design where **the root `dfssvc` with public IPv4/IPv6 (`dfs.example.com`) hosts an HTTP/1.1 reverse relay hub (`RelayHub`), and each `dfssvc` behind NAT/FW connects outbound to expose the public path `/relay/<node_id>/...`**.

---

## Mechanism

```text
[Home Mac dfssvc (behind NAT)]                     [root: dfs.example.com (RelayHub)]                         [RunPod Client]
   127.0.0.1:19440                                       https://dfs.example.com
         ▲                                                         │                                                 │
         └── RelayAgent ──(outbound POST /_relay/pull)─────────────┤                                                 │
                          (outbound POST /_relay/reply)            ◀── POST /relay/mac1/v1/resolve ──────────────────┤
                                                                   ◀── POST /relay/mac1/v1/ost/batch_get ────────────┤
```

1. **Agent-side outbound connection (`RelayAgent`)**
   - A `dfssvc` behind NAT starts with `--relay https://dfs.example.com --relay-node mac1`.
   - Multiple workers (default 4) continuously hold long-polling connections on `POST /_relay/pull?node=mac1` (up to 25 seconds).
   - When a request arrives, it is forwarded to the local `dfssvc` (`127.0.0.1:<registry_port>`), and the response is sent back via `POST /_relay/reply?node=mac1&id=<req_id>`.
2. **Hub-side relaying (`/relay/<node_id>/...`) and Direct-first priority control**
   - Routing all traffic through the root relay `dfs.example.com` would overload it, so **when direct communication is possible, clients communicate directly with the target host's `dfssvc`, falling back to the relay only when direct communication fails (Direct-first, Relay-as-fallback)**.
   - In `/v1/ost`, `dfssvc` keeps the direct `endpoint` first while advertising `https://dfs.example.com/relay/<node_id>` in `alternates` / `relay_endpoint`.
   - Clients (`RemoteRegistryClient`, `FailoverOSTClient`, `DFSNode`, `dfscli share`) try the leading direct URL first, so on the same LAN or in reachable environments they never go through `dfs.example.com`. Only environments where direct connection fails due to NAT/FW (such as RunPod) automatically fall back to `/relay/<node_id>`.
3. **Binary frame format**
   - Responses to `/_relay/pull` and requests to `/_relay/reply` use the following binary frame to avoid Base64 bloat:
   - `[4-byte big-endian JSON header length] + [UTF-8 JSON header] + [raw body bytes]`
4. **Authentication (`X-DFS-Relay-Token`)**
   - When `--relay-token <secret>` (or environment variable `DFS_RELAY_TOKEN`) is configured on the hub, `/_relay/pull` and `/_relay/reply` are verified using a constant-time comparison of the `X-DFS-Relay-Token` header.

---

## Medium- to Large-Scale Operation (Distributed Relays via DNSSEC + Public Hosts)

- **Why any production public host can act as a relay**:
  - `dfs` L3 chunks are AEAD-encrypted on the writer device, and L2/L4 metadata is signed with Ed25519. Therefore, a relay node **can neither decrypt plaintext nor forge signed logs or delegations** (zero-trust relaying).
- **Secure distribution of relay fleets via DNSSEC**:
  - For small-scale operation, a single hub (`dfs.example.com`) + `--relay-token` is sufficient, but for medium- to large-scale operation, `dfssvc --enable-relay` can be run on **any host with public IPv4/IPv6 that requires no NAT and allows both inbound and outbound traffic**, and distributed as the relay fleet under that domain via DNSSEC-signed records.
- **Redundant connections to multiple relays**:
  - A `dfssvc` behind NAT can specify `--relay` multiple times to maintain simultaneous outbound connections to multiple public relays. Because the client tries **Direct-first → Relay 1 → Relay 2 ...** in order, both overload on a single hub (`dfs.example.com`) and a single point of failure are avoided.
