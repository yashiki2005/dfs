# Signed Candidacy Discovery for Small-Scale Deployments

> **English** | [日本語](discovery.ja.md)

## Rationale

Three options were evaluated for `dfs` registry discovery:

1. **Unconditional candidacy (first server to start becomes root / primary)**
   - Rejected because it cannot prevent spoofing or split-brain during network partitions.
2. **Majority quorum candidacy (majority consensus such as Raft)**
   - Rejected because in small setups (2–3 nodes), losing a single node loses the majority, making operational overhead and complexity disproportionate.
3. **DNSSEC-based discovery**
   - Requires public domain management, zone signing, and external resolver dependencies, which is too heavy in practice for private, closed-network, or small-scale distributed file systems.

Based on the above, **small-scale and private deployments adopt the "Signed Candidacy Model (`dfs-candidacy-v1`)"**.
When scaling to **medium or larger deployments** (distribution to unspecified clients under a public domain, discovery via external resolvers across multiple sites, etc.), migrate to DNSSEC discovery in [specs/dnssec.md](dnssec.md).

---

## Mechanism

1. **Sharing the root of trust (out-of-band on initial setup only)**
   - Clients are given `root_pubkey` (and candidate registry URLs) during invitation/configuration.
2. **Candidacy (announcement) and verification**
   - The administrator signs a `dfs-candidacy-v1` envelope with the `root` private key and registers it at `/v1/candidacy/announce` on each registry (or distributes it as a file).
   - Clients query `/v1/candidacy` on the candidate registries, verify the signature and expiration using their local `root_pubkey`, and adopt the candidacy with the **valid and highest `epoch` (`role_epoch`)**.
3. **Switching `primary`**
   - To switch `primary`, simply increment `epoch` by `+1` and re-sign; candidacies with an older `epoch` are rejected as rollbacks.

---

## Envelope Format (`dfs-candidacy-v1`)

The SSH signature namespace is `dfs-candidacy-v1`, and the identity is `root_anchor`.

```json
{
  "payload": {
    "epoch": 2,
    "expires_at": 1738281600,
    "issued_at": 1735689600,
    "registries": [
      {"role": "primary", "url": "http://192.0.2.60:9440"},
      {"role": "secondary", "url": "http://192.0.2.61:9440"}
    ],
    "root_anchor": "/example.com",
    "root_pubkey": "ssh-ed25519 AAAA...",
    "schema": "dfs-candidacy-v1"
  },
  "signature": "-----BEGIN SSH SIGNATURE-----\n..."
}
```

### Verification Rules
- `schema == "dfs-candidacy-v1"`
- `root_anchor` is normalized (matches `normalize_path`)
- `root_pubkey` matches the client's locally trusted `root_pubkey`
- `issued_at <= now < expires_at`
- `epoch >= 1` and at least the locally known `min_epoch`
- `registries` has no duplicate URLs and has exactly one `primary` (`http://` or `https://`)
- `ssh_verify(expected_root_pubkey, root_anchor, "dfs-candidacy-v1", canonical_json(payload), signature)` is true

---

## CLI / HTTP API

- `POST /v1/candidacy`: Returns the registered signed candidacy envelope.
- `POST /v1/candidacy/announce`: Verifies and stores `{"envelope": ...}`.
- `dfscli candidacy create`: Generates and signs a candidacy envelope, and distributes it via `--out` or `--announce`.
- `dfscli candidacy discover`: Fetches and verifies `/v1/candidacy` from candidate URLs, and displays the result with the highest `epoch`.
- `dfscli config create <name> --candidacy-url <url>... --root-pubkey <pub>`: Creates a remote definition from the candidacy model.
