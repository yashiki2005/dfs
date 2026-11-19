# L1 Root / Registry Discovery via DNSSEC

> **English** | [日本語](dnssec.ja.md)

## Conclusion

DNSSEC is used for **distributing the root anchor public key and registry list**. It is not used for dynamic head tracking, CAS, or primary promotion decisions.

The "first server to start becomes the domain root" approach is not adopted.
`primary` / `secondary` roles are determined by the roles explicitly stated in the DNSSEC record or by the operator's static configuration. Starting first is not a basis for authority.

Even if the DNSSEC record becomes unavailable, clients can continue reading using the cached last-verified configuration. However, because record updates and expirations are subject to TTL, immediate registry failover must not depend on DNS.

## Record

Place a single JSON object in the `_dfs.<domain>` TXT record.

```json
{
  "schema": "dfs-discovery-v1",
  "domain": "example.com",
  "root_anchor": "/example.com",
  "root_pubkey": "ssh-ed25519 AAAA...",
  "registries": [
    {"url": "https://l2-a.example.com:9440", "role": "primary"},
    {"url": "https://l2-b.example.com:9440", "role": "secondary"}
  ],
  "epoch": 1,
  "ttl": 300
}
```

### Fields

| Field | Meaning |
|---|---|
| `schema` | Fixed to `dfs-discovery-v1` |
| `domain` | Domain managed by this record |
| `root_anchor` | Path of the L1 root (e.g., `/example.com`) |
| `root_pubkey` | OpenSSH public key of the L1 root |
| `registries` | One `primary` and zero or more `secondary` entries |
| `epoch` | Record generation; monotonically increasing |
| `ttl` | Guideline TTL for clients to consider adopting updates |

There must be exactly one `primary`. Multiple primaries or no primary are rejected.
URLs must be in `http(s)://host:port` format, and duplicates are rejected.

## Verification

1. Query `_dfs.<domain>` TXT with the EDNS0 DO bit set
2. Identify the signing zone from the TXT's RRSIG
3. Verify the DNSKEY / DS chain down to the signing zone on the client side, rooted at the IANA root trust anchor (DS for KSK-2017 / KSK-2024)
4. Verify the RRSIG of the TXT RRset
5. Validate the TXT JSON for schema, types, and required fields
6. Record `root_pubkey` as the trust root for `root_anchor`
7. Subsequent L1 delegation chains are verified using the existing root anchor verification

The AD (Authenticated Data) bit is not used in default verification. Only the legacy compatibility path with explicit `validate=False` trusts the AD bit from a validating resolver.
This legacy path is selected with `--dnssec-no-validate --dnssec-no-ad`. It is for diagnostics only and must not be used in normal operation.

## Roles of DNSSEC and L2/L3

- DNSSEC: root public key, initial registry list, `primary`/`secondary` roles
- L2 registry: delegation chains, locators, CAS / replication of L4 heads
- L3 OST: encrypted chunks; primary OST and read-replica OST

DNSSEC records are static discovery information and do not carry L4 heads.
Head updates are performed via signed logs in L2.

DNSSEC is **not required**. For initial deployments in closed networks, WireGuard, LANs, or small-scale deployments, use the "Signed Candidacy Model (`dfs-candidacy-v1`)" in [specs/discovery.md](discovery.md) or `dfscli config create --registry ... --root-pubkey ...`.
Migrate to DNSSEC when scaling beyond medium-sized deployments.
Even when DNSSEC is used, its role is limited to initial root/registry discovery.

## Failure Assumptions

We do not assume "the registry never goes down."

| Failure | Expected Behavior |
|---|---|
| DNSSEC / DNS outage | Use the last verified root key and registry list |
| `primary` registry outage | Reads fall back to `secondary`; writes fail |
| `secondary` registry outage | Continue reads and writes on `primary` |
| `primary` recovery | Fencing via `role_epoch` accepts writes only from writers after promotion |
| DNSSEC key compromise | Treat as domain authority compromise; rotate root key and registry list |

Making the first server to start the root is rejected because it causes split-brain during simultaneous startup, network partitions, and recovery.

## CLI

```bash
# Inspect discovery contents
dfscli discover example.com

# Fetch root key and primary/secondary from DNSSEC and register remote
dfscli config create scw \
  --dnssec-domain example.com \
  --key ~/.ssh/alice \
  --secret <tree_secret>

# Generate TXT JSON for a service managed by dfssvc
dfssvc dnssec scw --domain example.com
```

If `--registry` / `--registry-alternate` are also specified, an error is raised unless they match the DNSSEC contents. If `--root-pubkey` is also specified, it is rejected unless it matches the DNSSEC root public key.

## Limitations

- The root trust anchor is embedded in code. On an IANA KSK rollover, `ROOT_TRUST_ANCHOR_DS` must be updated
- Fencing upon `primary` promotion uses `role_epoch`. The old `primary` rejects writes from writers with a post-promotion `role_epoch`. However, writers on the old epoch can still write to the old `primary`, so writer configurations must be updated simultaneously
- Consider TXT record size, TTL, and propagation delay; do not pack too many registries into a single record
- DNSSEC does not perform liveness monitoring or automatic promotion of `primary`
- Updates to DNSSEC records must be protected by TSIG / dynamic update / zone management permissions

## Regression Tests

- `tests/test_dnssec.py`: validation of JSON schema, single primary, URLs, root key, and epoch
- `tests/test_dnssec.py`: `--dnssec-domain` CLI flag populates Remote with root key and primary/secondary
