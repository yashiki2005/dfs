# L1 Authority Delegation Specification (`specs/delegation.md`)

> **English** | [日本語](delegation.ja.md)

## 0. Purpose and Scope

This document defines the specification and verification rules for **L1 (Authority Delegation)** in `dfs`.
The role of L1 is to cryptographically prove and verify "which public key has write authority over which subtree (path)," closing the design by satisfying the following two points:

1. Authority delegation (and re-delegation) from parent to child can be verified unidirectionally as a chain of trust, similar to DNSSEC.
2. When key rotation or revocation occurs, it coordinates with L4 (append-only log) to reject rollbacks or forged appends signed by old keys.

**Implementation mapping**: `dfs/l1_delegation.py` (verification), `dfs/crypto.py` (canonicalization and signing), `tests/test_evil_suite.py::test_l1_delegation_invariants` (verification tests).

---

## 1. Data Format (Canonical JSON)

### 1.1 Payload (Signed Data)

The body (payload) of a delegation record is a single-line UTF-8 JSON object with keys sorted lexicographically (ASCII code order) and no extra whitespace (the output format of `dfs.crypto.canonical_json()`, including a trailing 1-byte LF).

```json
{"base_version":0,"epoch":1,"expires_at":1794436000,"issued_at":1762900000,"parent":"/example.com","path":"/example.com/alice","writer":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... alice@example.com"}
```

| Field | Type | Meaning |
|---|---|---|
| `parent` | string | Source subtree path of the delegation. Governed by the signing key (parent writer). |
| `path` | string | Target subtree path of the delegation. Must be directly under `parent` (prefix match). |
| `writer` | string | Public key of the delegated writer (single line, e.g. `ssh-ed25519 AAAA...`). Writers are identified by **key**, not by name. |
| `epoch` | int | Authority generation. When the parent signs a new generation, the writer for that subtree changes. `>= 1` and monotonically increasing. |
| `base_version` | int | L4 log version number handed over on writer rotation. See §3.2 below. |
| `issued_at` | int | Signing timestamp (UNIX seconds). |
| `expires_at` | int | Expiration timestamp (UNIX seconds). Must not exceed the parent's `expires_at`. |

**A path is a namespace identifier, not a stable file ID.** Identity across renames is handled by `file-id` in L4. L1 deals only with "who can write to this subtree."

### 1.2 Envelope (Signature Container)

The signature is not included in the payload. The envelope separates the payload and the signature.

```json
{
  "payload": { ... body from 1.1 ... },
  "signature": "-----BEGIN SSH SIGNATURE-----\n...\n-----END SSH SIGNATURE-----\n"
}
```

The signature uses OpenSSH detached signatures (SSHSIG) and must include the namespace `dfs-delegation-v1`. This prevents L1 signatures from being repurposed as L2 or L4 signatures.

---

## 2. Signing and Verification Procedure

1. Canonicalize the payload into normalized bytes using `canonical_json` (sorted keys, no whitespace, trailing LF).
2. Create a detached signature with the parent's private key using namespace `dfs-delegation-v1`.
3. During verification, verify the signature against the same canonicalized bytes using the **parent's public key**.

Signing uses `cryptography` (Ed25519) as the primary implementation, falling back to `ssh-keygen -Y sign` only for keys it cannot decrypt. Any `ssh-keygen` invocation must have a timeout (never hang indefinitely).

---

## 3. Verification Rules (5 Invariants)

A multi-hop delegation chain `[D_1, D_2, ..., D_n]` is verified sequentially from the root anchor. Each hop must satisfy the following:

### Invariant 1: Signature Validity
- Each hop's signature must verify against the previous hop's writer public key (or the root anchor public key for the root hop).
- Signatures over non-canonicalized payloads must be rejected (prevents forgery using normalization ambiguities).

### Invariant 2: Namespace Containment (Principle of Attenuation)
- `path` must be strictly under `parent` (`path` starts with `parent + "/"`).
- Paths must be pre-normalized (reject `..`, `//`, trailing slashes, NUL, and empty segments).
- A parent can only delegate a scope narrower than or equal to its own. **Authority only decreases toward children, never increases.**

### Invariant 3: Expiration Containment
- Current time `now` must fall within `[issued_at, expires_at)`.
- A child's `expires_at` must not exceed its parent's `expires_at`.
- This is also the principle of attenuation: a child cannot outlive its parent.

### Invariant 4: Monotonic Epoch Increase (Immediate Revocation)
- `epoch >= 1`.
- If a valid delegation already exists for the same `path`, the new `epoch` must be strictly greater than the current `epoch`.
- Once the epoch advances, appends to L4 signed under an earlier epoch are rejected (immediate revocation of old keys).

### Invariant 5: Chain Linkage
- The chain must be non-empty.
- The first hop's `parent` must match the root anchor's path.
- Each hop's `parent` must match the preceding hop's `path`.
- The root anchor (public key for `/example.com`) is verified via a separately defined trust anchor (DNSSEC, SSH CA, local trust anchor, etc.). **Never allow any hop in the chain to skip verification.**

---

## 3.2 Handover on Writer Rotation (`base_version`)

When rotating writers, the new writer resumes from the continuation of the predecessor's history. `base_version` guarantees this.

- The delegation record's `base_version` must match the **L4 log head version at the time of rotation**.
- L4 accepts only appends satisfying `version > base_version` (`dfs/l2_registry.py::announce_and_append`).
- Without this, a new writer could rewrite from version 1 and roll back history.

---

## 3.5 Root Anchor and Registry-Untrusted Verification

The root of trust in L1 is a single **root anchor public key**. As long as a client holds this locally, all subsequent delegations can be verified by following the chain from the root, **without needing to trust the registry (L2)**.

### 3.5.1 Why You Must Not Fetch It from the Registry

"Just ask the registry for the root public key" does not work. A malicious registry could return *its own (the attacker's) public key* as the root public key, and then construct a delegation chain rooted at itself that passes verification.

```text
If the registry returns the attacker's key as the root public key:
  Chain verification: passes (attacker can impersonate root)

If the correct root public key is provided externally:
  Chain verification: rejected (Invalid L1 delegation signature)
```

If you obtain the root of trust from the party being verified, it is not a root of trust. That is why the root public key is held locally.

### 3.5.2 Verification Procedure (Client Side)

1. The registry's `resolve` returns the leaf delegation together with the **entire chain** (from just below root to the leaf) and the **root anchor path** (`delegation_chain`).
2. The client calls `verify_delegation_chain` with its local root public key to verify all 5 invariants from root to leaf.
3. Only the **writer confirmed by verification** is used to verify the L4 head signature. Never use a writer merely claimed by the registry (otherwise forged delegations would pass).

### 3.5.3 Obtaining the Root Public Key (TOFU vs. Explicit)

| Scenario | Method |
|---|---|
| First time (local testing) | Fetch from the registry's `/v1/paths`, **display and record the fingerprint (TOFU)** |
| Production | Pin from the start via `--root-pubkey FILE` |
| Subsequent runs | Trust only the recorded public key. Reject if the registry returns a different value |

TOFU has the same strength as SSH `known_hosts` and is **vulnerable if redirected to an attacker on first contact**. It is convenient for local testing, but production deployments should specify `--root-pubkey` explicitly.

Fingerprints are displayed in the same `SHA256:<base64>` format as `ssh-keygen -lf` (for visual human comparison).

```text
  root アンカー: SHA256:n2ypRtbEq5vZOTK+i0WmBioSgHFEPFPCr21KWO7c4Jc （名簿から取得（TOFU））
                 これ以降この指紋だけを信頼します（違う値を返す名簿は拒否）
```

### 3.5.4 Where It Is Stored

The root public key is stored in the **remote definition** (`~/.config/dfs/remotes.json`) so that a single root can be shared across multiple remotes. A copy is also placed in the working directory's `dfs_config.json` (so the `dfs` CLI can read it via `--mount`).

### 3.5.5 Toward Node Discovery via DHT

If each node publishes its own signed delegation in the DHT, any discovered node's delegation can be verified back to the root using the **local root public key**. Nodes that fail verification are excluded as malicious nodes (never accessed).

**There is no need to query a root node every time.** The root public key alone is sufficient. Querying the root node would exclude all nodes unknown to the root, defeating the purpose of DHT (anyone can join) while introducing a single point of failure and unnecessary trust.

## 4. Revocation

Revocation is performed not by creating a separate "revoke delegation record," but by **having the parent sign a new generation**.

- The parent re-signs a delegation record with `epoch` incremented by 1. The new `writer` may be someone else or empty.
- Once the new epoch is registered, L4 appends signed by the old epoch's key are rejected.
- **Content already read in the past cannot be clawed back.** This is a fundamental property of cryptography and is accepted (same stance as `DESIGN.md` §6). Revocation protects subsequent writes.

Key rotation (when the same person moves to a new key) uses the exact same mechanism: the parent (or a higher authority of oneself) signs a delegation record with the new key as `writer`.

---

## 5. Test Cases and Expected Results

`tests/test_evil_suite.py::test_l1_delegation_invariants` verifies the following:

| Case | Description | Expected |
|---|---|---|
| (a) Valid delegation | Parent properly delegates to child | Verification succeeds; leaf `writer` is returned |
| (b) Forged delegation | `bob` impersonates parent and delegates to himself | **Rejected** at signature verification |
| (c) Expired | `now` is past `expires_at` | **Rejected** by Invariant 3 |
| (d) Re-delegation | Valid chain parent → child → grandchild | Verification succeeds |
| (e) Expiration overflow | Child's `expires_at` exceeds parent's | **Rejected** by Invariant 3 |

The acceptance criterion is **rejecting (b)(c)(e) and allowing (a)(d)**. If (b) cannot be rejected, the L1 design must be reworked.

---

## 6. Implementation Notes

- **`writer` is the full public key.** Key IDs (such as `SHA-256(pubkey)`) are used for display and indexing, while the delegation record itself holds the full key (`DESIGN.md` §5.2 policy).
- **Names (`user@domain`) are not verified by L1.** L1 guarantees only the binding between keys and subtrees. Name-to-key binding is handled separately via domain authority signatures or transparency logs (`DESIGN.md` §6.1).
- **Root anchor distribution**: Adopts fetching the root public key and registry list from the DNSSEC `_dfs.<domain>` TXT record. DNSSEC is limited to distributing the root key and is not used for dynamic head or primary promotion decisions. See `specs/dnssec.md` for details.
