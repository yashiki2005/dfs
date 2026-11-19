# dfs Design Notes

> **English** | [日本語](DESIGN.ja.md)

## 0. Role of This Document

This document records the 2026-11-11 discussion (evaluation of the `dfs` prototypes → feasibility of a global distributed file system → design proposal) as material for thinking through `dfs`. It is a pre-implementation design memo, not a final decision.

---

## 1. What Actually Happened in Previous Prototypes

### 1.1 The `dfs` Family (`~/dfs`, `dfs2`, `dfs3`, `src/dfs4`, `src/dfs`)

An educational encrypted distributed file system. The core design is as follows:

- Namespace is `/domain/user/...`. One vault per user.
- Paths are hidden using `HMAC(DEK, path)`. Chunks use zstd compression + ChaCha20-Poly1305.
- Indexes are signed. Format 4 splits the index into per-directory chunks (same idea as Git trees).
- On revocation, a new DEK is generated and contents are re-encrypted.
- Synchronization uses three-way merge. Conflicts are preserved as conflict copies.

**Lineage Summary (Important)**

| Path | Reality |
|---|---|
| `~/src/dfs` | Fork source (v0.23.7). Practically identical to `~/dfs` (0 diffs, 0 merge conflicts) |
| `~/dfs` | Development copy. Has the same fixes in separate commits |
| `~/dfs2` | Lineage A (v0.23.76, +74 commits). TLS / WG / TOFU / WG-only |
| `~/dfs3` | Lineage B (0.33.0, +41 commits). Rewrite of cryptographic design and test suite |
| `~/src/dfs4` | **Unified lineage** (v0.48.1, 103 commits). Forked from `dfs3` 0.33.0, with `dfs2` work ported over |

**Format Number Collision (Fatal Issue)**

- `~/dfs` / `~/src/dfs`: `FMT_CURRENT = 3`
- `~/dfs3`: `FMT_CURRENT = 4` = split index into **per-directory chunks**
- `~/dfs2`: `FMT_MAX = 4` = represent index as **manifest + snapshot + delta**

The same "Format 4" has two different meanings. When merged, one side could misinterpret a vault created by the other. Because the version number is identical, the guard "do not read unknown newer formats" fails to trigger.

**Timeline of `dfs4`**

- 0.41.0: Ported from `dfs2` (per-vault authorization, rejecting remote deletion, lock name collisions, listener queue, optional FUSE).
- 0.42.0: `export` (emergency extraction) and recovery drill tests.
- 0.43.0: **evil tests** (chunk poisoning, lock squatting, registry flooding) and fixes.
- 0.44.0: Capacity guards. 0.45.0 / 0.46.0: Addressing review feedback.
- 0.47.0 / 0.48.0: Module splitting and type annotations (e.g., turning `vault.py` into a facade over `vault_core.py`).
- From 10/23 onward: Focus shifted to `chat.py`, `signal_box.py`, `rtc.py`, `agent_service.py`, and GUI (mac / GTK4).
- Stopped at 10/25 11:34: "chat: if destination key is not on configured storage node, search other discovered nodes."
- Core FS (`vault_core.py`, `vault_sync.py`, `volume.py`, `node.py`, `chunks.py`) has been mostly frozen since 10/22.

**Evaluation**

- All 11/11 evil tests passed. The threat model (A: malicious user on shared node / B: fake node or relay / C: outsider without keys) is sound. **This is an asset.**
- Test run: `24 passed, 150 skipped` (default). Running all with `--dfs-all` takes a long time, and in this environment `test_helper_sync` (mismatch in report format between GUI and sync engine) and others fail.
- The core failure was not security, but **conflated goals**. While building distributed storage, it was compared against a flagship anonymous sharing system (Tor), and despite declaring anonymity out of scope, it was evaluated on anonymity.

### 1.2 `mini_lustre` (`~/src/mini_lustre`)

Lustre-like. Complete separation of MDS / OST and striping.

- Separates metadata (MDS, SQLite WAL) and actual data (OST, `chunk_{file_id}_{index}.bin`).
- Layout is decided by MDS (`crc32(path)` picks starting OST, deterministic and balanced).
- Metadata over QUIC, chunks over TLS/TCP (because `aioquic`'s Python implementation bottlenecks the data path).
- Adaptive read-ahead, LRU chunk cache, partial read optimization, RMW (partial writes to compressed chunks).
- Quotas, distributed locks, online snapshots (`VACUUM INTO`), `fsck`/`gc`.

**Evaluation**

- Tests: 81 passed / 2 failed (the 2 failures are environmental due to `ost_data` being non-writable).
- Not production-ready. Reasons:
  1. **Virtually no authentication.** `auth_token` is verified if present, but if absent, `caller_owner` is accepted as-is. OST has no authentication. mTLS is configured, but `aioquic` does not request client certificates, so it does not function.
  2. **No availability design.** MDS is a single point of failure. Writes are not all-or-nothing, leaving partial successes on one side. No automatic mirror healing.
  3. Performance was measured, but only for a single client, single host, and small capacity.
- However, as an L3 implementation (striping, parallel I/O, layout management), it is genuine. **An asset as a component.**

### 1.3 `clayfs` (`~/src/clayfs`)

Virtual drive + instant snapshots + rollback written in Swift 6. 5,377 lines, 74 commits, published on GitHub.

- macOS: sparsebundle (APFS) + `clonefile(2)`.
- Linux: Btrfs subvolume snapshots (`linux/clayfs_btrfs` is in Python).
- Restoration uses atomic rollback ("move aside, then swap"). Includes path traversal protection.
- Nothing sits on the read/write path. Compression and deduplication are batch maintenance tasks run afterward (like `git gc`). `docs/SPEC-dedup-compress.md` has measurements on 7.86GB / 269k files (3.73GB after dedup + compression).
- Tests verified: 9/12 passed on macOS (failures due to `hdiutil` being unavailable in the environment); Linux Btrfs logic tests all passed.

**Evaluation**

- **The most complete of all prototypes seen so far.** However, its scope is a "rollback machine."
- Why it succeeded: **It built on primitives provided by the OS (`clonefile` / `reflink` / atomic `rename`), minimizing the problems it had to solve itself.**
- Mac and Linux versions are **separate implementations** (Swift / Python). On-disk layouts are also incompatible (Mac: `.clayfs/snapshots/` + `timeline.sqlite3` / Linux: `store/layers/` + `log.jsonl`).
- Subvolumes cannot be copied with `rsync` (contents copy, but CoW properties are lost). Linux uses `btrfs send | receive` (`clayfs_btrfs rebuild DEST`).
- **Network support is unnecessary.** Layering NFS/Samba works for "read/write," but "rollback" breaks (inode identity, caching, conflicts, and `.clayfs` protection break). One-way `rsync` only works **if restricted to storing snapshots within the same platform**.

### 1.4 Relationship Between the Three Prototypes (Conclusion)

| Prototype | Layers Built | Status |
|---|---|---|
| `mini_lustre` | L3 (striping, parallel I/O) + part of L2 (location resolution via registry) | Works. Lacks authentication and availability |
| `dfs` | L0/L2 (`.pubkey`, TOFU, registry) + seeds of L4 (Format 4 Merkle tree, signed index) | Sound crypto design. Conflated goals |
| `clayfs` | L5 (local materialization, CoW, rollback) | Complete. Networking is out of scope |

**What is missing is L1 (delegation of authority). None of the three designed this.**

---

## 2. Question: Is a Distributed File System Covering the Entire Internet Possible?

### 2.1 The Answer is "3. Neither / Other"

- **Impossible to build**: True if defined as a single unified global POSIX file system.
- **Unnecessary**: True for restricted use cases, false as a general proposition.
- **Other (Adopted)**: **Possible and already exists when decomposed. Only unification is impossible.**

Both "a single unified global system cannot be built" and "a global distributed store is necessary and already exists" are true simultaneously. The question conflates the two.

### 2.2 What Dictates Impossibility

- **Speed of light**: Round-trip to the other side of the Earth is 100–300ms. POSIX metadata operations are synchronous, and `cp -r` issues thousands of syscalls. A file system taking 100ms per operation is unusable by definition.
- **CAP**: At global scale, partitions are guaranteed to occur. Choosing consistency makes it unusable during partitions; choosing availability makes it non-POSIX. **Either choice fails to yield a "global POSIX file system."**
- AFS hit this wall head-on, settling on cell structures, callback-based caching, and per-file optimistic consistency—explicitly giving up parts of POSIX. Even then, it remains site-scale.

### 2.3 Successful Global Systems Always Solve Only One Problem

| System | What It Globalized | What It Gave Up |
|---|---|---|
| DNS | Namespace | Holds no data |
| Web | Namespace + reads | Writes, atomicity, `rename`, directory listing |
| BitTorrent | Data transfer | Namespace, writes, consistency |
| Usenet | Append-only replicated store + namespace | Editing, deletion, consistency |
| Git | History | Live file system, automatic sync |
| IPFS | Content addressing | Performance, mutable namespace, incentives |
| Tor | Anonymity | Bandwidth, performance |
| CDN | Distribution and caching | Writes, namespace authority |

**The Web is almost a global file system** (URLs as a global namespace, HTTP as read/write semantics, global caching), yet it has no atomic multi-file operations, no `rename`, no directory listing, and no POSIX. **It works globally precisely because it degraded itself as a file system.**

### 2.4 Two Things Being Conflated

1. **Namespace**: Where things are and whose they are. Can be asynchronous. Cacheable. Cheap. Can be globalized.
2. **Data plane**: Location and movement of bytes. Needs synchronization. Latency-bound. Expensive. Should not be globalized.

**`dfs` tried to globalize both with a single mechanism.** Things that were individually sound stopped working the moment they were unified. `clayfs` pinned both locally and delegated to the OS—that is why it succeeded.

### 2.5 Parts Not Decided by Technology Alone

A global writable store becomes a problem of **economics and law**, not technology.

- **Who pays**: Storage and bandwidth cost money. BitTorrent works because popularity creates reciprocity. Nobody has an incentive to host `dfs` private vaults for strangers.
- **Who moderates**: Global writable storage becomes a magnet for spam, malware, and illegal content. This is why IPFS gateways centralized, and why Usenet required hierarchical governance.
- **Who decides names**: A global namespace requires global authority. DNS exists, but is politically centralized. A write-everywhere FS requires global consensus on ownership.

**`dfs` kept building key and approval mechanisms endlessly because it tried to solve these economic and legal problems with cryptography. It failed not from bad design, but from mistaking the category of the problem.**

### 2.6 Decomposing Real-Time Behavior

The speed of light cannot be changed. However, what this makes impossible is "synchronizing all operations globally in real time," not the file system itself. Real-time behavior can be decomposed into at least two parts:

| Scope | Requirement | How to Achieve |
|---|---|---|
| Within one machine | Immediate. Written data must be visible immediately (read-your-writes) | Local FS / local cache suffices |
| Cross-machine propagation | Can be delayed. Define an upper bound on staleness | Asynchronous replication / sync |

**What is impossible is not the former, but making the latter synchronous.** The speed of light does not prove "global sync is impossible"—it merely sets a **lower bound on latency**. Specifying "stale by at most 300ms plus queueing delay" turns it from an impossibility into a design parameter. Files On-Demand systems, AFS, Coda, and Git all operate globally or across multiple sites by giving up real-time guarantees in their own ways.

In this sense, `dfs`'s stance of "synchronizing isolated file systems afterward" was the right direction. What was wrong was assuming that after allowing delay, all nodes could perform a three-way merge on the same tree.

Furthermore, calling something non-real-time a POSIX file system makes a false promise. Rather than a "file system," design it as a **synchronized workspace / locally materialized view**. Preserve POSIX immediacy locally, and delay only cross-machine propagation.

---

## 3. Why "Domain + Username" Is Not Enough

The appeal of `domain + user` is legitimate. Proven by email and SSH, `alice@example.com` guarantees global uniqueness and maps cleanly to hierarchical paths. Both `dfs` and `mini_lustre` adopted `/domain/user/...`.

**However, both implementations already had other layers.**

- `mini_lustre`: After resolving `/example.com/someone`, the data location is a `StripeLayout` returned by MDS. MDS itself is discovered via mDNS and a global registry at `example.com:9005`.
- `dfs`: After resolving `/domain/user`, the vault lived at "the configured storage node URL." Nodes were found via a registry (`rendezvous`) and mDNS. Keys used `.pubkey` (TOFU), with key authority undefined.

In other words, **four layers were already needed, and humans were filling them in manually via config files**.

| Missing Layer | Question `domain + user` Cannot Answer |
|---|---|
| Location | Which node holds the data? |
| Authority | Who vouches for `alice@example.com`'s key? Who can rotate it? |
| Consistency | When two machines write to the same path, how is order decided? |
| Delegation | How are groups, sub-organizations, and admin delegations expressed? |

**Authority is the heaviest.** If the domain vouches for keys, the domain becomes a global CA, reproducing CA centralization issues. If users self-sign, it becomes a TOFU model, unable to handle key rotation or first-contact attacks. **Either way, `domain + user` is not self-contained.**

---

## 4. Design Proposal: Split into Layers, Delegate Each Layer to Existing Systems

```text
L5 Local Materialization  FUSE + CoW cache + local rollback            (clayfs)
        ↑ Lazy fetch · write locally · publish explicitly
L4 Consistency             Per-namespace signed append-only log         (dfs3 Format 4 / Git)
        ↑ One writer per partition
L3 Data Plane              Content-addressed chunks + multiple transports
        ↑ Local (reflink) / direct WG / libtorrent (DHT) / HTTP (range)
L2 Location Resolution     Signed locator records (like DNS A/AAAA) / DHT / registry
        ↑ From name to "where it is"
L1 Authority Delegation    Signed delegation (like DNS NS/DNSSEC)
        ↑ Who may claim this subtree
L0 Identifier              domain + user + key (existing: SSH-format Ed25519)
```

**L0 can stay as-is.** `domain + user + ssh-ed25519` is valid as an identifier. The problem was stopping there.

### What to Borrow at Each Layer

| Layer | What to Borrow | Why |
|---|---|---|
| L1 Delegation | DNSSEC delegation model | Signed delegation, key delegation, and revocation frameworks already exist |
| L2 Location | DNS NS/A separation, Kademlia DHT | Separating names from addresses is already designed |
| L3 Data | libtorrent DHT and piece exchange | Avoid writing many-to-many transfer and peer discovery from scratch |
| L3 Local | `clonefile` / `reflink` | Proven in `clayfs` |
| L4 Consistency | Git Merkle trees and append-only logs | `dfs3` Format 4 is literally this |
| L5 Materialization | `clayfs` CoW snapshots | Already complete |
| Control | Tor / I2P | Only for anonymizing small control messages |

**"Integrating existing systems" means filling in this table—not inventing new algorithms.**

---

## 5. Most Important Design Decision: Write Boundaries

**The core principle to avoid repeating `dfs`'s failure.**

`dfs` tried to three-way merge the entire tree: conflict copies, signature verification, version comparison, locks. Because every node can write anywhere, conflicts happen everywhere.

The right design:

> **Fix a single writer per subtree, and arbitrate only at boundaries where the writer changes (delegation boundaries).**

- Only devices holding Alice's key can write inside `/example.com/alice`.
- Only principals holding the group key can write inside `/lab.univ.edu/project-x`.
- **Because concurrent writes do not happen within a single subtree, merging is eliminated.**

Arbitration is only needed at delegation boundaries. Once a single signed record is agreed upon—" `lab.univ.edu` delegated `/lab/project-x` to `alice` "—everything inside has a single writer.

**This eliminates the problem `dfs` tried and failed to solve.** What must be agreed upon globally is only **who owns** each partition, not the contents themselves. The exact same structure that made DNS succeed.

### 5.1 If You Choose Delay, Decide the Writer First

Adopting delayed propagation removes the real-time defense of "cannot write simultaneously." As a result, the merge problem does not disappear—it gets pushed to the center.

- **Delayed propagation + single writer** → Only replication is needed. No merges occur. Simple and append-only.
- **Delayed propagation + multiple writers** → Merging is mandatory. Requires OT, CRDTs, or conflict copies.

Therefore, **decide "who writes" before "when to propagate."** This is not an implementation convenience; it is a prerequisite for safely allowing delay. Once a single writer per subtree is established, cross-machine delay remains mere replication lag, and reconciliation is needed only at delegation boundaries.

Reversing this order reproduces `dfs`'s failure. Even with the right stance of isolated vaults and later synchronization, trying to merge a global tree without restricting writers invites back avoidable conflicts.

### 5.2 Separate Writer, Event, and Display Name

A string like `user@domain % ssh-publickey /path/to/file # UTC-timestamp` is convenient as a **display format for humans reading writes**. However, using it directly as a "writer identifier" conflates four things: authority, signer, file name, and version.

| Element | What It Represents | Problem If Used Directly |
|---|---|---|
| `user@domain` | Human-readable name | Does not guarantee the **authority** of the key claiming the name |
| `ssh-publickey` | Key to verify signature | String changes on key rotation; full public key is too long |
| `/path/to/file` | Current display name | `rename` changes the address of the same file |
| `UTC-timestamp` | Human-facing timestamp | Subject to clock skew and spoofing; does not guarantee true order |

Recommended separation:

```text
Name (stable)        user@domain
Writer key (signer)  Immutable ID such as key-id = SHA-256(public-key)
Authority (signed)   Record where domain or delegated authority authorizes writer-key
Write (ordering)     subtree + seq + parent-hash + event-hash
Display (human)      user@domain%key-id/path#UTC-time
```

- **The writer is not the username itself, but an authorized writer key.** If the same user has multiple devices, a separate writer key can be issued per device. However, to preserve single-writer per subtree, either restrict active writer keys to one at a time or place a sequencer to order writes.
- **Do not use paths as stable IDs.** Maintain a separate stable `file-id` and treat paths as namespace aliases. This preserves identity between events and entities across renames.
- **Do not use timestamps as the source of truth for ordering.** Order by `seq` and `parent-hash`, and keep the signed UTC timestamp as an audit/display attribute. Clock skew or spoofing will not break causal write order.
- **Make the event ID the hash of canonicalized content**, signed by the writer key. Hashing the display string directly changes the ID whenever delimiters or escaping change, so define a separate internal canonical form.

This solves **L0's "name and signer pair"** and **L4's "write event identification and ordering."** What remains unsolved is **L1's chain of authority: "this writer key is permitted to write to this named subtree."**

---

## 6. Keys and Revocation

`dfs`'s "re-encrypt all chunks on revocation" breaks down in a distributed environment. Use the following approach instead:

- **Epoch-numbered keys**: `dek = KDF(master, epoch)`. Tag each chunk with its epoch.
- **Revocation means "do not hand out future epochs."** Those who already hold old epochs can still read them. Explicitly accept this as unavoidable by the nature of cryptography (as `dfs`'s `DESIGN.md` rightly noted: "previously read content cannot be taken back").
- **Record rotation in L1 as a signed delegation record.** This makes it traceable who changed keys and when.

Simply dropping "full re-encryption" makes it viable in a distributed environment.

### 6.1 How to Handle Key Publishing, Discovery, and Rotation

To verify a writer key, one must verify not just the public key itself, but **who vouches for the binding between this name and this key**. A plain keyserver only collects and returns keys without guaranteeing the validity of that binding.

`keys.openpgp.org` is useful for publishing and discovering OpenPGP keys, but **it is not a certificate authority**. Email verification only proves "this address can receive mail," not the identity `alice@example.com` or the authority to write `/example.com/alice/...`. Moreover, a standalone keyserver cannot prevent split-view attacks where different keys are shown to different users for the same name.

This design requires separating three things:

1. **Name-to-key binding (L0/L1)**: The domain or delegated authority signs the mapping between `user@domain` and `writer-key`. Use existing domain authorities where appropriate—SSH CA principals, DNSSEC, HTTPS `.well-known`, etc.
2. **Rotation and revocation history (L1)**: Key rotation is a signed delegation record by the new key, and revocation is a signed record stating "no further epochs are valid." Past events are never deleted; they remain append-only.
3. **Transparency (part of L2)**: Place name-to-key mappings in an append-only log providing inclusion proofs and consistency proofs. This detects split-view attacks where an operator or attacker serves different keys to different peers. What is needed instead of `keys.openpgp.org` is this kind of **key transparency**, not a mere key lookup service.

**There is no necessity to use OpenPGP.** For this use case, SSH Ed25519 keys are simpler, and SSH CA principals and expiration times can be used directly. Even if OpenPGP is used, do not treat the Web of Trust as a global authority; maintain domain-authority signatures or a transparency log separately.

Note that this section does not yet decide which authority to adopt. Open L1 questions (alignment between domain authority and storage owner, first contact, revocation handling) remain.

---

## 7. Parts That Must Not Be Integrated (Explicitly Out of Scope)

Areas where technical solutions failed. Explicitly mark three as out of scope:

1. **Economics**: Who pays for others' disk and bandwidth? Either design incentives or restrict to private nodes.
2. **Moderation**: Global writable storage becomes a magnet for illegal content. Separate public and private parts from the start.
3. **First-contact trust**: TOFU or CA? It can remain open, but **explicitly state which one is chosen**.

---

## 8. What to Build First, What Not to Build

### Build First (Small, Easy to Verify)

1. **Name resolution using only L0 + L1 + L2.** Signed delegations and locator records. Necessary because the target is storage.
2. **Single-writer L4 append-only log.** Reuse `dfs3` Format 4 Merkle trees.
3. **L5 local materialization.** Use `clayfs` as-is (already complete).

### Do Not Build (Dangerous)

- Global three-way merge
- Global POSIX consistency
- Custom DHT / custom peer exchange (borrow from libtorrent)
- Remote rollback
- Automatic bidirectional sync

---

## 9. Reinterpreting Each Prototype as "One Layer in the Design"

Viewing them not as "failures" but as per-layer prototypes reveals their value:

- **`mini_lustre`** = L3 + part of L2. MDS/OST separation is sound and actually works.
- **`dfs`** = L0/L2 + seeds of L4. Format 4 Merkle trees are usable. **All 11 evil tests can be reused directly as L4 security requirements** (especially "do not report success when a relay silently drops writes" = read-back verification, which is needed even on top of BitTorrent).
- **`clayfs`** = L5. Usable as-is.

**What was missing was L1.** Thinking `domain + user` was enough came from substituting L1 with an implicit assumption that "domain names are authority." In reality, a domain name was just a string, and nobody had defined authority.

Representing writers as a single string like `user@domain % ssh-publickey /path # UTC-time` works for displaying L0 and L4. However, mixing name, signer, path, and timestamp blurs authority and ordering (§5.2). Likewise, delegating key publishing and discovery to an external service cannot verify whether the name-to-key binding is genuine (§6.1). The L1 gap can only be addressed concretely once these two points are separated.

---

## 10. Open Questions (To Think Through)

1. **Can L1 (authority delegation) truly ride on DNSSEC?** Does domain name authority align with storage ownership (why should the owner of `example.com` necessarily have authority over `/example.com/*`)?
2. **Who decides the "boundaries" of write boundaries?** Can delegation be declared unilaterally, or is approval required?
3. **Where should L2 locators live?** DHT trades performance for anonymity. A registry centralizes. Reusing DNS invites censorship.
4. **How to enforce mutual exclusion for writes to protect single-writer?** Locally, a lock suffices. When the writer spans multiple devices (same person), consensus between devices is needed (the minimal consensus problem).
5. **~~When using libtorrent as the L3 foundation, how to fix `dfs`'s "lack of content addressing" problem?~~**
   **→ Resolved (2026-11-11).** Because there is a single writer, the writer itself—not the OST—performs deduplication. Deduplication happens before encryption using plaintext content address `plain_id`, and the index (`plain_id -> wire_id`) is reconstructed from signed history. Thus encryption does not need to be deterministic; standard AEAD (ChaCha20-Poly1305) with a fresh random nonce per write can be used. Deduplication and confidentiality are orthogonal.
   Observed: re-pushing unchanged data sends 0 ciphertext bytes; adding identical content under another name sends 0 payload bytes.
   Keep the content-addressing key `K_addr` separate from encryption key rotation (mixing them wipes out deduplication on key rotation).
6. **How much of the existing code to keep as-is?** Use `clayfs` directly, or rebuild only L5?
7. **Is it really okay to leave the three out-of-scope items (economics, moderation, first contact) out of scope?** The moment they are excluded, the system is restricted to "between private nodes." Is that acceptable?

---

## 11. Decision Guidelines from This Discussion (For When in Doubt)

- **If you can explain "what happens when the other party changes," you may add the feature.** The moment you add something you cannot explain, you repeat `dfs` (`rsync` gets away with it because it only makes an explainable one-way contract).
- **Do not re-solve problems the OS has already solved.** Atomicity is solved by `rename`, CoW by cloning, compression by transparent compression (`clayfs` did this).
- **Only agree globally on "who owns it."** Never make the content itself the subject of global consensus.
- **Rather than adding layers, restrict each layer to a single writable principal.**
- **Keep nothing on the read/write path. Do heavy work afterward in batches** (`clayfs` design principle).
