# Mac and Pi5 Hardware Integration (`specs/e2e_lan.md`)

> **English** | [日本語](e2e_lan.ja.md)

## 0. Purpose and Scope

Records hardware test results for `PLAN.md` Phase 5 (sharing a single tree across two machines).

- Harness: `bench/e2e_lan.py`
- Raw data: `bench/results/20261111-200812-e2e-lan.json`
- Execution date: 2026-11-11
- Connection: `ssh -i ~/.ssh/pi-mock-test operator@198.51.100.7`

---

## 1. Setup

```text
[Mac]                                         [Pi5 (Ubuntu 24.04, aarch64, 4 core, 16GB)]
clayfs (L5)                                     dfs serve
  └ tree/  ── push ──▶ L3 ChunkStore (TLS 9443) ──┐
  .clayfs/snapshots/                             │
        ▲                                        │
        └──── pull ◀── L4 追記ログ ◀── L2 名簿 (HTTP 9440)
```

| Item | Value |
|---|---|
| Mac | macOS 27.3 arm64, Python 3.12 |
| Pi5 | Ubuntu 24.04 (Linux 7.0), Python 3.14.4, `cryptography` installed, no pytest |
| LAN RTT (10 pings) | **Avg 2.25ms** (min 0.57 / max 6.04) |
| L2 | `http://198.51.100.7:9440` (Symbolic Registry, HTTP) |
| L3 | `tls://198.51.100.7:9443` (TLS 1.3) |
| Existing service on host | `mini_lustre` using 9001/9002. **Tested on separate ports without stopping it** |

---

## 2. Procedure

1. Generate Ed25519 keys for `root` / `alice` with `ssh-keygen`.
2. Place `root`'s public key on Pi5 and start `dfs serve` (state in `~/dfs_e2e/server_state`).
3. From Mac, delegate `/example.com` → `/example.com/alice/notes` via `dfs delegate` and register on Pi5's L2.
4. Run `dfs init` on Mac and Pi5 using the same `tree_secret`.
5. `push` from Mac → `pull` on Pi5 → verify contents with SHA-256.
6. `push` from Pi5 → `pull` on Mac (reverse direction).
7. Simultaneously `push` from both on the same parent version, and verify one is rejected with `ConflictError`.
8. Verify no conflict copies are created.

---

## 3. Results

| Step | Result | Elapsed (harness) | Notes |
|---|---|---|---|
| L2 connectivity (HTTP) | Pass | 32.5 ms | `resolve` returns delegation and head version in 1 round trip |
| L3 connectivity (TLS) | Pass | 75.9 ms | TLS 1.3 (including initial handshake) |
| Mac push v1 | Pass | 66.4 ms | Sent 1,624 B |
| Pi5 pull v1 | Pass | 39.9 ms | Received 978 B, contents match |
| Pi5 push v2 | Pass | 60.4 ms | Sent 1,641 B |
| Mac pull v2 | Pass | 94.0 ms | Received 995 B, contents match |
| Mac push v3 | Pass | 67.7 ms | Sent 1,661 B |
| **Pi5 concurrent push** | **Rejected** | — | `ConflictError` (CAS mismatch) |
| Content match (SHA-256) | Pass | — | Digests of 2 files match on both devices |
| Conflict copies | **0** | — | No `*conflict*` files |

Harness summary (v4):

```text
OK   L2 疎通（HTTP）          32.5 ms
OK   L3 疎通（TLS）           75.9 ms
OK   Mac push              165.3 ms（内部計測 70.5 ms、送信 1,661 B）
OK   Pi5 pull              643.5 ms（内部計測 38.8 ms、受信 1,015 B、ssh 起動を含む）
OK   内容一致（SHA-256）       2 ファイル
OK   同時書き込みを CAS で拒否
OK   衝突コピー 0 件
```

---

## 4. What Was Verified

- **L2 signed locators work over LAN.** The registry returns delegation and head version in 1 round trip.
- **L3 TLS/TCP works over LAN.** TLS 1.3, custom protocol.
- **L4 single-writer semantics hold on real hardware.** Concurrent pushes from the same parent version result in `ConflictError` for the later arrival.
- **No 3-way merge occurs.** Zero conflict copies were created.
- **Bidirectional sync works.** Contents matched in both Mac ↔ Pi5 directions.
- **Testable without stopping existing services.** Ran on 9440/9443 while `mini_lustre` was using 9001/9002.

---

## 5. What Was Not Measured

- **WAN conditions.** LAN RTT is ~2ms. `PLAN.md` target (high latency 200ms) is untested here.
  The harness does not support `tc qdisc` or proxy latency injection.
- **Many nodes.** Only 2 machines. Delegation boundaries and registry contention with 3+ nodes are untested.
- **pytest on Pi5.** Not installed, so tests were only run on Mac.
  On Pi5, CLI, encryption, and signing were verified directly.
- **Long-running stability.** Only a few minutes of testing. Degradation over continuous push/pull is unmeasured.
- **Striping.** Tested with 1 OST on hardware. 2 OSTs are verified locally
  (`TestL3Striping`), but 2 OSTs over LAN have not been tested.

---

## 6. Reproduction

```bash
# On Pi5
ssh -i ~/.ssh/pi-mock-test operator@198.51.100.7
cd ~/src/dfs
python3 -m dfs.cli serve --bind 0.0.0.0 \
  --registry-port 9440 --ost-port 9443 \
  --root-anchor /example.com \
  --root-pubkey ~/dfs_e2e/root.pub \
  --state-dir ~/dfs_e2e/server_state

# On Mac
python bench/e2e_lan.py
```

Raw data is saved in `bench/results/`. Because it includes environment and timestamp details, re-run with the same harness when comparing.
