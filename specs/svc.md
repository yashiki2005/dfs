# Running a Local Server (`dfssvc`)

> **English** | [日本語](svc.ja.md)

## 0. Purpose and Positioning

With `dfs serve`, you have to prepare the state directory, root public key, and L2/L3 ports
yourself. That is fine for testing individual layers, but too many steps for "spin one up
locally to try it out." `dfssvc` is the entry point that handles the following for you:

1. **Finds two consecutive free ports**, assigning the first to L2 (registry) and the second to L3 (OST).
2. Creates the root key (L1 authority Ed25519) and **writer key** (which signs the L4 log) if they do not exist.
3. Prepares the state directory and starts `dfs serve`. Use `--ost-dir` if you want to place
   only the OST chunks on a separate disk.
4. Waits for startup, verifies it, and **registers the delegation to the writer**.
5. Records the values needed to connect (`~/.config/dfs/services.json`).
6. Provides `stop` / `list` / `status` / `env` / `dnssec` / `logs` for cleanup and inspection.

- Implementation: `dfs/svc.py`
- Entry point: `./dfssvc`
- Tests: `tests/test_svc_cli.py`

---

## 1. Why: Placing L2 and L3 Adjacent to Each Other

L2 and L3 listen on separate ports. Taking two consecutive free ports makes them easy to
remember—`--registry-port N` / `--ost-port N+1`—and lets us check for collisions in one pass.

### 1.1 Checking Free Ports (macOS Pitfall)

**Do not judge a port as "free" just by binding with `SO_REUSEADDR`.** On macOS, even if
another process is listening on `0.0.0.0:19440`, a bind to `127.0.0.1:19440` still
succeeds (because they are treated as different addresses).

Therefore, `is_port_free` checks in two stages:

1. **Attempt a connection** (timeout 0.4 s). If there is a response, someone is there = in use.
   Since L3 is a TLS server, it closes before the handshake, but as soon as `connect` succeeds
   we know someone is on that port.
2. **Bind without `SO_REUSEADDR`**. This also catches `TIME_WAIT` remnants.

Originally, stage 2 was implemented with `SO_REUSEADDR`, which falsely reported `127.0.0.1:19440`
as "free" even when a launchd server was listening on `0.0.0.0:19440`. The two-stage check above fixes this.

In addition, ports already used by recorded services are excluded from the search candidates
(so the same number is never picked twice).

---

## 2. Commands

```text
dfssvc start [--name NAME] [--host HOST] [--port N] [--advertise HOST]
              [--state-dir DIR] [--ost-dir DIR] [--root-key FILE] [--root-anchor PATH]
              [--wait SECONDS] [--foreground] [--force]
dfssvc list
dfssvc status [NAME]
dfssvc stop   [NAME] [--forget]
dfssvc env    [NAME] [--workdir DIR]
dfssvc dnssec [NAME] [--domain DOMAIN] [--primary-url URL]
                     [--secondary-url URL] [--ttl SECONDS] [--epoch N]
dfssvc logs   [NAME] [-n LINES]
```

Passing `--json` outputs machine-readable results for `start` / `list` / `status`.

### 2.1 Arguments

| Argument | Default | Meaning |
|---|---|---|
| `--name` | `local` | Service name; key for state and records |
| `--host` | `127.0.0.1` | Address to bind; use `0.0.0.0` for external access |
| `--advertise` | inferred from `--host` | Host advertised by L2 as the L3 location |
| `--port` | `19440` | Start searching for two consecutive free ports from this number |
| `--state-dir` | `~/dfssvc/<name>/server` | Server state (chunks and registry) |
| `--ost-dir` | `<state-dir>/ost_chunks` | Storage directory for L3 OST chunks; can be separated onto an external SSD, etc. |
| `--root-key` | `~/dfssvc/<name>/keys/root` | L1 authority Ed25519 key (created if missing) |
| `--root-anchor` | `/example.com` | Root path |
| `--writer-key` | `~/dfssvc/<name>/keys/writer` | Writer Ed25519 key (created if missing) |
| `--path` | `<root-anchor>/<name>` | Subtree to delegate; `dfscli` looks this up from the key |
| `--no-delegate` | — | Do not register delegation (only start the server) |
| `--wait` | `30` | Seconds to wait for startup |
| `--foreground` | — | Run in foreground (stop with Ctrl-C) |
| `--force` | — | Stop any running service with the same name and recreate its record |

### 2.2 Records

Stored in `~/.config/dfs/services.json` (mode 600). Written by `start`, PID set to 0 by `stop`,
and removed by `--forget`.

```json
{
  "schema": "dfs-services-v1",
  "services": {
    "dev": {
      "name": "dev",
      "registry_port": 19441,
      "ost_port": 19442,
      "bind": "127.0.0.1",
      "advertise": "127.0.0.1",
      "state_dir": "~/dfssvc/dev/server",
      "root_key": "~/dfssvc/dev/keys/root",
      "writer_key": "~/dfssvc/dev/keys/writer",
      "sub_path": "/example.com/dev",
      "role": "primary",
      "role_epoch": 1,
      "ost_dir": "/Volumes/ExtSSD/dfs/ost/dev",
      "pid": 12345
    }
  }
}
```

`registry_url` and `ost_endpoint` are not written to the record; they are constructed when
reading (to avoid duplication and prevent divergence on edits).

When `ost_dir` is specified, L2 state (`registry_state.json`) and TLS certificates remain in
`--state-dir`, and only L3 encrypted chunks are placed in `--ost-dir`.

```bash
dfssvc start --name dev --ost-dir /Volumes/ExtSSD/dfs/ost/dev
```

### 2.3 Automatic Delegation Registration

Simply starting `dfs serve` leaves the remote empty (`/v1/paths` is empty), so `dfscli` cannot
resolve any subtree. `dfssvc start` takes care of this too:

- Prepares the writer's Ed25519 key at `~/dfssvc/<name>/keys/writer`.
- Registers delegations at intermediate levels from the root as well (L1 requires multi-hop).
  For `/example.com/team/notes`, it goes through `/example.com/team` to the leaf. Intermediates
  are created with the root key as writer.
- Delegates the leaf to the writer's key.
- If a delegation for the same writer and path already exists, it does not re-register it
  (does not recreate it on restart).

The validity period is **365 days for the leaf (writer delegation) and 366 days for intermediates**.
L1 requires `child.expires_at <= parent.expires_at` (Invariant 3). Because parent and child are
signed in separate steps/processes, using the same number of days caused the child to exceed the
parent and fail if execution crossed a 1-second boundary (this actually happened in tests). Making
intermediates 1 day longer guarantees parent > child. Since clock skew/execution delta is at most
a few seconds, day-level granularity is sufficient.

Passing `--no-delegate` starts only the server so you can set up delegations yourself.

### 2.4 Outputting DNSSEC TXT

`dnssec` generates the JSON to place in the `_dfs.<domain>` TXT record from the service record's
root public key, root anchor, and registry URL.

```bash
dfssvc dnssec dev
```

The default domain is the first component of `root_anchor` (e.g., `example.com` for
`/example.com/dev`), and the registry URL is the service's L2 URL. For public DNSSEC,
override as needed:

```bash
dfssvc dnssec dev \
  --domain example.com \
  --primary-url https://l2.example.com \
  --secondary-url https://l2-b.example.com \
  --ttl 300 \
  --epoch 2
```

Stdout outputs single-line JSON ready to put into a TXT record, and stderr prints the record name.
Passing `--json` outputs formatted JSON (`dfssvc --json dnssec dev`).
The generated value is re-validated with the discovery parser to ensure there is exactly one
primary and that URLs and TTL are valid.

---

## 3. Usage

### 3.1 Start, Connect, Write

```bash
cd ~/src/dfs

# 1. Start the server (picks consecutive free ports and prepares keys & delegation)
./dfssvc start --name dev

# 2. Connect dfscli. L2 knows both L3 and the subtree, so --ost and --path are unnecessary
./dfscli config create dev \
    --registry http://127.0.0.1:19441 \
    --key ~/dfssvc/dev/keys/writer \
    --secret dev-secret

# 3. Use it
mkdir -p /tmp/sample
echo "hello" > /tmp/sample/hello.txt
./dfscli copy /tmp/sample dev:
./dfscli ls   dev:
./dfscli cat  dev:hello.txt
```

Running `./dfssvc env dev` prints the connection line (excluding `--secret`) ready to copy:

```
$ ./dfssvc env dev
# Connect to dev (L2 advertises L3, so --ost is not needed)
dfscli config create dev --registry http://127.0.0.1:19441 --key ~/dfssvc/dev/keys/writer --secret <tree_secret>

# Info: L3 for this server is tls://127.0.0.1:19442
#       Writer key : ~/dfssvc/dev/keys/writer (usable directly for --key)
#       Subtree    : /example.com/dev (L2 resolves from key, so --path is not needed)
#       L1 root    : ~/dfssvc/dev/keys/root (used for --signing-key)
```

### 3.2 Status and Cleanup

```bash
./dfssvc list             # Recorded services and running status
./dfssvc status dev       # Details and L2 health check
./dfssvc logs dev -n 20   # Tail of logs
./dfssvc stop dev         # Stop (keeps record)
./dfssvc stop dev --forget  # Stop and remove from record
```

`stop` sends `SIGTERM`, waits 10 seconds, and falls back to `SIGKILL` if the process has not exited.

---

## 4. Tests

14 tests in `tests/test_svc_cli.py`:

| Test | What it verifies |
|---|---|
| `test_consecutive_ports_are_adjacent` | The two returned ports are adjacent |
| `test_busy_port_is_skipped` | A port with an active listener is detected as in use |
| `test_start_port_that_is_busy_is_avoided` | Starting from a busy port number skips that port |
| `test_out_of_range_start_is_rejected` | Rejects trying to allocate 2 ports starting at 65535 |
| `test_store_roundtrip_with_600` | Record roundtrip with mode 600, and derived values are not written |
| `test_start_then_stop` | start → running → L2 responds → stop terminates it |
| `test_same_name_without_force_is_refused` | Refuses to overwrite the same name without `--force` |
| `test_two_services_get_different_ports` | Second service gets a different consecutive pair |
| `test_start_registers_delegation` | `start` prepares the writer key and delegation |
| `test_ls_works_before_any_write` | `ls` succeeds even on a remote with nothing written yet |
| `test_no_delegate_leaves_registry_empty` | `--no-delegate` creates no delegation |
| `test_explicit_path_is_used` | Delegations are created for both leaf and intermediate paths of `--path` |
| `test_dnssec_outputs_txt_json` | `dnssec` outputs TXT JSON and record name |
| `test_dnssec_json_and_secondary_primary_requirement` | Formatted JSON, primary required for secondary, automatic addition of secondary URL |

Tests redirect `HOME` to a temporary directory and isolate state and records inside it.
`tearDown` stops all services remaining in the record (`addCleanup` can run after temporary
directory cleanup, leaving orphan processes if you rely on ordering).

---

## 5. Notes

- **No authentication.** If binding `--host 0.0.0.0`, restrict it to WireGuard / LAN.
  Integrity is guaranteed by L4 signatures.
- **`dfssvc` does not generate `tree_secret`.** Because it is a shared secret not stored on the
  server, pass it yourself via `dfscli config create --secret`.
- **`stop` keeps the record.** Starting again with the same name requires `--force`. `--force`
  stops the old process so no two processes share the same state directory. Use `--forget` to remove.
- **The root key is reused.** Restarting with the same `--name` preserves previous delegations.
  To start fresh, specify a different `--root-key` path.
- **Read-only `dfscli` commands automatically create a working directory.** Commands like `ls` / `cat` / `size` / `check`
  only read remote versions, but still need a place to store connection info (resolved ost and `sub_path`)
  and HeadPin. They create it on the fly without requiring `touch` first.

## 6. Pitfalls Log

- **Read-only commands used to require `touch`.** Initially implemented with `open_remote(create=False)`,
  so `dfscli ls` returned "not initialized, run touch first." Requiring initialization for a read-only
  command was poor ergonomics, so read-only commands were changed to `create=True`.
- **`dfssvc start` did not register delegations.** The server ran, but the remote was empty so `ls`
  had nothing to show and `dfscli` could not resolve a subtree. Added to `start`.
- **`SO_REUSEADDR` bind misdetected busy ports.** Fixed with the two-stage check in §1.1.
- **Multi-hop delegations had identical validity periods and failed on clock/second boundaries.**
  Because intermediate and leaf delegations are signed separately, a 1-second difference caused the
  child's `expires_at` to exceed the parent's, failing Invariant 3. Fixed by making intermediates 1 day longer (§2.3).
- **Failed delegation registration left the started server orphaned.** `start` launches the server and
  then registers the delegation. If registration raised an exception, an unrecorded process remained
  holding the port (actually happened in tests). Fixed to always stop the server before exiting on
  failure (SIGTERM → 10 s → SIGKILL).
