# dfscli (`specs/cli.md`)

> **English** | [日本語](cli.ja.md)

## 0. Purpose and Scope

`dfs/cli.py` is for testing the layers, exposing raw layer operations such as `serve` / `delegate` / `init` / `push` / `pull`. For everyday file operations, a more conventional tool is needed.
`dfscli` reuses the components of `dfs/cli.py` (L2 registry client, server, node construction) and wraps them in a CLI that **addresses locations by remote name**.

- Implementation: `dfs/cli_main.py`, `dfs/remotes.py`
- Entry point: `./dfscli`
- Tests: `tests/test_cli_main.py`

`dfs/cli.py` is kept for directly verifying layers (starting `serve`, registering `delegate`, measuring `push`/`pull` round trips).

### Installation

Can be installed as console scripts via `pip` / `pipx`:

```bash
pipx install .
dfscli --version
dfssvc --help
```

To also use libp2p/QUIC, include the optional extra:

```bash
pipx install '.[libp2p]'
```

To also use Zstandard compression:

```bash
pipx install '.[compression]'
```

To also use FUSE mounts, include the `fuse` extra:

```bash
pipx install '.[fuse]'
```

On macOS, `fuse-t` is also required:

```bash
brew install macos-fuse-t/homebrew-cask/fuse-t
```

`./dfscli` and `./dfssvc` at the repository root are kept as compatibility wrappers for direct use during development.

---

## 1. Concepts

### 1.1 Remote = Write Boundary

The single-writer boundary in `dfs` is a "subtree path" (e.g., `/example.com/alice/notes`).
An `rclone`-style remote maps to this—**not to a hostname**.

Among the fields of a remote, **anything that can be queried from the L2 registry can be omitted**:

| Item | Example | When omitted |
|---|---|---|
| L2 registry | `192.0.2.60` | **Required** (starting point; hostname alone suffices) |
| Writer's OpenSSH Ed25519 private key | `~/.ssh/alice` | Generated on the spot (`~/.config/dfs/keys/<name>_ed25519`) |
| L3 OST `host:port` | `192.0.2.60:19443` | Resolved from L2 locator (`endpoints`) |
| Subtree path | `/example.com/alice/notes` | Looked up in L2 by writer public key |
| `tree_secret` (shared secret) | — | Read from terminal without echo |
| Working directory | `~/.cache/dfs/<name>` | Default (override with `--workdir`) |

The minimal registration is:

```bash
# Hostname only. Generates key and reads secret from terminal
dfscli config create scw --registry 192.0.2.60
```

#### Registry Only Needs a Hostname

The default L2 port is **9440**. Passing only a hostname (or IP) such as `192.0.2.60` to `--registry` automatically fills in `http://` and `:9440`. For a different port, pass `--registry-port` or write `host:port` explicitly.

```
192.0.2.60                -> http://192.0.2.60:9440
http://host:1234           -> http://host:1234        (as-is)
host --registry-port 19440 -> http://host:19440
```

Parsed with `urlparse`, so `host:port` and `host` are never confused.

#### Alternate Registries for Reads

Repeating `--registry-alternate` registers fallback registries for reads.
Writes (`announce` / `delegate`) are always sent only to the primary registry in `--registry`.

```bash
dfscli create scw --registry 192.0.2.60 \
  --registry-alternate 192.0.2.61
```

When the primary registry is started with e.g. `dfs serve --replica http://192.0.2.61:9440`, it replicates signed delegation chains, L4 logs, and locators to the alternate registries. Alternate registries re-verify from the root anchor and never roll back to older bundles.

Repeating `--ost-alternate` registers read-only OSTs separate from the writer's primary OST. Writes go only to the primary OST, and chunks are copied to replica OSTs. Because `pull` / `cat` try `endpoints` in the locator in order, reads can continue even if the primary OST goes down as long as a replica OST is alive. See `specs/ost-replica.md` for details.

#### Fetching Root Key and Registry List via DNSSEC

Passing `--dnssec-domain` fetches the root public key and primary/secondary registries from the DNSSEC-verified TXT record at `_dfs.<domain>`. `--registry` is not required.

```bash
dfscli discover example.com

dfscli config create scw \
  --dnssec-domain example.com \
  --key ~/.ssh/alice \
  --secret <tree_secret>
```

DNSSEC is limited to distributing the root key and initial registry list; it is not used for L4 head or primary promotion decisions. If `--registry` / `--root-pubkey` are also specified, they are rejected unless they match the DNSSEC contents. See `specs/dnssec.md` for details.

#### BitTorrent Archive

The current head version can be saved as signed metadata + all chunks + `.torrent`.
BitTorrent is not on the hot path; it is for long-term retention and last-resort recovery.

```bash
dfscli archive create scw: --out ./scw-v1
dfscli archive create scw: --out ./scw-v1-published --publish
dfscli archive create scw: --version 3 --out ./scw-v3
dfscli --remote scw archive publish ./scw-v3
dfscli archive fetch scw: --version 3 --out ./downloads ./restored
dfscli archive verify ./scw-v1
dfscli archive extract ./scw-v1 ./restored
dfscli archive catalog .
```

`create --publish` registers a signed descriptor in L2. `fetch` retrieves the descriptor from L2, downloads the bundle via DHT/tracker using `aria2c` or `transmission-cli`, and re-verifies the DFS signatures. DNSSEC is one way to initially obtain the root public key, and `fetch` works with just a normal `--registry` and `remotes.json`.
See `specs/bittorrent.md` for details.

#### L4 Version History

`history` displays the signed L4 log history held by L2 in newest-first order.

```bash
dfscli history scw:
dfscli history scw:/example.com/alice --limit 20
```

On the L2 API, this uses `/v1/history` and the `version` parameter of `/v1/resolve`.

#### Manual Registry Promotion

To promote a secondary registry to primary, stop the old primary and advance the state's role epoch on the secondary:

```bash
dfs promote --state-dir ~/.dfs_server --role-epoch 2
dfs serve ... --role primary --role-epoch 2
```

Update the writer side to the same generation with `config create ... --role-epoch 2`.
A secondary accepts only writes with a matching `role_epoch`. See `specs/promotion.md` for details.

#### libp2p/QUIC Reads

An OST's chunk directory can be served over libp2p/QUIC and added as a read candidate.
The server runs in a dedicated process due to `py-libp2p` process constraints.

```bash
dfscli libp2p-serve \
  --chunks-dir ~/.dfs_server/ost_chunks \
  --listen /ip4/0.0.0.0/udp/0/quic-v1

dfscli create scw \
  --registry http://primary:9440 \
  --libp2p-peer /ip4/203.0.113.10/udp/19443/quic-v1/p2p/12D3KooW...
```

Reads try primary OST → replica OST → libp2p in order. Writes go only to the primary OST.
See `specs/libp2p.md` for details.

**Why L2 knows OST locations and paths**: L2 locators (`dfs-l2-locator-v1`) carry `endpoints` containing L3 locations (`tls://192.0.2.60:19443`), updated whenever a version is written. Delegation records contain the writer's public key (`writer`), so L2 can answer "which subtree does this key write to?" Before the first version is written, no locator exists yet, so L2 advertises its L3 location via `--advertise` (or a host inferred from bind).

#### Writer Keys Are Generated on the Spot

If `--key` is omitted, an Ed25519 key is created at `~/.config/dfs/keys/<name>_ed25519` (configurable via `--key-dir`), in OpenSSH format with permissions `600`.

If `--key` **is** passed but the path does not exist, `dfscli` does not create one and exits with a usage error (exit code 2), preventing typos from silently creating a new key when the user intended to use an existing one.

#### `tree_secret` Is Read from the Terminal

`tree_secret` cannot be fetched from L2 (it is a shared secret never stored on the server) and is required **before writing**.
If `--secret` is omitted, it prompts **twice without echo** from the terminal. Because a typo creates an undecryptable tree (irrecoverable since no plaintext is stored on the server), it asks a second time for confirmation and accepts only matching inputs.

```
$ dfscli create scw --registry 192.0.2.60
scw の tree_secret:                       ← 入力は画面に出ない
scw の tree_secret（確認のためもう一度）:  ← 同じものを打つ
[dfscli] リモート 'scw' を保存しました: ~/.config/dfs/remotes.json
  registry    : http://192.0.2.60:9440
  書き手の鍵  : ~/.config/dfs/keys/scw_ed25519（作った。OpenSSH 形式の Ed25519）
  tree_secret : *** （端末から読みました）
```

If they do not match, it retries (up to 3 times):

```
[dfscli] 入力が一致しません。もう一度入力してください（1/3）
```

If all 3 attempts fail to match, it registers the remote with an empty secret and prompts the user to set `--secret` later. Attempting to write with an empty secret stops with a usage error (exit code 2).

#### `create` Is a Shorthand for `config create`

Since registration is the most frequent operation, a shorthand omitting `config` is provided (calls the same function):

```bash
dfscli create scw --registry 192.0.2.60       # = dfscli config create scw ...
dfscli config show scw                         # show, delete, list are under config
dfscli config delete scw
dfscli listremotes                             # same as config list
```

Implemented using Python's standard-library `getpass` reading without echo from `/dev/tty`.
Inside pipes or redirects where no TTY exists, it does not prompt and asks for `--secret`.
Passing `--no-prompt` skips prompting even when a TTY is present (for scripts).

Attempting to write with an empty secret stops with a usage error (exit code 2) rather than silently using weak encryption.

#### Why Not `pinentry`

The standard Unix component for safely reading passphrases from a terminal is **`pinentry` (`pinentry-curses`)** (or `dialog` / `whiptail`). However, it is not pre-installed on macOS, so `getpass` is used to avoid external command dependencies.

### 1.2 Root Anchor (Trust Root) and Certificate Pinning

Verifying a delegation chain from the root requires the root anchor's public key. This is **stored in the remote definition** (`root_pubkey` and display `root_fingerprint`).

- Passing `--root-pubkey FILE` (`create` / `join`) pins it upfront from the file (recommended for production; errors if it mismatches DNSSEC or the registry's key).
- When omitted, it is fetched from the registry (`/v1/paths`) on initial registration and recorded (**initial TOFU pinning**), displaying the source and `SHA256:...` fingerprint.
- Thereafter, only the recorded public key is trusted; if a registry returns a different value, it is rejected.
- Explicitly passing `--allow-tofu` (`create` / `join`) permits TOFU without writer verification even on remotes where the root public key is unavailable or unset (by default, signature verification fails when `root_pubkey` is unset).

```text
  root アンカー: SHA256:n2ypRtbEq5vZOTK+i0WmBioSgHFEPFPCr21KWO7c4Jc （名簿から取得（初回 TOFU ピン留め））
                 これ以降この指紋だけを信頼します（違う値を返す名簿は拒否）
```

L3 OST TLS certificate pinning (`ost_cert_sha256`) works similarly:

- Can be specified explicitly with `--ost-cert-sha256`; update to the new pin during rotation.
- When omitted, auto-pinning occurs only if the selected OST endpoint matches the normalized `endpoint` from registry `/v1/ost` and uses `tls://` (`host:port`) (never auto-applied to `https://` reverse proxies or other OSTs).
- When switching `Remote.ost` to a different endpoint, any stale certificate pin in the working directory is automatically cleared if the new definition has no pin.

The rationale and limitations are in `specs/delegation.md` §3.5: because "fetching the root of trust from the peer does not make it a root of trust," TOFU is used only on first contact and the local record is used thereafter. Production should specify it explicitly.

### 1.3 Key Format

`--key` expects an **OpenSSH-format Ed25519 private key**, not PEM (also generated in this format when omitted).

- `crypto.py` first tries `cryptography`'s `load_ssh_private_key`, and falls back to `ssh-keygen -Y sign` for keys it cannot decrypt. Both assume OpenSSH format.
- Only `ssh-ed25519` is supported. RSA / ECDSA are rejected during signature verification.
- Passphrase-less keys are faster; passphrase-protected keys work too, but spawn `ssh-keygen` on every signature.

---

## 2. Commands

```text
dfscli listremotes
# Minimal (hostname only; generates key and reads secret twice from terminal)
dfscli create NAME --registry HOST
# ↑ Same as config create. Below are optional explicit flags
dfscli config create NAME --registry HOST

# Add only when you don't want defaults
#   --registry-port N  Port to fill in (default 9440)
#   --key FILE         Existing Ed25519 private key (refuses if missing)
#   --key-dir DIR      Directory to create key in (default ~/.config/dfs/keys)
#   --secret VALUE     tree_secret (reads from terminal if omitted)
#   --no-prompt        Do not read from terminal
#   --ost / --path / --workdir / --epoch / --compression / --node-name
dfscli config create NAME --registry HOST --key FILE --ost HOST:PORT --path /sub/path \
                          [--workdir DIR] [--epoch N] [--node-name NAME]
dfscli config show|delete|list [NAME]

# Read operations (do not advance version)
dfscli ls     REMOTE:path
dfscli lsd    REMOTE:path
dfscli mount  REMOTE:path LOCAL_MOUNT
dfscli lsl    REMOTE:path
dfscli lsjson REMOTE:path
dfscli size   REMOTE:path
dfscli cat    REMOTE:path/file
dfscli about  REMOTE:
dfscli check  REMOTE:path LOCAL_DIR

# Write operations (committed as 1 version)
dfscli copy   LOCAL REMOTE:path [--checksum [MODE]] [--include PATTERN] [--exclude PATTERN] [-n]
dfscli copyto LOCAL_FILE REMOTE:path/file [--checksum [MODE]] [-n]
dfscli import_tar ARCHIVE REMOTE:path [--strip-components N] [-n]
dfscli mv     REMOTE:path REMOTE:path [--overwrite] [-n]
dfscli sync   LOCAL_DIR REMOTE:path [--delete] [--checksum [MODE]] [--include PATTERN] [--exclude PATTERN] [-n]

# Directories and deletion
dfscli mkdir  REMOTE:dir
dfscli rm     REMOTE:path [-R|--recursive] [--rmdirs] [-n]
dfscli rmdir  REMOTE:dir [-n]
dfscli purge  REMOTE:path [-n]

# Fetch
dfscli pull   REMOTE:path LOCAL_DIR [--force] [--include PATTERN] [--exclude PATTERN]

# Server side uses dfs/cli.py directly
dfscli serve    ... --advertise <host advertising L3>
dfscli serve    ... --ost-dir /Volumes/ExtSSD/dfs/ost/<name>
dfscli delegate ...
```

`REMOTE` is the name given to `config create`. `REMOTE:` refers to that remote's root, and `REMOTE:docs` refers to a subpath. Passing `--remote NAME` lets you omit `remote:` and write only the path (equivalent to `rclone`'s `:backend:`).

---

## 2.1 Additional L2 Queries

To keep `config create` concise, two endpoints were added to L2 (`dfs/cli.py`):

| Endpoint | Returns |
|---|---|
| `POST /v1/ost` | L3 location (`tls://host:port`) and per-path locator endpoints |
| `POST /v1/paths` | Registered subtrees, writer public keys, epochs, head versions |

`dfscli` uses these two endpoints to resolve `--ost` and `--path`:

- **OST**: First checks `endpoints` in the locator. If none exist yet (initial setup), uses the `/v1/ost` advertisement.
- **Path**: Derives the public key from the private key (`ssh-keygen -y` or `.pub`) and searches `/v1/paths` for matching subtrees. If multiple match, picks the shortest one.

---

## 3. Behavior

### 3.1 Writes "Sync Local Copy First, Then Commit 1 Version"

Write commands execute in the following order:

1. Sync the working directory copy to the remote's head version (just 1 L2 round trip if already on the same version).
2. Apply local changes to the working copy.
3. `push` them together as 1 version.

If it fails mid-way, the remote version is never corrupted. Because `dfs` push sends chunks first and then appends 1 version via CAS, a failed CAS does not advance the version.

If both primary and secondary registries are down, it falls back to verified responses in `.clayfs/l2_cache.json`. Expired or rolled-back cached entries are still rejected.

### 3.2 Idempotency

If nothing changed, **no new version is created**. Like `rclone`'s default, size is checked first.
`--checksum` accepts `size` / `crc32` / `sha1` / `plain_id`. A bare `--checksum` is treated as `plain_id` for backward compatibility.

```
$ dfscli copy ./sample local:
[dfscli] copy OK -> v1 | 追加/更新 4 件（同じ 0 件） | sent=6303 B | 74.7 ms

$ dfscli copy ./sample local:
[dfscli] copy: 変更なし（4 ファイルが同じ）。新しい版は作りません
```

Because `dfs` deduplicates chunks via the writer-side index, pushing identical content would not resend file bodies. Even so, incrementing the version number is wasteful, so the CLI avoids creating a new version when nothing changed.

#### 3.2.1 Move Uses 1 Version

`mv` is handled as an intra-remote rename and pushes only 1 version at the end.
It does not consume 2 versions like `copy` + `rm`.

- Destination is interpreted as "the new name itself" (does not auto-nest into an existing directory)
- Refuses if the destination already exists by default
- Allows replacing a file with another file only with `--overwrite`
- Does not merge directories
- Cross-remote moves use `copy` + `rm`

#### 3.2.2 Filters

`copy` / `sync` / `pull` accept `--include PATTERN` and `--exclude PATTERN`.
Patterns apply to paths relative to the operation's base directory and support shell-style wildcards (`*` / `?` / `[]`). `--exclude` always takes precedence over `--include`.

In `sync --delete`, remote files outside the filter are not deleted.
For example, passing `--exclude 'docs/private/*'` completely excludes that scope from synchronization.

#### 3.2.3 tar Import

`import_tar` auto-detects `.tar` / `.tar.gz` / `.tar.xz` / `.tar.bz2` and imports into a remote. Like `copy`, extracted entries are committed as additions/updates in 1 version, without deleting remote-only files.

- Allows only regular files and directories
- Rejects symlinks, hardlinks, devices, and FIFOs
- Rejects absolute paths and `..`, normalizing `\` as a separator before checking
- Ignores `.clayfs`
- `--strip-components N` strips the first N path components from tar entries
- Does not create a new version if all files have identical content

```bash
dfscli import_tar release.tar.gz backup:
dfscli import_tar bundle.tar.xz backup:project --strip-components 1
```

#### 3.2.4 FUSE Mount

`mount` exposes a remote subtree at a local mount point.
Prefers `fuse-t` on macOS and uses `libfuse` on Linux.

```bash
dfscli mount scw:docs /mnt/dfs-docs
dfscli mount scw:docs /mnt/dfs-docs --read-only
```

Reads and writes happen on the working tree, and changes are pushed to DFS on file close (FUSE `release`) and on unmount. Writing multiple files concurrently may increment versions per file. To preserve the single-writer assumption while mounted, do not modify the same subtree from another DFS writer concurrently.

`--allow-other`, `--debug`, and `--fuse-library PATH` are also supported. On macOS, if `fusepy` picks macFUSE instead, pass `fuse-t`'s `libfuse-t.dylib` to `--fuse-library`.

#### 3.2.5 Per-Folder Compression

Compression policy can be set via the directory xattr `user.dfs.compression`.
Values are `none` / `zstd`. Children inherit the setting of their nearest ancestor.

```bash
xattr -w user.dfs.compression zstd /path/to/tree/src
xattr -w user.dfs.compression none /path/to/tree/archive
```

On push, the effective policy is saved in the signed directory chunk, so the remote interpretation remains unchanged even if xattrs are later lost. Compression is applied to plaintext, and chunks are stored with the `DFSB3` codec header. If the actual compressed ratio is 95% or higher, it is stored uncompressed as `DFSB2`.

A remote-wide default can be set via `config create --compression zstd`.
This default is used only when no xattr is present.

### 3.3 Listings Do Not Fetch File Contents

`ls` / `lsd` / `lsl` / `lsjson` / `size` traverse only directory chunks and never fetch file contents.
Transfer volume depends only on **tree depth** (breadth-first traversal in `l4_log.py::list_tree`).
`cat` fetches only the directory chunks along the path to the target file and that file's chunks.
`lsd` returns only immediate subdirectories.

### 3.4 Deletion and Empty Directories

`dfs` **preserves empty directories in versions**. A directory chunk is represented as `{"entries": [], "format": "dfs-dir-v1"}`, and readers recreate the directory from it. That is, deleting all files inside a directory does not delete the directory itself; `pull` will materialize the empty directory.

| Command | Action |
|---|---|
| `mkdir REMOTE:dir` | Creates an empty directory (persisted in version) |
| `rm REMOTE:file` | Deletes a file. **Leaves any resulting empty directory by default** |
| `rm REMOTE:dir -R` | Deletes directory contents recursively (files only; empty hierarchy remains) |
| `rm REMOTE:dir -R --rmdirs` | Deletes contents recursively and **prunes resulting empty directories** |
| `rmdir REMOTE:dir` | Deletes only an empty directory (refuses if non-empty) |
| `purge REMOTE:path` | Deletes everything under the path and the directory itself |

Use `--rmdirs` when you want the remote to match the local view like `rclone`, and omit it when you want to keep empty directories as assets.

`rm --rmdirs` targets **only the parent directories of the deleted path**. It does not prune unrelated empty directories across the working tree or siblings under the same parent.

`sync --delete` is an operation to "match local," so it also prunes directories that become empty as a result of deletion (without needing `--rmdirs`).

### 3.5 Single-Writer Conflicts

If another machine wrote first, `push`'s CAS fails. The CLI handles this cleanly instead of raising an unhandled exception, exiting with code 7 and instructing the user to `pull` and retry.

| Exit code | Meaning |
|---|---|
| 0 | Success |
| 1 | Unexpected error |
| 2 | Usage error (undefined remote, invalid path, etc.) |
| 6 | L2/L3 unreachable |
| 7 | Single-writer conflict (CAS failure) |
| 8 | Rollback detected (B6) |
| 9 | Silent discard detected (B7) |

---

## 4. Internal Structure (What Is Written to Disk)

State after running `copy ./sample local:` once, assuming `sample/` contains `a.txt` (12B), `dup.txt` (identical content), `b.bin` (3KB), `docs/readme.md`, and `docs/sub/deep.txt`.

```text
# Client side (working directory)
wd/
├── tree/                         Working tree for actual reads/writes
│   ├── a.txt  b.bin  dup.txt
│   └── docs/readme.md  docs/sub/deep.txt
└── .clayfs/
    ├── dfs_config.json          L2 URL, OST, sub_path, tree_secret
    ├── local_head.json           HeadPin (version / entry_hash / epoch)
    ├── l2_cache.json             Verified delegation / locator / head
    ├── ost_index.json            Writer's plain_id -> (wire_id, store_id) index
    ├── cache_version             "Current working copy version" added by rclone CLI
    └── snapshots/v1/             Version snapshot taken on push (hardlinks)

# Server side
srv/
├── ost_cert.pem  ost_key.pem    L3 TLS certificate (auto-generated on first run)
├── ost_chunks/                   L3 chunks; filenames are wire_id
│   ├── 546d0806...blk  (12 B)   Plaintext "hello world\n"
│   ├── 99d12a68...blk  (879 B)  Directory chunk (root)
│   └── ...
└── registry_state.json          L1 delegation + L2 locator + L4 log
```

File bodies are split into **8 MiB chunks**, and directories into **1 chunk per directory**.
File entries list each chunk's `plain_id`, `wire_id`, `offset`, and `size` under `chunks`.
If `a.txt` and `dup.txt` have identical content, both point to the same `wire_id` chunk (deduplication).
Legacy manifests with "whole file as 1 chunk" are also readable.

Each chunk is plaintext + 60B fixed overhead (`plain_id` 32 + `nonce` 12 + `tag` 16) + framing, so for small files the fixed overhead is larger.

File and directory `mode`, `mtime`, and `user.*` / `com.apple.*` xattrs are also stored in signed directory chunks and restored on `pull`. Owners, ACLs, and privileged xattrs are not stored.

---

## 5. Tests

49 tests in `tests/test_cli_main.py`.

4 tests in `tests/test_fuse_mount.py` (read/write, push on `release`, read-only, error when `fuse-t` is missing).

| Test | What it verifies |
|---|---|
| `test_config_roundtrip` | Remote config persistence and `600` permissions |
| `test_unknown_remote_is_an_error` | Rejects unknown remotes |
| `test_copy_ls_cat_pull` | `copy` → `cat` → `pull` preserves content |
| `test_copy_is_idempotent` | Second `copy` does not create a version |
| `test_copyto_and_checksum` | `copyto` with identical content does not create a version |
| `test_mv_file_uses_one_version` | `mv` renames a file in 1 version |
| `test_mv_directory_and_dry_run` | Directory move and non-updating dry-run |
| `test_mv_refuses_collision_and_allows_file_overwrite` | Collision rejection and `--overwrite` |
| `test_mv_rejects_cross_remote_and_descendant_destination` | Rejects cross-remote and self-descendant moves |
| `test_copy_include_exclude` | `copy` include / exclude |
| `test_sync_delete_does_not_touch_excluded_paths` | `sync --delete` does not delete excluded paths |
| `test_pull_include_and_exclude` | `pull` include / exclude |
| `test_lsd_lists_only_directories` | `lsd` returns only immediate subdirectories |
| `test_sync_delete` | `--delete` removes remote-only items |
| `test_sync_without_delete_keeps_remote_only_files` | Keeps remote-only files without `--delete` |
| `test_dry_run_does_not_write` | `-n` does not write to remote |
| `test_check_reports_difference` | Exit code reflects presence of differences |
| `test_ls_prefix_only_lists_direct_children` | `ls` lists only direct children |
| `test_rm_file_leaves_empty_dir` | Deleting a file leaves empty directory |
| `test_rm_rmdirs_prunes_empty` | `--rmdirs` prunes resulting empty directories |
| `test_rm_dir_needs_recursive` | Directory is not deleted without `--recursive` |
| `test_rm_missing_is_an_error` | Missing path returns exit code 2 |
| `test_mkdir_and_rmdir` | Can create and remove empty directories |
| `test_rmdir_refuses_non_empty` | `rmdir` refuses non-empty directories |
| `test_purge_removes_everything` | `purge` deletes everything |
| `test_empty_dir_survives_roundtrip` | Empty directories persist in versions and return on `pull` |
| `test_rm_dry_run` | `rm -n` does not actually delete |
| `test_no_default_remote_is_reported` | Path without `--remote` fails with exit code 2 |
| `test_remote_error_exit_code` | Unknown remote returns exit code 2 |
| `test_config_can_omit_ost_and_path` | Omitting `--ost` / `--path` still resolves via L2 for read/write |
| `test_registry_host_only_gets_default_port` | `--registry` accepts hostname only and fills in port |
| `test_config_create_makes_key_when_omitted` | Omitting `--key` creates OpenSSH key (`600`) |
| `test_explicit_missing_key_is_refused` | Typo in `--key` does not create a key |
| `test_no_prompt_keeps_secret_empty` | `--no-prompt` does not read from terminal |
| `test_create_alias_exists` | `dfscli create` behaves identically to `config create` |
| `test_prompt_verifies_secret_twice` | Prompts twice for secret on terminal; retries on mismatch |
| `test_path_without_leading_slash_is_accepted` | `--path` does not need a leading `/` |
| `test_empty_secret_is_refused_on_write` | Writing with empty `tree_secret` is blocked |
| `test_registry_advertises_ost_and_paths` | L2 returns L3 location and registered paths |

`TestPullBatch` in `tests/test_integration.py` verifies batched reads (1 round trip per level) that back `list_tree`.

---

## 6. Usage Notes

- **A remote is a single write boundary.** Defining two remotes for the same subtree and writing concurrently will cause one to be rejected by single-writer CAS (by design).
- **`sync --delete` deletes from the remote.** Preview with `-n` first to see what will be deleted.
- **`purge` cannot be undone.** Deletes everything under the path and the directory itself. Check with `-n`.
- **Empty directories are kept by default.** Use `rm --rmdirs` or `sync --delete` to match local state.
- **Omitting `--key` creates a key.** Always pass `--key` to use an existing key; if the path does not exist, it refuses (to avoid creating a new key on a typo).
- **Omitting `--secret` reads from the terminal.** When using in pipelines, specify `--secret` or `--no-prompt` explicitly.
- **`tree_secret` is independent per remote.** Running `config create` with a different secret from the WAN test tree (`dfs-wan-shared-secret`) treats it as a separate tree; use the same secret to share. Because it cannot be fetched from L2 (never stored on the server), always set it before writing.
- **`--path` can be omitted assuming 1 key = 1 boundary.** If one key is used for multiple subtrees, L2 returns one of them (the shortest); specify `--path` explicitly in that case.
- **There is no authentication.** Use L3 only inside WireGuard or a LAN. Integrity is guaranteed by L4 signatures.
- To run the server persistently, use `launchd`. `nohup` alone terminates when the parent session ends.
