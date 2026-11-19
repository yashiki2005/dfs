# L5 Filesystem Abstraction (`dfs.fs`)

> **English** | [日本語](fs-cow.ja.md)

## Purpose

Make snapshots and local materialization work **without depending on OS CoW**.
The top priority is producing identical results anywhere Python runs—Windows, macOS, or Linux.

## Policy

| Item | Policy |
|---|---|
| Default backend | `copy` (full copy). Works everywhere. |
| CoW | Used if available (optimization). Falls back to `copy` if unavailable. |
| Correctness | Independent of CoW availability. Snapshots always have independent inodes. |
| Setting | `auto` (default) / `copy` / `reflink` / `fast_clone` |

## Backends

| Name | Capability | Implementation | Primary Environments |
|---|---|---|---|
| `copy` | Full copy | `shutil.copy2` / symlink recreation | Everywhere |
| `reflink` | Per-file CoW | macOS `clonefile(2)` / Linux `FICLONE` | APFS, Btrfs, XFS |
| `fast_clone` | Per-file CoW | Windows `FSCTL_DUPLICATE_EXTENTS_TO_FILE` | ReFS, Dev Drive |

- `reflink` / `fast_clone` recurse into directories and attempt CoW per file.
- Only files that cannot be CoW-cloned (`EINVAL`/`ENOTSUP`/`EXDEV`) fall back to a full copy and are recorded in `SnapshotResult.warnings`.
- FIFOs, sockets, and devices are excluded from snapshots and recorded in `SnapshotResult.skipped`.

## Detection

`detect_backends(root)` verifies support by actually cloning a test file inside `root`.
Therefore, backend selection is determined by "whether CoW works in this directory right now," not "macOS means APFS."
On NFS, SMB, or external exFAT, it falls back to `copy`.

## API

```python
from dfs.fs import fs, FileSystem

f = fs("/path/to/mount")
f.info()            # {'backend': 'reflink', 'cow': True, ...}
f.take_snapshot("v1")
f.clone("a.txt", "b.txt")
f.materialize(snapshot_path, "restored")
```

CLI:

```
dfscli fs info <dir>
dfscli fs snapshot <dir> v1
dfscli fs materialize <dir> out --src <snapshot>
```

## Unsupported Features and Future Work

- Windows ReFS block clone is implemented, but cannot be used on NTFS.
  Supporting CoW on NTFS would require a minifilter driver, which is not distributed as part of `dfs`.
- Directory-level CoW via btrfs subvolume / `btrfs send|receive` is not yet implemented
  (reserved as an alternative implementation of `fast_clone`).
- Transparent compression and deduplication are responsibilities of L3 and are not handled at this layer.
