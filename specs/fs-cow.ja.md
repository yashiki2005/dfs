# L5 ファイルシステム抽象 (`dfs.fs`)

> [English](fs-cow.md) | **日本語**

## 目的

スナップショットとローカル実体化を、**OS の CoW に依存せず**成立させる。
Python さえ動けば Windows / macOS / Linux のどこでも同じ結果になることを最優先する。

## 方針

| 項目 | 方針 |
|---|---|
| 既定 backend | `copy`（実コピー）。どこでも動く。 |
| CoW | あれば使う（最適化）。無ければ `copy` に落ちる。 |
| 正しさ | CoW の有無に依存しない。スナップショットは常に独立した inode。 |
| 設定 | `auto`（既定）/ `copy` / `reflink` / `fast_clone` |

## backend

| 名前 | 能力 | 実装 | 主な環境 |
|---|---|---|---|
| `copy` | 実コピー | `shutil.copy2` / symlink 再生成 | どこでも |
| `reflink` | ファイル単位 CoW | macOS `clonefile(2)` / Linux `FICLONE` | APFS, Btrfs, XFS |
| `fast_clone` | ファイル単位 CoW | Windows `FSCTL_DUPLICATE_EXTENTS_TO_FILE` | ReFS, Dev Drive |

- `reflink` / `fast_clone` はディレクトリを再帰し、ファイルごとに CoW を試みる。
- CoW できないファイル（`EINVAL`/`ENOTSUP`/`EXDEV`）だけ実コピーへフォールバックし、
  `SnapshotResult.warnings` に記録する。
- FIFO / socket / device はスナップショットに含めず、`SnapshotResult.skipped` に記録する。

## 検出

`detect_backends(root)` は `root` の上で実際に 1 ファイルを複製して確かめる。
したがって「macOS だから APFS」ではなく「今このディレクトリで CoW が動くか」で決まる。
NFS / SMB / 外付け exFAT 上では `copy` に落ちる。

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

## 非対応と将来

- Windows ReFS の block clone は実装済みだが、NTFS では使えない。
  NTFS で CoW を得るには minifilter ドライバが必要で、dfs 本体としては配布しない。
- btrfs subvolume / `btrfs send|receive` によるディレクトリ単位 CoW は未実装
  (`fast_clone` の別実装として予約)。
- 透過圧縮・重複排除は L3 の責務であり、この層では扱わない。
