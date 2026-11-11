# rclone ライク CLI（`specs/rclone_cli.md`）

## 0. 目的と位置づけ

`dfs5/cli.py` は層の試験用で、`serve` / `delegate` / `init` / `push` / `pull` という
「層の操作」をそのまま見せる。日常のファイル操作には、もっと普通の道具が要る。
そこで `dfs5/cli.py` の部品（L2 名簿クライアント、サーバ、ノード構築）をそのまま使い、
**リモート名で場所を指す** CLI を被せたものが `dfs5r` である。

- 実装: `dfs5/rclone_cli.py`、`dfs5/remotes.py`
- エントリポイント: `./dfs5r`
- 試験: `tests/test_rclone_cli.py`

`dfs5/cli.py` は残す。層を直接確かめる用途（`serve` の起動、`delegate` の登録、
`push`/`pull` の往復計測）では今もそちらを使う。

---

## 1. 考え方

### 1.1 リモート = 書き込み境界

dfs5 の単一書き手の境界は「サブツリーのパス」である（`/example.com/alice/notes`）。
rclone のリモートはこれに対応させた。**ホスト名ではない。**

1 つのリモートは次の 6 つをまとめて持つ。だからコマンドのたびに長い URL や鍵のパスを
書かなくて済む。

| 項目 | 例 |
|---|---|
| L2 名簿 URL | `http://172.16.1.60:19440` |
| L3 OST の host:port | `172.16.1.60:19443` |
| サブツリーのパス | `/example.com/alice/notes` |
| 書き手の OpenSSH Ed25519 秘密鍵 | `~/.ssh/alice` |
| `tree_secret`（Convergent AEAD の共有秘密） | — |
| 作業ディレクトリ | `~/.cache/dfs5/<名前>`（`--workdir` で変更） |

定義は `~/.config/dfs5/remotes.json`（`DFS5_CONFIG` で変更）に置く。秘密を含むため
パーミッションは 600 にする。

### 1.2 鍵の形式

`--key` は **OpenSSH 形式の Ed25519 秘密鍵**。PEM ではない。

- `crypto.py` はまず `cryptography` の `load_ssh_private_key` で読み、復号できない鍵は
  `ssh-keygen -Y sign` に委ねる。どちらも OpenSSH 形式を前提にする。
- `ssh-ed25519` のみ対応。RSA / ECDSA は署名検証で弾かれる。
- パスフレーズ無しが速い。有りでも動くが、署名のたびに `ssh-keygen` が起動する。

---

## 2. コマンド

```text
dfs5r listremotes
dfs5r config create NAME --registry URL --ost HOST:PORT --path /sub/path \
                          --key <Ed25519 秘密鍵> --secret <tree_secret> \
                          [--workdir DIR] [--epoch N] [--node-name NAME]
dfs5r config show|delete|list [NAME]

# 読み出し（版を進めない）
dfs5r ls     REMOTE:path
dfs5r lsl    REMOTE:path
dfs5r lsjson REMOTE:path
dfs5r size   REMOTE:path
dfs5r cat    REMOTE:path/file
dfs5r about  REMOTE:
dfs5r check  REMOTE:path LOCAL_DIR

# 書き込み（1 版としてまとめる）
dfs5r copy   LOCAL REMOTE:path [--checksum] [-n|--dry-run]
dfs5r copyto LOCAL_FILE REMOTE:path/file [--checksum] [-n]
dfs5r sync   LOCAL_DIR REMOTE:path [--delete] [--checksum] [-n]

# 取り出し
dfs5r pull   REMOTE:path LOCAL_DIR [--force]

# サーバ側は cli.py のものをそのまま使う
dfs5r serve    ...
dfs5r delegate ...
```

`REMOTE` は `config create` で付けた名前。`REMOTE:` はそのリモートの根、`REMOTE:docs` は
配下を指す。`--remote NAME` を付ければ `remote:` を省略してパスだけ書ける
（rclone の `:backend:` 相当）。

---

## 3. 振る舞い

### 3.1 書き込みは「写しを合わせてから 1 版」

書き込み系は次の順で動く。

1. 作業ディレクトリの写しを、リモートの先頭版に合わせる（既に同じ版なら L2 の 1 往復だけ）。
2. ローカルの変更を写しへ載せる。
3. 1 版としてまとめて `push` する。

途中で失敗しても、リモートの版は壊れない。dfs5 の push は「塊を送ってから CAS で 1 版を
追記する」順なので、CAS が失敗すれば版は増えない。

### 3.2 冪等

変更が無ければ**新しい版を作らない**。判定は rclone の既定と同じく大きさを先に見て、
`--checksum` のときだけ内容アドレス（`plain_id`）まで比べる。

```
$ dfs5r copy ./sample local:
[dfs5r] copy OK -> v1 | 追加/更新 4 件（同じ 0 件） | sent=6303 B | 74.7 ms

$ dfs5r copy ./sample local:
[dfs5r] copy: 変更なし（4 ファイルが同じ）。新しい版は作りません
```

dfs5 は書き手側の索引で塊を重複排除するので、内容が同じなら `push` しても本文は送られない。
それでも版が増えるのは無駄なので、CLI 側で「変わらないなら版を作らない」を決めている。

### 3.3 一覧は内容を取らない

`ls` / `lsl` / `lsjson` / `size` は、ディレクトリ塊だけを辿ってファイルの中身は取らない。
取得量は**構造の階層数**で決まる（`l4_log.py::list_tree` の幅優先走査）。
`cat` は目的のファイルまでのディレクトリ塊と、そのファイル塊だけを取る。

### 3.4 単一書き手の衝突

他の端末が先に書いていた場合、`push` の CAS が失敗する。CLI はこれを例外にせず、
終了コード 7 と案内（`pull` してからやり直す）にする。

| 終了コード | 意味 |
|---|---|
| 0 | 成功 |
| 1 | 予期しないエラー |
| 2 | 使い方の誤り（リモート未定義・パス不正など） |
| 6 | L2/L3 に到達できない |
| 7 | 単一書き手の競合（CAS 失敗） |
| 8 | 巻き戻しを検出（B6） |
| 9 | 黙った破棄を検出（B7） |

---

## 4. 内部構造（何がディスクに出来るか）

`copy ./sample local:` を 1 回実行した後の姿。`sample/` には a.txt（12B）、
dup.txt（同一内容）、b.bin（3KB）、docs/readme.md、docs/sub/deep.txt があるとする。

```text
# クライアント側（作業ディレクトリ）
wd/
├── tree/                         実際に読み書きする作業ツリー
│   ├── a.txt  b.bin  dup.txt
│   └── docs/readme.md  docs/sub/deep.txt
└── .clayfs/
    ├── dfs5_config.json          L2 URL・OST・sub_path・tree_secret
    ├── local_head.json           HeadPin（版番号 / entry_hash / epoch）
    ├── cache_version             rclone CLI が足した「今の写しの版」
    └── snapshots/v1/             push 時に取った版の写し（ハードリンク）

# サーバ側
srv/
├── ost_cert.pem  ost_key.pem    L3 の TLS 証明書（初回に自動生成）
├── ost_chunks/                   L3 の塊。ファイル名は wire_id
│   ├── 546d0806...blk  (12 B)   平文 "hello world\n"
│   ├── 99d12a68...blk  (879 B)  ディレクトリ塊（ルート）
│   └── ...
└── registry_state.json          L1 委譲 + L2 ロケータ + L4 ログ
```

ファイル塊は**ファイルごと**、ディレクトリ塊は**ディレクトリごと**に 1 つ。つまり塊は
「ファイル本体」と「目次」の 2 種類しかない。`a.txt` と `dup.txt` が同一内容なら、
同じ `wire_id` の塊 1 つを両方が指す（重複排除）。

各塊は平文 + 固定費 60B（plain_id 32 + nonce 12 + tag 16）+ フレームで、小さいファイルでは
固定費の方が大きい。1MB のファイルの塊は 1,024B のチャンクに分かれる。

---

## 5. 試験

`tests/test_rclone_cli.py` に 12 件。

| 試験 | 確かめること |
|---|---|
| `test_config_roundtrip` | リモート定義の保存と 600 のパーミッション |
| `test_unknown_remote_is_an_error` | 知らないリモートを弾く |
| `test_copy_ls_cat_pull` | copy → cat → pull で内容が一致する |
| `test_copy_is_idempotent` | 2 回目の copy が版を作らない |
| `test_copyto_and_checksum` | 同じ内容の copyto が版を作らない |
| `test_sync_delete` | `--delete` でリモートにしかないものを消す |
| `test_sync_without_delete_keeps_remote_only_files` | `--delete` 無しでは消さない |
| `test_dry_run_does_not_write` | `-n` がリモートに書かない |
| `test_check_reports_difference` | 差分の有無で終了コードが変わる |
| `test_ls_prefix_only_lists_direct_children` | `ls` が直下だけを返す |
| `test_no_default_remote_is_reported` | `--remote` 無しのパスを終了コード 2 で弾く |
| `test_remote_error_exit_code` | 知らないリモートが終了コード 2 で返る |

`tests/test_integration.py` の `TestPullBatch` は、`list_tree` を支える読み出し側の
一括取得（1 階層 1 往復）を確かめる。

---

## 6. 使うときの注意

- **リモートは 1 つの書き込み境界**。同じサブツリーを別のリモート名で 2 つ定義して
  同時に書くと、単一書き手の CAS で片方が拒否される（設計どおり）。
- **`sync --delete` はリモートを消す**。`-n` で何が消えるか先に見ること。
- **`tree_secret` はリモートごとに独立**。WAN 試験のツリー（`dfs5-wan-shared-secret`）と
  別の秘密で `config create` すれば、別のツリーとして扱われる。共有したい場合は同じ秘密を使う。
- **認証は無い**。L3 は WireGuard / LAN の中だけで使うこと。完全性は L4 の署名で担保する。
- サーバを常駐させるなら launchd を使う。`nohup` だけだと親のセッション終了で落ちる。
