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
# 最小（L2 が OST とパスを知っているので、この 3 つだけでよい）
dfs5r config create NAME --registry URL --key <Ed25519 秘密鍵>

# 書くなら tree_secret も渡す
dfs5r config create NAME --registry URL --key <Ed25519 秘密鍵> --secret <tree_secret>

# 明示したいときだけ --ost / --path / --workdir / --epoch / --node-name を足す
dfs5r config create NAME --registry URL --key <鍵> --ost HOST:PORT --path /sub/path \
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

# ディレクトリと削除
dfs5r mkdir  REMOTE:dir
dfs5r rm     REMOTE:path [-R|--recursive] [--rmdirs] [-n]
dfs5r rmdir  REMOTE:dir [-n]
dfs5r purge  REMOTE:path [-n]

# 取り出し
dfs5r pull   REMOTE:path LOCAL_DIR [--force]

# サーバ側は cli.py のものをそのまま使う
dfs5r serve    ... --advertise <L3 を広告するホスト>
dfs5r delegate ...
```

`REMOTE` は `config create` で付けた名前。`REMOTE:` はそのリモートの根、`REMOTE:docs` は
配下を指す。`--remote NAME` を付ければ `remote:` を省略してパスだけ書ける
（rclone の `:backend:` 相当）。

---

## 2.1 L2 が答える追加の問い合わせ

`config create` を短くするために、L2 に 2 つの口を足した（`dfs5/cli.py`）。

| エンドポイント | 返すもの |
|---|---|
| `POST /v1/ost` | L3 の場所（`tls://host:port`）と、パスごとのロケータの endpoint |
| `POST /v1/paths` | 登録済みのサブツリー、書き手公開鍵、epoch、先頭版 |

`dfs5r` はこの 2 つを使って `--ost` と `--path` を解決する。

- **OST**: まずロケータの `endpoints` を見る。無ければ（初回）`/v1/ost` の広告を使う。
- **パス**: 秘密鍵の公開鍵を作り（`ssh-keygen -y` または `.pub`）、`/v1/paths` で
  一致するサブツリーを探す。複数あれば短いものを選ぶ。

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

### 3.4 削除と空ディレクトリ

dfs5 は**空のディレクトリも版に残す**。ディレクトリ塊は `{"entries": [], "format": "dfs5-dir-v1"}`
として表現され、読み出し側はそれを見て実体を作る。つまり「中のファイルが全部消えた」だけでは
ディレクトリは消えず、`pull` すると空のディレクトリごと降りてくる。

| コマンド | すること |
|---|---|
| `mkdir REMOTE:dir` | 空のディレクトリを作る（版に残る） |
| `rm REMOTE:file` | ファイルを消す。**空になったディレクトリは既定で残す** |
| `rm REMOTE:dir -R` | ディレクトリを中身ごと消す（ファイルだけ。空の階層は残す） |
| `rm REMOTE:dir -R --rmdirs` | 中身ごと消し、**空になったディレクトリも片付ける** |
| `rmdir REMOTE:dir` | 空のディレクトリだけを消す（中身があれば断る） |
| `purge REMOTE:path` | 指定パスの中身をすべて消し、ディレクトリ自身も消す |

`--rmdirs` は「rclone のように、リモートをローカルの見た目に合わせたい」とき、
付けなければ「空のディレクトリは資産として残したい」とき、と使い分ける。

`rm` の `--rmdirs` は、掃除の起点を**消したディレクトリの位置**にする。作業ツリー全体を
掃除すると、無関係な空ディレクトリまで巻き込んで消えてしまうため。

`sync --delete` は「ローカルと一致させる」操作なので、消した結果として空になった
ディレクトリも片付ける（`--rmdirs` は要らない）。

### 3.5 単一書き手の衝突

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
| `test_rm_file_leaves_empty_dir` | ファイルを消すと空ディレクトリが残る |
| `test_rm_rmdirs_prunes_empty` | `--rmdirs` で空になったディレクトリも片付く |
| `test_rm_dir_needs_recursive` | ディレクトリは `--recursive` 無しでは消さない |
| `test_rm_missing_is_an_error` | 無いパスは終了コード 2 |
| `test_mkdir_and_rmdir` | 空ディレクトリを作って消せる |
| `test_rmdir_refuses_non_empty` | 中身のあるディレクトリを `rmdir` で消さない |
| `test_purge_removes_everything` | `purge` で全部消える |
| `test_empty_dir_survives_roundtrip` | 空ディレクトリは版に残り `pull` で降りてくる |
| `test_rm_dry_run` | `rm -n` が実際に消さない |
| `test_no_default_remote_is_reported` | `--remote` 無しのパスを終了コード 2 で弾く |
| `test_remote_error_exit_code` | 知らないリモートが終了コード 2 で返る |
| `test_config_can_omit_ost_and_path` | `--ost` / `--path` を省いても L2 から解決して読み書きできる |
| `test_path_without_leading_slash_is_accepted` | `--path` は `/` で始まらなくてよい |
| `test_empty_secret_is_refused_on_write` | `tree_secret` が空のまま書こうとすると止まる |
| `test_registry_advertises_ost_and_paths` | L2 が L3 の場所と登録済みパスを返す |

`tests/test_integration.py` の `TestPullBatch` は、`list_tree` を支える読み出し側の
一括取得（1 階層 1 往復）を確かめる。

---

## 6. 使うときの注意

- **リモートは 1 つの書き込み境界**。同じサブツリーを別のリモート名で 2 つ定義して
  同時に書くと、単一書き手の CAS で片方が拒否される（設計どおり）。
- **`sync --delete` はリモートを消す**。`-n` で何が消えるか先に見ること。
- **`purge` は取り消せない。** 指定パスの中身を全部消し、ディレクトリも消す。`-n` で確認する。
- **空ディレクトリは既定で残る。** ローカルに合わせたいときは `rm --rmdirs` か
  `sync --delete` を使う。
- **`tree_secret` はリモートごとに独立**。WAN 試験のツリー（`dfs5-wan-shared-secret`）と
  別の秘密で `config create` すれば、別のツリーとして扱われる。共有したい場合は同じ秘密を使う。
  L2 からは引けない（サーバに置かない共有秘密）ので、書く前に必ず設定する。
- **`--path` は 1 つの鍵で 1 つの境界**を書く前提で省略できる。1 つの鍵を複数のサブツリーに
  使っている場合、L2 はどれか 1 つ（短いもの）を返す。そのときは `--path` を明示する。
- **認証は無い**。L3 は WireGuard / LAN の中だけで使うこと。完全性は L4 の署名で担保する。
- サーバを常駐させるなら launchd を使う。`nohup` だけだと親のセッション終了で落ちる。
