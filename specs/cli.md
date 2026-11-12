# dfs5cli（`specs/cli.md`）

## 0. 目的と位置づけ

`dfs5/cli.py` は層の試験用で、`serve` / `delegate` / `init` / `push` / `pull` という
「層の操作」をそのまま見せる。日常のファイル操作には、もっと普通の道具が要る。
そこで `dfs5/cli.py` の部品（L2 名簿クライアント、サーバ、ノード構築）をそのまま使い、
**リモート名で場所を指す** CLI を被せたものが `dfs5cli` である。

- 実装: `dfs5/cli_main.py`、`dfs5/remotes.py`
- エントリポイント: `./dfs5cli`
- 試験: `tests/test_cli_main.py`

`dfs5/cli.py` は残す。層を直接確かめる用途（`serve` の起動、`delegate` の登録、
`push`/`pull` の往復計測）では今もそちらを使う。

### インストール

pip / pipx で console script として入れられる。

```bash
pipx install .
dfs5cli --version
dfs5svc --help
```

libp2p/QUIC も使う場合は optional extra を付ける。

```bash
pipx install '.[libp2p]'
```

リポジトリ直下の `./dfs5cli` / `./dfs5svc` は、開発中にそのまま使うための
互換ラッパーとして残している。

---

## 1. 考え方

### 1.1 リモート = 書き込み境界

dfs5 の単一書き手の境界は「サブツリーのパス」である（`/example.com/alice/notes`）。
rclone のリモートはこれに対応させた。**ホスト名ではない。**

1 つのリモートが持つ情報のうち、**L2 名簿に問い合わせれば分かるものは書かなくてよい**。

| 項目 | 例 | 省略したとき |
|---|---|---|
| L2 名簿 | `172.16.1.60` | **必須**（出発点。ホスト名だけでよい） |
| 書き手の OpenSSH Ed25519 秘密鍵 | `~/.ssh/alice` | その場で作る（`~/.config/dfs5/keys/<名前>_ed25519`） |
| L3 OST の host:port | `172.16.1.60:19443` | L2 のロケータ（`endpoints`）から解決する |
| サブツリーのパス | `/example.com/alice/notes` | L2 で書き手公開鍵から探す |
| `tree_secret`（共有秘密） | — | 端末からエコーなしで読む |
| 作業ディレクトリ | `~/.cache/dfs5/<名前>` | 既定（`--workdir` で変更） |

最小の登録はこうなる。

```bash
# ホスト名だけ。鍵は作り、secret は端末から読む
dfs5cli config create scw --registry 172.16.1.60
```

#### レジストリはホスト名だけでよい

L2 の既定ポートは **9440**。`--registry` に `172.16.1.60` のようにホスト名（または IP）だけ
を渡すと、`http://` と `:9440` を補う。別のポートなら `--registry-port` で変えるか、
`host:port` をそのまま書く。

```
172.16.1.60                -> http://172.16.1.60:9440
http://host:1234           -> http://host:1234        （そのまま）
host --registry-port 19440 -> http://host:19440
```

`urlparse` で判定するので、`host:port` と `host` を取り違えない。

#### 読み取り用の代替名簿

`--registry-alternate` を繰り返すと、読み取り時のフォールバック先を登録できる。
書き込み（`announce` / `delegate`）は常に `--registry` の主名簿だけに送る。

```bash
dfs5cli create scw --registry 172.16.1.60 \
  --registry-alternate 172.16.1.61
```

主名簿は `dfs5 serve --replica http://172.16.1.61:9440` のように起動すると、
署名済みの委譲チェーン・L4 ログ・ロケータを代替名簿へ複製する。代替名簿は
root アンカーから再検証し、古いバンドルで巻き戻さない。

`--ost-alternate` を繰り返すと、書き手の主 OST とは別の読み取り専用 OST を
登録できる。書き込みは主 OST だけで行い、複製 OST にはチャンクをコピーする。
`pull` / `cat` は locator の `endpoints` を順に試すため、主 OST が停止しても
複製 OST が生きていれば読み取りを継続できる。詳細は `specs/ost-replica.md`。

#### DNSSEC から root 鍵と registry 一覧を取得する

`--dnssec-domain` を指定すると、`_dfs5.<domain>` の DNSSEC 検証済み TXT レコードから
root 公開鍵と primary/secondary registry を取得する。`--registry` は不要。

```bash
dfs5cli discover example.com

dfs5cli config create scw \
  --dnssec-domain example.com \
  --key ~/.ssh/alice \
  --secret <tree_secret>
```

DNSSEC は root 鍵と初期 registry 一覧の配布に限定し、L4 head や primary 昇格の
判断には使わない。`--registry` / `--root-pubkey` を併記した場合は、DNSSEC の内容と
一致しなければ拒否する。詳細は `specs/dnssec.md`。

#### BitTorrent archive

現在の先頭版を、署名済みメタデータ + 全 chunk + `.torrent` として保存できる。
BitTorrent はホットパスではなく、長期保存・最終復旧用である。

```bash
dfs5cli archive create scw: --out ./scw-v1
dfs5cli archive create scw: --version 3 --out ./scw-v3
dfs5cli archive verify ./scw-v1
dfs5cli archive extract ./scw-v1 ./restored
dfs5cli archive catalog .
```

実際の seeding / downloading は外部の BitTorrent クライアントで行う。
詳細は `specs/bittorrent.md`。

#### L4 版履歴

`history` は L2 が保持する署名済み L4 ログの履歴を新しい順に表示する。

```bash
dfs5cli history scw:
dfs5cli history scw:/example.com/alice --limit 20
```

L2 の API では `/v1/history` と `/v1/resolve` の `version` 指定を使う。

#### registry の手動昇格

secondary registry を primary に昇格する場合は、旧 primary を停止してから
secondary 側で state の role epoch を進める。

```bash
dfs5 promote --state-dir ~/.dfs5_server --role-epoch 2
dfs5 serve ... --role primary --role-epoch 2
```

writer 側も `config create ... --role-epoch 2` で同じ世代に更新する。
secondary は `role_epoch` が一致する書き込みだけを受け付ける。詳細は
`specs/promotion.md`。

#### libp2p/QUIC 読み取り

OST の chunk ディレクトリを libp2p/QUIC で配布し、読み取り候補に追加できる。
サーバは py-libp2p のプロセス制約のため専用プロセスで起動する。

```bash
dfs5cli libp2p-serve \
  --chunks-dir ~/.dfs5_server/ost_chunks \
  --listen /ip4/0.0.0.0/udp/0/quic-v1

dfs5cli create scw \
  --registry http://primary:9440 \
  --libp2p-peer /ip4/203.0.113.10/udp/19443/quic-v1/p2p/12D3KooW...
```

読み取りは主 OST → 複製 OST → libp2p の順に試す。書き込みは主 OST のみ。
詳細は `specs/libp2p.md`。

**L2 が OST の場所とパスを知っている理由**: L2 のロケータ（`dfs5-l2-locator-v1`）は
`endpoints` を持ち、そこに L3 の場所（`tls://172.16.1.60:19443`）が入る。これは版を
書くたびに更新される。委譲レコードは書き手の公開鍵（`writer`）を持つので、「この鍵が
書くのはどのサブツリーか」を L2 に聞ける。最初の版を書く前はロケータがまだ無いため、
L2 は `--advertise`（または bind から推定したホスト）で自分の L3 の場所を広告する。

#### 書き手の鍵はその場で作る

`--key` を省くと、`~/.config/dfs5/keys/<名前>_ed25519` に Ed25519 の鍵を作る
（`--key-dir` で場所を変えられる）。OpenSSH 形式で、パーミッションは 600。

`--key` を**渡した**のにそのパスが無い場合は、勝手に作らず使い方の誤り（終了コード 2）で
止める。既存の鍵を使いたい人が、打ち間違いで新しい鍵を作ってしまうのを避けるため。

#### tree_secret は端末から読む

`tree_secret` は L2 から引けない（サーバに置かない共有秘密だから）。**書く前に**必要になる。
`--secret` を省くと、端末から**エコーなしで 2 回**聞く。打ち間違えると復号できないツリーに
なる（サーバに平文を置かないので取り返しがつかない）ため、確認用にもう一度聞き、一致した
ものだけ採る。

```
$ dfs5cli create scw --registry 172.16.1.60
scw の tree_secret:                       ← 入力は画面に出ない
scw の tree_secret（確認のためもう一度）:  ← 同じものを打つ
[dfs5cli] リモート 'scw' を保存しました: ~/.config/dfs5/remotes.json
  registry    : http://172.16.1.60:9440
  書き手の鍵  : ~/.config/dfs5/keys/scw_ed25519（作った。OpenSSH 形式の Ed25519）
  tree_secret : *** （端末から読みました）
```

一致しなければやり直す（3 回まで）。

```
[dfs5cli] 入力が一致しません。もう一度入力してください（1/3）
```

3 回とも一致しなければ、secret を空のまま登録し、あとで `--secret` を設定するよう促す。
空のまま書こうとすると使い方の誤り（終了コード 2）で止まる。

#### `create` は `config create` の短い入口

登録は一番よく打つので、`config` を省いた入口を用意した。中身は同じ関数。

```bash
dfs5cli create scw --registry 172.16.1.60       # = dfs5cli config create scw ...
dfs5cli config show scw                         # 表示・削除・一覧は config の下
dfs5cli config delete scw
dfs5cli listremotes                             # config list と同じ
```

実装は Python の `getpass`（標準ライブラリ）。`/dev/tty` からエコーなしで読む。
パイプやリダイレクトの中では端末が無いので読まず、`--secret` を渡すよう促す。
`--no-prompt` を付けると、端末があっても読まない（スクリプト用）。

空のまま書こうとすると、黙って弱い暗号にせず使い方の誤り（終了コード 2）で止める。

#### なぜ pinentry を使わないか

パスフレーズを端末から安全に読む Unix の標準部品は **`pinentry`（`pinentry-curses`）** で、
`dialog` / `whiptail` も同種である。ただし macOS には既定で入っていないため、外部コマンドに
頼らず `getpass` で済ませている。

### 1.2 root アンカー（信頼の根）

委譲チェーンを root から検証するには、root アンカーの公開鍵が要る。これは**リモート定義に
持つ**（`root_pubkey` と、表示用の `root_fingerprint`）。

- `--root-pubkey FILE` を渡せば、その中身を使う（本番はこちら）。
- 省略すると、名簿の `/v1/paths` から取って記録する（**TOFU**）。指紋を画面に出す。
- 以降は記録した公開鍵だけを信頼し、名簿が違う値を返したら拒否する。

```text
  root アンカー: SHA256:n2ypRtbEq5vZOTK+i0WmBioSgHFEPFPCr21KWO7c4Jc （名簿から取得（TOFU））
                 これ以降この指紋だけを信頼します（違う値を返す名簿は拒否）
```

理由と限界は `specs/delegation.md` §3.5 に書いた。要は「信頼の根を相手から取ると根に
ならない」ので、初回だけ TOFU で取り、以降は手元の記録を使う。本番は明示する。

### 1.3 鍵の形式

`--key` は **OpenSSH 形式の Ed25519 秘密鍵**。PEM ではない（省略時はこの形式で作る）。

- `crypto.py` はまず `cryptography` の `load_ssh_private_key` で読み、復号できない鍵は
  `ssh-keygen -Y sign` に委ねる。どちらも OpenSSH 形式を前提にする。
- `ssh-ed25519` のみ対応。RSA / ECDSA は署名検証で弾かれる。
- パスフレーズ無しが速い。有りでも動くが、署名のたびに `ssh-keygen` が起動する。

---

## 2. コマンド

```text
dfs5cli listremotes
# 最小（ホスト名だけ。鍵を作り、secret は端末から 2 回読む）
dfs5cli create NAME --registry HOST
# ↑ は config create と同じ。以下は明示したいときだけ
dfs5cli config create NAME --registry HOST

# 省略したくないときだけ足す
#   --registry-port N  ポートを補う番号（既定 9440）
#   --key FILE         既存の Ed25519 秘密鍵（無ければ断る）
#   --key-dir DIR      鍵を作る場所（既定 ~/.config/dfs5/keys）
#   --secret VALUE     tree_secret（省くと端末から読む）
#   --no-prompt        端末から読まない
#   --ost / --path / --workdir / --epoch / --node-name
dfs5cli config create NAME --registry HOST --key FILE --ost HOST:PORT --path /sub/path \
                          [--workdir DIR] [--epoch N] [--node-name NAME]
dfs5cli config show|delete|list [NAME]

# 読み出し（版を進めない）
dfs5cli ls     REMOTE:path
dfs5cli lsd    REMOTE:path
dfs5cli lsl    REMOTE:path
dfs5cli lsjson REMOTE:path
dfs5cli size   REMOTE:path
dfs5cli cat    REMOTE:path/file
dfs5cli about  REMOTE:
dfs5cli check  REMOTE:path LOCAL_DIR

# 書き込み（1 版としてまとめる）
dfs5cli copy   LOCAL REMOTE:path [--checksum] [--include PATTERN] [--exclude PATTERN] [-n]
dfs5cli copyto LOCAL_FILE REMOTE:path/file [--checksum] [-n]
dfs5cli import_tar ARCHIVE REMOTE:path [--strip-components N] [-n]
dfs5cli mv     REMOTE:path REMOTE:path [--overwrite] [-n]
dfs5cli sync   LOCAL_DIR REMOTE:path [--delete] [--checksum] [--include PATTERN] [--exclude PATTERN] [-n]

# ディレクトリと削除
dfs5cli mkdir  REMOTE:dir
dfs5cli rm     REMOTE:path [-R|--recursive] [--rmdirs] [-n]
dfs5cli rmdir  REMOTE:dir [-n]
dfs5cli purge  REMOTE:path [-n]

# 取り出し
dfs5cli pull   REMOTE:path LOCAL_DIR [--force] [--include PATTERN] [--exclude PATTERN]

# サーバ側は cli.py のものをそのまま使う
dfs5cli serve    ... --advertise <L3 を広告するホスト>
dfs5cli serve    ... --ost-dir /Volumes/ExtSSD/dfs5/ost/<name>
dfs5cli delegate ...
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

`dfs5cli` はこの 2 つを使って `--ost` と `--path` を解決する。

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

primary / secondary registry が両方停止した場合は、`.clayfs/l2_cache.json` の
検証済み応答へフォールバックする。キャッシュも期限切れ・巻き戻しは拒否する。

### 3.2 冪等

変更が無ければ**新しい版を作らない**。判定は rclone の既定と同じく大きさを先に見て、
`--checksum` のときだけ内容アドレス（`plain_id`）まで比べる。

```
$ dfs5cli copy ./sample local:
[dfs5cli] copy OK -> v1 | 追加/更新 4 件（同じ 0 件） | sent=6303 B | 74.7 ms

$ dfs5cli copy ./sample local:
[dfs5cli] copy: 変更なし（4 ファイルが同じ）。新しい版は作りません
```

dfs5 は書き手側の索引で塊を重複排除するので、内容が同じなら `push` しても本文は送られない。
それでも版が増えるのは無駄なので、CLI 側で「変わらないなら版を作らない」を決めている。

#### 3.2.1 移動は 1 版

`mv` は同一リモート内の rename として扱い、最後に 1 版だけ push する。
`copy` + `rm` のように 2 版を消費しない。

- 宛先は「新しい名前そのもの」として解釈する（既存ディレクトリへの自動格納はしない）
- 宛先が存在する場合は既定で拒否する
- ファイル同士の置換だけは `--overwrite` で許可する
- ディレクトリの merge は行わない
- 別リモート間の移動は `copy` + `rm` を使う

#### 3.2.2 フィルタ

`copy` / `sync` / `pull` は `--include PATTERN` と `--exclude PATTERN` を受け付ける。
パターンは操作の基準ディレクトリからの相対パスに適用し、`*` / `?` / `[]` の
シェル風ワイルドカードを使える。`--exclude` は `--include` より常に優先する。

`sync --delete` では、フィルタの外側にあるリモートファイルを削除しない。
たとえば `--exclude 'docs/private/*'` を付ければ、その範囲は同期対象から完全に外れる。

#### 3.2.3 tar インポート

`import_tar` は、`.tar` / `.tar.gz` / `.tar.xz` / `.tar.bz2` を自動判定して
リモートへインポートする。展開結果は `copy` と同じく追加・更新として 1 版にまとめ、
リモートにしかないファイルは削除しない。

- 通常ファイルとディレクトリだけを許可する
- symlink / hardlink / device / FIFO は拒否する
- 絶対パスと `..` を拒否し、`\` も区切りとして正規化して検査する
- `.clayfs` は取り込まない
- `--strip-components N` で tar の先頭 N 要素を除ける
- 内容が同じファイルだけなら新しい版を作らない

```bash
dfs5cli import_tar release.tar.gz backup:
dfs5cli import_tar bundle.tar.xz backup:project --strip-components 1
```

### 3.3 一覧は内容を取らない

`ls` / `lsd` / `lsl` / `lsjson` / `size` は、ディレクトリ塊だけを辿ってファイルの中身は取らない。
取得量は**構造の階層数**で決まる（`l4_log.py::list_tree` の幅優先走査）。
`cat` は目的のファイルまでのディレクトリ塊と、そのファイル塊だけを取る。
`lsd` は直下のディレクトリだけを返す。

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
    ├── l2_cache.json             検証済みの delegation / locator / head
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

`tests/test_cli_main.py` に 47 件。

| 試験 | 確かめること |
|---|---|
| `test_config_roundtrip` | リモート定義の保存と 600 のパーミッション |
| `test_unknown_remote_is_an_error` | 知らないリモートを弾く |
| `test_copy_ls_cat_pull` | copy → cat → pull で内容が一致する |
| `test_copy_is_idempotent` | 2 回目の copy が版を作らない |
| `test_copyto_and_checksum` | 同じ内容の copyto が版を作らない |
| `test_mv_file_uses_one_version` | `mv` が 1 版でファイルを改名する |
| `test_mv_directory_and_dry_run` | ディレクトリ移動と dry-run の非更新 |
| `test_mv_refuses_collision_and_allows_file_overwrite` | 衝突拒否と `--overwrite` |
| `test_mv_rejects_cross_remote_and_descendant_destination` | 別リモート・自己配下への移動を拒否する |
| `test_copy_include_exclude` | `copy` の include / exclude |
| `test_sync_delete_does_not_touch_excluded_paths` | フィルタ外を `sync --delete` で消さない |
| `test_pull_include_and_exclude` | `pull` の include / exclude |
| `test_lsd_lists_only_directories` | `lsd` が直下のディレクトリだけを返す |
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
| `test_registry_host_only_gets_default_port` | `--registry` はホスト名だけでよく、ポートを補う |
| `test_config_create_makes_key_when_omitted` | `--key` を省くと OpenSSH 形式の鍵を作る（600） |
| `test_explicit_missing_key_is_refused` | `--key` の打ち間違いでは鍵を作らない |
| `test_no_prompt_keeps_secret_empty` | `--no-prompt` なら端末から読まない |
| `test_create_alias_exists` | `dfs5cli create` が `config create` と同じに動く |
| `test_prompt_verifies_secret_twice` | 端末では secret を 2 回聞き、不一致ならやり直す |
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
- **`--key` を省くと鍵を作る。** 既存の鍵を使いたいときは必ず `--key` で渡す。渡したパスが
  無ければ断る（打ち間違いで新しい鍵を作らないため）。
- **`--secret` を省くと端末から読む。** パイプの中で使うなら `--secret` か `--no-prompt` を
  明示する。
- **`tree_secret` はリモートごとに独立**。WAN 試験のツリー（`dfs5-wan-shared-secret`）と
  別の秘密で `config create` すれば、別のツリーとして扱われる。共有したい場合は同じ秘密を使う。
  L2 からは引けない（サーバに置かない共有秘密）ので、書く前に必ず設定する。
- **`--path` は 1 つの鍵で 1 つの境界**を書く前提で省略できる。1 つの鍵を複数のサブツリーに
  使っている場合、L2 はどれか 1 つ（短いもの）を返す。そのときは `--path` を明示する。
- **認証は無い**。L3 は WireGuard / LAN の中だけで使うこと。完全性は L4 の署名で担保する。
- サーバを常駐させるなら launchd を使う。`nohup` だけだと親のセッション終了で落ちる。
