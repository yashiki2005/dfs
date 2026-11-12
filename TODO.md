# dfs 再開用の状況メモ（`TODO.md`）

この文書は **2026-11-12 時点**で作業を中断したときの記録である。再開する人は、
まずここを読んで「どこまで動いていて、次に何をするか」を掴んでほしい。

- リポジトリ: `~/src/dfs`（`/Volumes/ExtSSD/src/dfs` へのシンボリックリンク）
- 基準コミット: `1562f01 feat: add fuse-t mount support`
- テスト: **160 件パス、1 件 skip**（`~/dfs-venv/bin/python -m pytest tests -q`）
- 作業ツリー: 未コミット差分あり（checksum 形式、フォルダ圧縮、B3 チャンク）

---

## 1. 今どうなっているか（動くもの）

### 1.1 層の実装

| 層 | 状態 | 実体 |
|---|---|---|
| L1 委譲 | 実装済み・検証済み | `l1_delegation.py`（5 不変条件、チェーン検証） |
| L2 名簿 | 実装済み | `l2_registry.py`（署名付きロケータ、CAS 追記、root へチェーン復元） |
| L3 データ平面 | 実装済み・WAN 計測済み | `l3_ost_adapter.py`（TLS/TCP、batch_has / put / get） |
| L4 一貫性 | 実装済み・evil 試験済み | `l4_log.py`（追記ログ、Merkle 塊、HeadPin、B6/B7 防御） |
| L5 実体化 | 実装済み | `l5_clayfs.py`（`dfs.fs` 経由のスナップショット連携） |
| L5 CoW 抽象 | 実装済み | `dfs/fs/`（CoW があれば CoW、無ければ実コピー） |

### 1.2 2 つの CLI

| コマンド | 役割 | 実体 |
|---|---|---|
| `./dfscli` | ローカル CLI（rclone ライク）。`ls` / `cat` / `copy` / `sync` / `pull` / `rm` / `mkdir` など | `dfs/cli_main.py` |
| `./dfssvc` | ローカルにサーバを立てる（空きポート 2 つ + 委譲まで自動） | `dfs/svc.py` |
| `python -m dfs.cli` | サーバ側の生の操作（`serve` / `delegate` / `push` / `pull`） | `dfs/cli.py` |

**注意**: 以前の名前は `dfsr` / `rclone_cli.py` だった。`122afcf` より前のメモや
手順書にある `./dfsr` は `./dfscli` に読み替える。

### 1.3 できること（実機で確認済み）

- ローカルにサーバを立てて、ファイルを push / pull できる（Mac）
- LAN（Mac ↔ Pi5）と WAN（Mac / Sakura / Scaleway の 3 拠点）で同期できる
- 同一の親版からの同時 push を CAS で拒否する（衝突コピー 0 件）
- 通信断でハングせず `ServiceUnavailableError` になる

### 1.4 速さ（計測済み）

| 場面 | 往復 | 根拠 |
|---|---|---|
| push | **1 往復**（チャンク数に依らない） | `specs/e2e_wan.md`、`specs/l3_data_plane.md` |
| pull（平らな構造） | **2 往復**（根 1 + ファイル 1） | 同上。500 ファイルでもローカルで 2 往復 |
| pull（入れ子） | 階層数 + 1 | 同上 |

WAN（RTT 285ms、20 × 128KB）で push 4.3 秒 / pull 4.0 秒。batch 系の導入前は
pull が 8.0 秒（21 往復）だった。

2026-11-12 のローカル再測では、2.62MB の初回 copy が 52.5ms、無変更 copy が 16.9ms、
128KiB read が 7.3ms。Ed25519 検証の in-process 化と DNSSEC ゾーン鍵キャッシュで
短縮した。詳細は `specs/performance.md`。

3 拠点（Mac / Sakura / Scaleway）の 2.62MB 試験では、2 複製込み push が 9.98 秒、
primary 停止後の secondary pull が 0.82 秒、Sakura 停止後の Scaleway pull が
4.15 秒で、全経路の内容が一致した。

---

## 2. 次にやること（優先順）

### 2.1 実装済み: A（L2 読み取りの可用性）

2026-11-12 に、L2 名簿の読み取りフォールバックと主→複製を実装した。

- `Remote.registry_alternates` に代替名簿を持てる
- 読み取りは主 → 代替の順に試し、書き込みは主だけに送る
- `dfs serve --replica` / `dfssvc start --replica` で、主から署名済みバンドルを複製する
- 複製側は root アンカー・委譲チェーン・L4 署名・CAS を再検証し、古いバンドルで巻き戻さない
- 回帰試験: `tests/test_availability.py`

**OST 複製**: 主 OST のチャンクを読み取り専用の複製 OST へコピーし、locator に
複数 endpoint を持たせる実装を追加した。主 OST が停止しても、複製 OST が生きていれば
`pull` / `cat` は継続できる。スプールは採用せず、書き込みは主 OST で完結させる。
詳細は `specs/ost-replica.md`。

**なぜ**: L2 名簿が落ちると**全停止**する（単一障害点）。`specs/l2_comparison.md` §2.5。
`ls` / `cat` / `pull` が名簿に届かないだけで止まる。

**前提は整っている**: `122afcf` で「名簿を信頼しない検証」を実装した。名簿が偽の委譲を
返しても拒否する（root アンカーからチェーンを検証）。だから**名簿を複数立てても、どの
答えでも安全**に扱える。

**やること**:

1. リモート定義で名簿を複数持てるようにする。案: `registry` を配列にする、または
   `registry` + `registry_alternates` を持つ。
2. `resolve` / `paths` / `ost` を**順に試し、最初に読めたものを使う**。全応答は root 公開鍵で
   検証するので、どの名簿の答えでもよい。
3. 書き込み（`announce`）は 1 つの「主」に送る。主が落ちたら失敗させる（昇格は B）。
4. 試験: 名簿を 2 つ立て、片方を止めても `ls` / `cat` / `pull` が続くこと。
   `dfssvc` を別ポートで 2 つ立てれば、1 台で試せる（下の §4 参照）。

**設計上の注意**:

- root 公開鍵は**名簿から取って信頼してはいけない**（`specs/delegation.md` §3.5.1）。
  初回だけ TOFU で取り、以降は手元の記録（`remotes.json` の `root_pubkey`）を使う。
- 名簿の選択で「どれが正しいか」を比べる必要はない。署名で検証できるため。

### 2.2 B（書き込みの複製と昇格）

primary/secondary の role と role epoch、secondary の書き込み拒否、手動昇格を
実装した。旧 primary を停止してから secondary の state を昇格し、writer の
`role_epoch` を更新する。詳細は `specs/promotion.md`。

自動選挙・quorum・lease は持たない。旧 primary を停止せずに両方を primary にすると
split-brain になるため、強固な自動昇格が必要なら lease / 合意形成を追加する。
C（合意形成）は当面やらない。

### 2.3 CLI の追加（使い勝手）

2026-11-12 に、次の CLI 機能を実装した。

| コマンド | 内容 | 状態 |
|---|---|---|
| `mv` | 同一リモート内の移動・改名を 1 版で行う。既存宛先は拒否し、ファイル同士だけ `--overwrite` 可 | 実装済み |
| `--exclude` / `--include` | `copy` / `sync` / `pull` の相対パスフィルタ。`sync --delete` はフィルタ外を消さない | 実装済み |
| `lsd` | 直下のディレクトリだけを一覧する | 実装済み |
| `import_tar` | `.tar` / `.tar.gz` / `.tar.xz` / `.tar.bz2` を安全に 1 版でインポートする | 実装済み |
| `mount` | fuse-t / fusepy でリモートをローカルにマウントする | 実装済み |
| `--checksum` | `size` / `crc32` / `sha1` / `plain_id` の変更検出 | 実装済み |
| フォルダ圧縮 | `user.dfs.compression` xattr と `DFSB3` codec ヘッダー | 実装済み |

書き手の内容アドレス索引は `.clayfs/ost_index.json` に永続化する。tree_secret が
変わると `address_key` が一致しなくなるため、古い索引は自動的に無効化される。

`mv` は宛先を新しい名前そのものとして扱う（既存ディレクトリへの自動格納や merge はしない）。
詳細は `specs/cli.md` §3.2.1〜3.2.2。

### 2.4 配置（完成時）

`pyproject.toml` を追加し、pip / pipx で配布できるようにした。

- console scripts: `dfscli = dfs.cli_main:main`、`dfssvc = dfs.svc:main`
- 必須依存: `cryptography` / `dnspython`
- optional extra: `libp2p`
- `pip install --no-deps --target ... .` で wheel を作り、両エントリポイントの起動を確認済み
- リポジトリ直下のシェルラッパーは開発用の互換入口として残す

現在の Mac の OST は `/Volumes/ExtSSD/dfs/ost/` 配下に置き、各 state dir の
`ost_chunks` はそこへの symlink にしている。新規サービスは
`dfssvc start --ost-dir ...`、直接起動は `dfs serve --ost-dir ...` で指定できる。

### 2.5 root アンカーの配布（大規模運用のとき）

DNSSEC の `_dfs.<domain>` TXT から root 公開鍵と registry 一覧を取得する方式を
実装した。`dfscli discover <domain>` と `config create --dnssec-domain <domain>` で使う。

DNSSEC は **root 鍵と初期 registry 一覧の配布**に限定し、L4 head や primary 昇格の
判断には使わない。primary / secondary は DNSSEC レコードまたは静的設定で決め、
「最初に起動したサーバを root にする」方式は採用しない。

詳細は `specs/dnssec.md`。クライアント側で root trust anchor から DNSKEY/DS
チェーンを検証し、TXT の RRSIG を確認する。AD ビットは `validate=False` の
旧互換経路だけで使う。

### 2.5.1 BitTorrent archive（MVP 実装済み）

現在の先頭版を、署名済みメタデータ + 全 chunk + `.torrent` として保存する
`archive create` を実装した。BitTorrent はホットパスではなく、過去版の長期保存・
最終復旧用とする。`archive verify` と `archive extract` も利用できる。

詳細は `specs/bittorrent.md`。v1 torrent の SHA-1 は transport 用で、chunk の
真正性は DFS の SHA-256 で検証する。BitTorrent v2、L4 への archive descriptor
統合、erasure coding は未実装。

### 2.5.2 libp2p/QUIC chunk source（実験実装）

libp2p を OST の追加 ChunkSource として実装した。最初の TCP 試作は別プロセス間で
カスタムストリームが動かなかったが、`enable_quic=True` と
`/ip4/.../udp/.../quic-v1` では動作することを確認した。

`dfscli libp2p-serve` で chunk ディレクトリを QUIC 配布し、クライアントは
`--libp2p-peer` で読み取り候補に追加する。書き込みは従来の主 OST のまま。
詳細は `specs/libp2p.md`。

### 2.6 検証が足りていないもの

| 項目 | 状況 | やり方 |
|---|---|---|
| 3 台以上の同時参加 | 自動試験と実機 3 拠点（Mac / Sakura / Scaleway）を実施済み | 1 台で複数起動（§4）。足りなければ Docker |
| 長時間運用・連続 push/pull の劣化 | 未実施 | — |
| WAN での 100 塊以上の実測 | 未実施 | 20 ファイルのみ。ローカルで 500 は確認 |
| 実効スループット | 未計測 | 所要時間とバイト数からの概算のみ |
| 高遅延の追加注入（`tc qdisc`） | 未実施 | Scaleway の実測 285ms を代用 |
| LAN 越しの 2 OST（ストライピング） | 未実施 | ローカル検証のみ（`TestL3Striping`） |
| 1,000 塊以上の再計測 | 未実施 | — |
| Pi5 での pytest | 未実施 | Mac のみ |

### 2.7 未実装（必要になったとき）

| 項目 | 状況 |
|---|---|
| mini_lustre との RPC アダプタ | 未実装。そもそも mini_lustre 自体が試作なので、必要なら載せ替えを検討 |
| DHT によるノード発見 | 未実装。`specs/delegation.md` §3.5.5 に、発見後の排除の設計を書いた |
| 名簿のキャッシュ | 実装済み（`.clayfs/l2_cache.json`、全 registry 停止時の読み取りフォールバック） |
| 過去の版の取り出し（ロールバック） | 実装済み。`/v1/history` / `/v1/resolve?version` / `dfscli history` / `archive create --version` |

---

## 3. 設計の要点（再開時に効く知識）

### 3.1 名簿を信頼しない

信頼の根は **root アンカーの公開鍵 1 つ**。`resolve` は末端の委譲に**チェーン全体**と
`root_anchor` を足して返し、クライアントは `verify_delegation_chain` で root から検証する。
署名を検証する鍵は「**検証で確定した writer**」だけを使う（名簿が名乗った writer は使わない）。

```
名簿が root 公開鍵として攻撃者の鍵を返す → 手元の記録と食い違うので拒否
```

`specs/delegation.md` §3.5 に詳細。試験は `tests/test_root_anchor.py`（7 件）。

**限界**: TOFU 前（root 未設定）は、初回に欺かれると通る（SSH の `known_hosts` と同じ）。
本番は `--root-pubkey` で初回から固定する。この「通ってしまう」こともテストに残してある。

### 3.2 空のディレクトリも版に残る

ディレクトリ塊は `{"entries": [], "format": "dfs-dir-v1"}` として表現され、読み出し側は
それを見て実体を作る。`rm` でファイルを消してもディレクトリは残り、`pull` すると空の
ディレクトリごと降りてくる。片付けるには `rm --rmdirs` か `sync --delete`。
`specs/cli.md` §3.4。

### 3.3 送信元ポートを固定する

WireGuard のスポーク（Scaleway）は `ListenPort` を固定してある。エフェメラルだと送信元
ポートが変わり、ハブ（Sakura）側が最後に受信したポートから学習する都合で一時的に不通に
なる。ハブ側の keepalive も対称に揃えてある（`specs/e2e_wan.md`）。

### 3.4 ハマったところ

| 症状 | 原因 | 対処 |
|---|---|---|
| `ls` が「先に touch しろ」と言う | 参照系を `create=False` で呼んでいた | 参照系も作業ディレクトリを作る |
| `create` したのに「委譲が無い」と言う | `dfssvc start` が委譲を登録していなかった | `start` に含めた |
| 空きポートを見落とす | `SO_REUSEADDR` 付き bind が `0.0.0.0:N` を素通り | 接続を試す 2 段判定に |
| 多段委譲が時刻のずれで落ちる | 中間と末端の有効期間が同じ | 中間を 1 日長く |
| 委譲失敗でサーバが孤児に残る | `start` が例外時に止めていなかった | 失敗時は必ず止める |
| テストでサーバが残る | `addCleanup` の順序 | `tearDown` で記録を全部止める |

---

## 4. 検証の仕方（1 台で複数ノード）

`dfssvc` を別ポートで複数立てれば、1 台で「複数の拠点」を模擬できる。

```bash
cd ~/src/dfs

# 名簿を 2 つ立てる（A の試験用。別ポートになる）
./dfssvc start --name node-a --port 20000
./dfssvc start --name node-b --port 20010
./dfssvc list

# やめる
./dfssvc stop node-a --forget
./dfssvc stop node-b --forget
```

- `--port` は「この番号から連続した空きを探す」起点。L2 が 1 つ目、L3 が 2 つ目。
- 名前ごとに状態ディレクトリ（`~/dfssvc/<名前>/`）と鍵が分かれる。
- `--advertise` で広告するホストを変えられる（既定は `--host` から推定）。
- ネットワーク分断や遅延も試すなら Docker（`docker network create` + 各コンテナに
  `tc netem`）を使う。ポート違いでは再現しない。

サーバ側のタイムアウトは環境変数で変えられる（`DFS_L2_TIMEOUT`、`DFS_OST_SOCKET_TIMEOUT`、
`DFS_OST_CONNECT_TIMEOUT`）。`dfscli` も `dfssvc` も `os.environ` をそのまま見る。

---

## 5. 環境の現状（2026-11-12）

### 5.1 手元（Mac）

| もの | 状態 |
|---|---|
| launchd のサーバ | `com.example.dfs-local`（L2 19440 / L3 19443、`~/dfs-local/`）**稼働中** |
| `dfssvc` のサービス | `local`（L2 19441 / L3 19442、`~/dfssvc/local/`）**稼働中** |
| `dfscli` のリモート | `local`（`http://127.0.0.1:19441`）のみ |
| Python | `~/dfs-venv/bin/python`（3.12、`cryptography` 入り） |

**注意**: 上記の 2 つのサーバは `122afcf` より前のコードで起動している。root 公開鍵を
返すのは新しいコードなので、`root_pubkey` を使う試験をする前に再起動が要る
（`launchctl bootout` → `bootstrap`、`./dfssvc stop local` → `start`）。

### 5.2 遠隔（WireGuard）

| 拠点 | 接続 | 備考 |
|---|---|---|
| Scaleway | `ubuntu@172.16.1.60`（公開 `51.15.35.162`） | RTT 約 285ms。`ListenPort` 固定済み |
| Sakura | `ubuntu@yashiki.top`（172.16.1.254） | ハブ。RTT 約 21ms。keepalive 対称 |
| Pi5 | `yy@192.168.0.7` | RTT 約 0.5ms |

**注意**: WireGuard の経路は不安定なときがある。テスト中に Mac → Scaleway が数分不通に
なった（公開 IP と Sakura 経由では到達できた）。断が起きたら時刻を控えると追いやすい。

dfs のサーバは**どの拠点でも止めてある**（確認済み）。再開時に立て直す。

---

## 6. 再開の手順

```bash
cd ~/src/dfs

# 1. 状態の確認
git log --oneline -3
git status --short          # 空ならクリーン
~/dfs-venv/bin/python -m pytest tests -q   # 160 件パス、1 skip（約 171 秒）

# 2. サーバを立てる（新コードで）
./dfssvc list               # 既存のサービスを確認
./dfssvc start --name work --port 20000
./dfssvc env work           # dfscli の設定行が出る

# 3. つないで使う
./dfscli create work --registry http://127.0.0.1:20001 \
    --key ~/dfssvc/work/keys/writer --secret <tree_secret>
./dfscli ls work:
./dfscli config show work   # root_fingerprint が記録されているはず
```

そのあと §2.1（A: 読み取りの可用性）に進む。
