# L3 データ平面の仕様と判断（`specs/l3_data_plane.md`）

## 0. 目的と位置づけ

本文書は `PLAN.md` 段階 4（L3: データ平面）の計測結果と判断を記録する。
`DESIGN.md` §10 の問い 5（内容アドレッシングと暗号化の両立）は §1 で解決済みであり、
ここでは「何を土台にし、どこまで自前で持つか」を決める。

- ハーネス: `bench/l3_bench.py`
- 生データ: `bench/results/20261111-195612-l3-local.json`
- 実測環境: macOS arm64、Python 3.12、ローカル（ループバック）

---

## 1. 暗号と内容アドレス（解決済み）

重複排除の判定は**暗号化の前**に行う。単一書き手なので、判定の主体は OST ではなく書き手自身である。

| 要素 | 方式 |
|---|---|
| 内容アドレス | `plain_id = HMAC(K_addr, "dfs-plain-id-v1:" \|\| plaintext)`。`K_addr` は長期固定 |
| 暗号 | ChaCha20-Poly1305。**Nonce は毎回 `os.urandom(12)`** |
| 暗号化鍵 | `K_enc = HMAC(tree_secret, "dfs-chunk-key-v1:" \|\| plain_id)`。epoch で回してよい |
| 保管キー | `wire_id = SHA256(ciphertext)` |
| 検証 | `wire_id` の照合 → AEAD タグ → 復号後の `plain_id` 再計算（A2 を三段で検出） |
| 圧縮 | `DFSB3` ヘッダーに codec と元サイズを保存。平文を圧縮してから暗号化 |

`plain_id` の導出鍵と暗号化鍵を分離しているので、鍵ローテーション後も過去のチャンクと重複排除できる。
Nonce がランダムでも重複排除率は落ちない（判定は Nonce を使わない）。

---

## 2. 転送効率の実測

ファイルツリーを一括 PUT したときの送信量と往復回数。

| ファイル数 × サイズ | ペイロード | 所要時間 | 送信量 | 暗号文本体 | 往復 | 送信/ペイロード |
|---|---|---|---|---|---|---|
| 10 × 4KB | 40KB | 15.3 ms | 45,303 B | 43,713 B | **2** | 1.106 |
| 100 × 4KB | 400KB | 7.0 ms | 449,763 B | 436,293 B | **2** | 1.098 |
| 100 × 64KB | 6.4MB | 24.7 ms | 6,593,863 B | 6,580,393 B | **2** | **1.006** |

- **通常規模の往復回数はファイル数に依存しない。** 存在確認（HAS）と本体送信（PUT）の
  2 往復で、100 ファイルでも同じ。クライアントは 1 回の HAS を 1,024 件、
  PUT を 1,024 件または 64 MiB ごとに区切るため、それを超える場合は複数往復になる。
- 固定費は 1 ファイルあたり約 64 バイト（plain_id 32 + nonce 12 + tag 16 + フレーム）＋ディレクトリ塊。
  大きいファイルほど比率が 1 に近づく。

### 2.1 重複排除

| 場面 | 暗号文本体の送信量 |
|---|---|
| 同一内容 2 ファイル（同じバッチ） | **8,757 B**（1 ファイル 8,192 B ＋ ディレクトリ塊 565 B） |
| 同じツリーを再送（無変更） | **0 B**（索引と HAS のみ） |
| 別名で同一内容を追加（別バッチ） | **697 B**（ディレクトリ塊のみ。本文は再送しない） |

同一バッチ内で同一内容を二重送信していたバグを修正した（`l4_log.py::_stage`）。
送信待ちの塊を「未送信」と誤判定していたのが原因で、回帰テスト
`TestL3ContentDedup` を追加した。

索引は `.clayfs/ost_index.json` に永続化する。CLI の別プロセス実行でも
`plain_id -> (wire_id, store_id, codec)` を再利用できる。索引には内容アドレス鍵の
指紋 (`address_key`) を記録し、tree_secret の変更後は古い索引を無効化する。
20 × 128KiB の push 後、1 ファイルだけ変更して別プロセスから再 push した場合、
送信量は 2,628,420 B から 5,731 B に減った。

---

## 2.2 WAN の往復回数

LAN の計測（§2）だけでは往復回数の問題が見えなかった。RTT 285ms の WAN では
「チャンクごとに 1 往復」が致命的になる。そこで `l4_log.py::upload_directory` を直し、
往復をチャンク数から切り離した。

| 場面 | 旧の往復 | 新の往復 |
|---|---|---|
| push（索引ヒットしたチャンクが N 個） | N 回の `batch_has` + 1 回の PUT | **1 回の `batch_has`（まとめて）+ 1 回の PUT** |
| push（新規チャンクが N 個） | — | **1 回の `batch_has` + 1 回の PUT**（`assume_absent=True`） |
| pull（ファイル N 個、平ら） | 根 1 + ファイル N | **根 1 + ファイル 1 = 2 往復** |
| pull（入れ子 D 階層 + ファイル） | ディレクトリ塊 + ファイルごと | **D 往復 + ファイル 1 往復** |

実装の要点:

- `batch_has` をチャンクごとに撃つのをやめ、索引ヒットを `reused` に溜めて最後に 1 回だけ送る。
- 新規に暗号化した塊は「サーバに無い」と分かっているので、`batch_put_if_absent(..., assume_absent=True)`
  で内部の `batch_has` を省略する。送信自体はクライアント上限（1,024 件 / 64 MiB）ごとに分割する。
- 一括 HAS で「サーバから消えていた」塊が見つかった場合だけ、もう 1 回走査して作り直す
  （ディレクトリ塊は子の `wire_id` を含むため、部分差し替えでは整合しない）。
- 読み出しは `download_directory` を 2 段に分ける。**ディレクトリ塊は幅優先で 1 階層 1 往復**、
  **ファイル塊は最後に store ごと・上限ごとに一括取得**する。1 回の応答が大きくなりすぎないよう、
  マニフェストの `size` から先に分かる見積りで組を切る（`DFS_BATCH_CHUNKS` = 既定 1024、
  `DFS_BATCH_BYTES` = 既定 16 MiB）。同じ `wire_id` は 1 回しか取りに行かない。

ファイル本体は 8 MiB ごとの独立した塊に分ける。旧版の「ファイル全体を 1 塊」とする
マニフェストも読める。新形式のファイルエントリは `chunks` に、各 chunk の
`plain_id`、`wire_id`、`offset`、`size`、配置 store を持つ。これにより L3 の
1 塊 256 MiB 上限を超えるファイルも保存でき、大きなファイルの一部だけを重複排除できる。

WAN 実測（20 × 128KB、RTT 278〜285ms、`specs/e2e_wan.md`）:

| 経路 | push 往復 | push 所要 | pull 往復 | pull 所要 |
|---|---|---|---|---|
| Mac → Scaleway（278.5ms） | **1** | 4,391ms | **21** | 8,025ms |
| Sakura → Scaleway（279.8ms） | **1** | 3,937ms | **23** | 7,692ms |
| Mac → Sakura（22.4ms） | **1** | 923ms | **21** | 953ms |

push は往復が固定なので、所要時間はほぼ RTT と転送量で決まる。
pull も batch 系の導入後は往復がファイル数に依存しなくなった（下記）。

batch 導入の前後（20 × 128KB = 2.13MB）:

| 経路 | RTT | pull 往復 | pull 所要 |
|---|---|---|---|
| Mac → Scaleway | 275.8ms | **21 → 2** | **8,025 → 4,010ms** |
| Sakura → Scaleway | 275.1ms | **23 → 2** | **7,692 → 3,644ms** |
| Mac → Sakura | 22.1ms | **21 → 2** | **953 → 534ms** |

ローカルの回帰では、500 ファイルの平らな構造でも 2 往復、入れ子 3 階層 + 53 ファイルで 4 往復。
残るのは転送量そのもので、往復の回数はもう支配的でない。

回帰テスト:

- `TestWanRoundTrips::test_assume_absent_skips_has` — `assume_absent=True` は HAS を送らない。
- `TestWanRoundTrips::test_push_round_trips_do_not_scale_with_chunks` — チャンク 100 個でも 2 往復以下。
- `TestWanRoundTrips::test_ost_timeout_env_vars_are_honored` — タイムアウトが環境変数で変わる。
- `TestWanRoundTrips::test_server_socket_timeout_is_actually_applied` — サーバのソケットに実際に効く。
- `TestWanRoundTrips::test_l2_timeout_env_var_is_honored` — L2 HTTP のタイムアウトが変わる。
- `TestPullBatch::test_flat_pull_is_two_round_trips` — 100 ファイルの pull が 2 往復。
- `TestPullBatch::test_nested_pull_is_one_round_trip_per_level` — 入れ子は 1 階層 1 往復。
- `TestPullBatch::test_same_chunk_fetched_once` — 同一内容の塊は 1 回しか取らない。
- `TestPullBatch::test_batch_get_split_by_size_cap` — `DFS_BATCH_CHUNKS` で組を絞れる。
- `TestPullBatch::test_missing_chunk_is_reported` — 欠落は黙って欠けず例外になる。

---

## 3. mini_lustre の OST を「そのまま」使えるか

**結論: そのままでは使えない。** `DESIGN-ANSWER.md` の「無改造流用」という記述は誤りだった。

| 項目 | mini_lustre OST | dfs L3 |
|---|---|---|
| フレーム | `>II`（JSON 長、payload 長）+ JSON + payload | 1 バイト opcode + 64 バイト wire_id + `>I` 長 + 本体 |
| 要求 | `{"action":"write_chunk","args":{...}}` | 独自バイナリ `H`/`P`/`G`/`B`/`M`/`F` |
| 応答 | 同じ 8 バイトヘッダ + JSON + payload | 1 バイト status（`O`/`E`/`U`） |
| 塊の識別 | `(file_id, chunk_index)` | `wire_id`（暗号文の SHA-256） |
| 一括操作 | 無し（個別 `read_chunk` / `write_chunk`） | `batch_has` / `batch_put_if_absent` / `batch_get` |

実測: dfs の `H` フレームを mini_lustre の OST に送ると、最初の 4 バイト（`H` + wire_id の先頭 3 バイト）が
JSON 長として読まれ、`RPC JSON length exceeds limit` でエラーになる。
一方、mini_lustre の正しいフレームはそのまま通り、`{"status":"ok","bytes_written":5}` を返す。

**さらに重要な点**: mini_lustre は `(file_id, chunk_index)` で塊を識別するため、
同じ `wire_id` の塊を別のファイルとして置くと、**別チャンクとして保存される**。
つまり mini_lustre の上では、内容アドレスによる OST 側の重複排除はできない。

---

## 4. 判断

### 4.1 libtorrent は導入しない

- 100 ファイル・6.4MB の転送が 2 往復・24.7ms で終わる。
- libtorrent はハンドシェイクとメタデータ検証の固定費がかかり、この規模では利点がない。
- 1,000 塊以上、または多数のピアから並列に引く必要が出た時点で再検討する（`PLAN.md` の判定どおり）。

### 4.2 mini_lustre へは RPC アダプタを挟む

無改造流用はできない。将来 mini_lustre の OST を保管先に使う場合は、
**dfs の `wire_id` を `file_id`/`chunk_index` に写すアダプタ層**を置く。

ただしこの方法では mini_lustre 側の識別子が内容に依存しないため、
重複排除は**書き手の索引（byte 単位の省略）だけ**に頼ることになる。
OST 側で同じ塊を共有させることはできない。

### 4.3 現行の独自 L3 を維持する

初期実装では `dfs/l3_ost_adapter.py`（クラス名は `ChunkStoreServer`、モジュール別名 `dfs/l3_store.py`）の TLS/TCP を使う。

理由:

- 2 往復で完結し、一括操作がある（`batch_has` / `batch_put_if_absent` / `batch_get`）。
- 塊の識別が `wire_id` なので、書き手の索引とそのまま一致する。
- 無認証である点は運用で補う（LAN 内または WireGuard 内に限定し、完全性は L4 の署名で担保する）。

**この OST を公開ネットワークに置かないこと**を、運用上の必須条件とする。

---

## 5. 残課題

| 項目 | 状態 |
|---|---|
| 標準 AEAD・ランダム Nonce | 実装済み |
| 書き手側の索引による重複排除 | 実装済み（同一バッチのバグも修正、`.clayfs/ost_index.json` に永続化） |
| 一括 PUT / 一括 GET / 一括 HAS | 実装済み |
| mini_lustre との RPC アダプタ | **未実装**（必要になったとき） |
| libtorrent | **導入しない**（規模が小さいうち） |
| 大規模（1,000 塊以上）の再計測 | **未実施** |
| WAN（RTT 285ms）での実機計測 | **実施済み**（push 1 往復、pull 2 往復。`specs/e2e_wan.md`） |
| pull の往復削減（`batch_get` の一括化） | **実装済み**（平らな構造で 2 往復） |

---

## 6. ストライピング

複数の OST に塊を分散できる。**既定は 1 OST** で、2 個以上を渡したときだけ分散する。

```python
# 既定（1 OST）
builder = MerkleTreeBuilder(crypto, ost0)

# 分散（round-robin）
builder = MerkleTreeBuilder(crypto, ost0, stores={"ost0": c0, "ost1": c1})
```

| 項目 | 挙動 |
|---|---|
| 割り当て | `stores` の順に round-robin。1 個なら常に既定 |
| 配置の記録 | ディレクトリ塊の各エントリに `store` を持たせる。既定の OST のときは省略する（旧リーダーとの互換） |
| 読み出し | エントリの `store` を見て該当 OST から取得する。根の塊は `root_store` で渡す（省略時は既定） |
| 重複排除 | `plain_id -> (wire_id, store_id)` を索引に持つ。旧形式の `str` も読める |

**実測（ローカル、2 OST、10 ファイル）**: OST0 に 6 個、OST1 に 5 個の塊が置かれ、
互いに重複しない。索引なしの新しい読み手でも全体を復元できた。

回帰テストは `TestL3Striping`（1 OST 既定、2 OST 分散、復元）にある。
