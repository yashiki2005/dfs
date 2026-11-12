# WAN 実機試験（Scaleway / Sakura）と遅延耐性（`specs/e2e_wan.md`）

## 0. 目的と位置づけ

LAN（RTT 2ms）では動いていた dfs が、WAN（RTT 20〜285ms）でも動くか、
また WAN の遅延と往復回数がどこまで耐えられるかを実機で確かめる。

- ハーネス: `bench/e2e_wan.py`
- 生データ:
  - `bench/results/20261111-205551-mac-to-scaleway-wan.json`
  - `bench/results/20261111-205831-sakura-to-scaleway-wan.json`
  - `bench/results/20261111-205952-mac-to-sakura-wan.json`
- 実行日: 2026-11-11
- 接続: WireGuard 上の 3 拠点（Mac / Scaleway / Sakura）

---

## 1. 構成

```text
[Mac]                [Sakura (172.16.1.254)]                 [Scaleway (172.16.1.60)]
clayfs (L5)          dfs serve （比較用サーバ）              dfs serve
  └ tree/ ──push──▶  L3 ChunkStore (TLS 19443) ─┐             L3 ChunkStore (TLS 19443)
  .clayfs/                                       │             L2 名簿 (HTTP 19440)
       ▲──pull──── L4 追記ログ ◀── L2 名簿 ───────┴─────────────┘
```

| 拠点 | 接続 | RTT（実測平均） | 環境 |
|---|---|---|---|
| Mac | 起点 | — | macOS arm64、Python 3.12 |
| Scaleway | `ubuntu@172.16.1.60` | **278.5ms** | x86_64、1vCPU/950MB |
| Sakura | `ubuntu@yashiki.top`（172.16.1.254） | **22.4ms** | x86_64、2core/960MB |

| 項目 | 値 |
|---|---|
| L2 | `http://<host>:19440`（Symbolic Registry, HTTP） |
| L3 | `tls://<host>:19443`（TLS 1.3） |
| 状態ディレクトリ | 各拠点とも `~/dfs_wan/server_state` |
| 部屋の既存サービス | Scaleway の dfs4 資産とは別ポート。**止めていない** |
| 3 拠点の共有 | `tree_secret` と委譲鍵を共有（単一書き手の試験） |

---

## 2. 事前に直したこと（WAN 対応）

現行コードは WAN で失敗した。理由は「タイムアウトが固定」かつ「往復回数がチャンク数に比例」の 2 点。

### 2.1 タイムアウトの環境変数化

| 箇所 | 旧 | 新（既定） | 環境変数 |
|---|---|---|---|
| L2 HTTP | 5.0 秒固定 | 10 秒 | `DFS_L2_TIMEOUT` |
| L3 サーバ側ソケット | 2.0 秒固定 | 30 秒 | `DFS_OST_SOCKET_TIMEOUT` |
| L3 クライアント接続 | 3.0 秒固定 | 10 秒 | `DFS_OST_CONNECT_TIMEOUT` |

不正値・負値を設定したときは既定に戻す（無制限に待たない）。

### 2.2 往復回数の削減（push 側）

`MerkleTreeBuilder._stage` は**チャンクごとに `batch_has` を呼んでいた**。
これを、索引ヒットをいったん溜めて**最後に 1 回だけ一括 HAS**する形に変えた。
送信も `batch_put_if_absent(..., assume_absent=True)` を使い、1 往復で PUT する。

結果として 1 回の push は **HAS 1 往復 + PUT 1 往復**に固定される。

| 場面 | 旧 | 新 |
|---|---|---|
| push（20 チャンク） | チャンク数に比例（約 20+ 往復） | **1 往復** |

### 2.3 往復回数の削減（pull 側・batch 系）

`download_directory` は**塊ごとに `get` を呼んでいた**（`batch_get` は 1 塊ずつ）。
これを、取得を 2 段に分けた一括取得に変えた。

- **ディレクトリ塊**: 幅優先で回り、**1 階層ぶんを 1 回の `batch_get`** にまとめる。
- **ファイル塊**: 最後に store ごと・上限ごとに `batch_get` でまとめて取得する。
  大きさの上限はマニフェストの `size` から先に分かるので、応答が大きくなりすぎない。

これで往復は「ファイル数」ではなく「階層数 + 組数」だけで決まる。

| 構造 | 旧 | 新 |
|---|---|---|
| 平らなディレクトリ（20 / 100 / 500 ファイル） | 21 / 101 / 501 往復 | **2 往復**（根 1 + ファイル 1） |
| 入れ子 3 階層 + 53 ファイル | 56 往復 | **4 往復** |

`DFS_BATCH_CHUNKS`（既定 1024）と `DFS_BATCH_BYTES`（既定 16 MiB）で組を絞れる。
同一内容の塊は 1 回しか取りに行かない（重複排除は読み出し側でも効く）。


---

## 3. 結果

### 3.1 3 拠点の比較（20 × 128KB = 2.13MB）

batch 系（§2.2 の push、§2.3 の pull）を入れた後の実測。

| 経路 | RTT | push 往復 | push 所要 | pull 往復 | pull 所要 | 内容一致 | CAS | 衝突コピー | 通信断 |
|---|---|---|---|---|---|---|---|---|---|
| Mac → Scaleway | 275.8ms | **1** | 4,299ms | **2** | 4,010ms | 一致 | 拒否 | 0 件 | 即失敗 |
| Sakura → Scaleway | 275.1ms | **1** | 3,699ms | **2** | 3,644ms | 一致 | 拒否 | 0 件 | 即失敗 |
| Mac → Sakura | 22.1ms | **1** | 910ms | **2** | 534ms | 一致 | 拒否 | 0 件 | 即失敗 |

- すべて `ALL OK`。`bench/results/*-batch-wan.json` の `verdict` が全項目 true。
- **push の往復は RTT にもチャンク数にも依存せず 1 回**。
- **pull の往復もファイル数に依存せず 2 回**（根 1 + ファイル 1）。
- pull の所要はどの中継でも半減した（8,025 → 4,010ms、7,692 → 3,644ms、953 → 534ms）。
  残るのは主に 2.1MB の転送時間そのもので、往復の回数ではない。

#### 3.1.1 batch 導入の前後

| 経路 | push 往復 | push 所要 | pull 往復 | pull 所要 |
|---|---|---|---|---|
| Mac → Scaleway | 1 → 1 | 4,391 → 4,299ms | **21 → 2** | **8,025 → 4,010ms** |
| Sakura → Scaleway | 1 → 1 | 3,937 → 3,699ms | **23 → 2** | **7,692 → 3,644ms** |
| Mac → Sakura | 1 → 1 | 923 → 910ms | **21 → 2** | **953 → 534ms** |

push は既に 1 往復に固定されていたため変化しない。pull は往復が 1/10 以下になり、
所要が半分になった。残りは転送量（2.1MB）と RTT の積で、往復の回数はもう支配的でない。

### 3.2 往復回数の内訳

```text
push : [HAS 1] + [PUT 1]                                  = 1（新規・無変更とも）
pull : [根の GET 1] + [ファイルの GET 1]                    = 2（平らなディレクトリ）
       入れ子は「1 階層 = 1 往復」+ ファイル 1        = 階層数 + 1
```

`round_trips` は `OSTClient.round_trips`（L3 のみ）を CLI の `--metrics` で出した値。
L2 の往復は含まない。

### 3.3 耐障害（通信断）

サーバプロセスを止めた状態で push した。

| 経路 | 返り方 | 所要 | 例外 |
|---|---|---|---|
| Mac → Scaleway | 即失敗（ハングしない） | 399ms | `ServiceUnavailableError` |
| Sakura → Scaleway | 即失敗 | 938ms | `ServiceUnavailableError` |
| Mac → Sakura | 即失敗 | 138ms | `ServiceUnavailableError` |

接続失敗・読み取りタイムアウト・TLS 失敗を `ServiceUnavailableError` に正規化した。
呼び出し側は「サーバ停止」と同じ扱いで再試行判断ができる。

### 3.4 単一書き手の排他

3 経路すべてで、同じ親版から後着の push が `ConflictError` になり、
衝突コピーは 0 件だった。LAN の結果（`specs/e2e_lan.md`）と同じ挙動が WAN でも成立する。

---

## 4. 何が確かめられたか

- **WAN で dfs が動く。** RTT 285ms・3 拠点で push/pull が完走した。
- **push の往復は固定。** チャンク数にも RTT にも依存せず 1 回で終わる。
- **高遅延でも単一書き手が効く。** 後着は拒否され、三方向マージは起きない。
- **通信断でハングしない。** すべて明示的な例外で返る。
- **既存サービスを止めずに試験できる。** dfs4 資産と別ポートで共存した。

---

## 5. 測れていないこと／残課題

| 項目 | 状態 |
|---|---|
| pull の往復削減（batch 系） | **実施済み**。平らな構造は 2 往復、入れ子は階層数 + 1 |
| 100 塊以上の pull 実測（WAN） | 未実施（本試験は 20 ファイル。ローカルでは 500 ファイルで 2 往復を確認） |
| 実効スループット | 未計測（所要時間とバイト数からの概算のみ） |
| 高遅延の追加注入（`tc qdisc`） | 未実施。Scaleway の実測 285ms を WAN 条件として使った |
| 3 台以上の同時参加 | 未実施（サーバ 1 + クライアント 1〜2 の構成のみ） |
| 長時間運用・連続 push/pull の劣化 | 未実施 |
| WireGuard 経路の安定性 | 試験中に Mac→Scaleway の WG が一時不通になった（復旧後は再現せず）。経路自体の可用性は本試験の範囲外 |

---

## 6. 再現方法

```bash
# サーバ側（例: Scaleway）
cd ~/src/dfs
nohup python3 -m dfs.cli serve --bind 0.0.0.0   --registry-port 19440 --ost-port 19443   --root-anchor /example.com --root-pubkey ~/dfs_wan/keys/root.pub   --state-dir ~/dfs_wan/server_state   > ~/dfs_wan/serve.log 2>&1 < /dev/null &

# Mac → Scaleway（ハーネスが配置・委譲・計測まで行う）
python bench/e2e_wan.py --mode wan --label mac-to-scaleway \
  --server-host 172.16.1.60 --server-ssh ubuntu@172.16.1.60 \
  --server-key ~/.ssh/pi-mock-test --reset

# Sakura → Scaleway（クライアントを ssh 先で実行）
python bench/e2e_wan.py --mode wan --label sakura-to-scaleway \
  --server-host 172.16.1.60 --server-ssh ubuntu@172.16.1.60 \
  --server-key ~/.ssh/pi-mock-test \
  --client-ssh ubuntu@yashiki.top --client-key ~/.ssh/id_ed25519_sakura --reset

# ハーネス自体の自己検証（Mac 内で完結）
python bench/e2e_wan.py --mode loopback --label selfcheck --server-host 127.0.0.1
```

- 試験データは合計 20MB 未満（Scaleway の空き 1.6GB を考慮）。
- `--reset` はサーバの**状態とマウントだけ**を消す。鍵は残す。
- 高遅延の追加注入はしない。Scaleway の実測 285ms を WAN 条件とする。

---

## 7. ハーネスの設計メモ

`e2e_lan.py` からの主な違い。

- `--server-host` / `--server-ssh` / `--client-ssh` で拠点を切り替える。
- `--mode loopback` で Mac 内に閉じて自己検証できる（CI で壊れていないか確認する用）。
- 各 push/pull の往復回数・送受信バイトを JSON に残す（CLI の `--metrics` を解析）。
- 失敗は例外にせず `{"ok": false, "detail": ...}` として記録する。
- 起動と確認を分ける。WAN では ssh チャネルが閉じずタイムアウト扱いになることがあるため、
  起動コマンドは短く切り、L2 の応答を制御側からポーリングして成否を判定する。
