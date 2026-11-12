# 性能計測（2026-11-12）

## 環境

| 項目 | 値 |
|---|---|
| マシン | MacBook-Neo（Apple A18 Pro） |
| OS | macOS 27.3 arm64 |
| Python | 3.12.16（`~/dfs-venv`） |
| 計測 | ローカル / loopback |

生データは `bench/results/20261112-current-*.json` に保存している。
WAN の数値は既存の `specs/e2e_wan.md`（2026-11-11）を使う。

## L2 / L3

| 項目 | 結果 |
|---|---:|
| L2 `resolve`（プロセス内辞書引き） | 中央値 **0.0006 ms** |
| Ed25519 SSHSIG 検証（最適化後） | 中央値 **0.043 ms** / p95 0.045 ms |
| DNS 問い合わせ | 中央値 **13.05 ms** |
| L3 100 × 64KiB | **29.56 ms** / 1 往復 / 約 **222 MB/s** |
| L3 100 × 4KiB | 9.14 ms / 1 往復 |
| 同一内容 2 ファイルの暗号文本体 | 8,757 B（1 ファイル分） |
| 既存内容の別名追加 | 697 B |

`resolve` は名簿サービス内の辞書引きであり、HTTP 往復は含まない。実ネットワークでは
L2 HTTP、署名検証、L3 TLS のコストが加わる。

## CLI

20 ファイル × 128KiB（2.62MB）をローカル server に push / read / pull した結果。

| 操作 | 最適化前 | 最適化後 |
|---|---:|---:|
| 初回 copy（コマンド全体） | 59.2 ms | **52.5 ms** |
| 初回 copy（push 内部） | 35.3 ms | **24.5 ms** |
| 無変更 copy | 48.1 ms | **16.9 ms** |
| 通常の 128KiB read | 20.0 ms | **7.3 ms** |
| registry 全停止後の cache read | 19.8 ms | **9.5 ms** |
| registry 全停止後の `list_remote` | 18.5 ms | **6.3 ms** |
| registry 全停止後の pull（2.62MB） | 37.8 ms | **37.9 ms** |

初回 copy のスループットは約 **50 MB/s**、push 内部は約 **107 MB/s**。
pull は L3 の転送が支配的で、署名検証の最適化ではほとんど変わらない。

なお、ローカルで registry を停止した場合は connection refused が即時に返る。
実際の通信断では `DFS_L2_TIMEOUT`（既定 10 秒）を registry ごとに待つ可能性がある。

## DNSSEC

`discover_domain("yashiki.top")` を同一プロセスで 20 回実行した結果。

| 項目 | 最適化前 | ゾーン鍵キャッシュ後 |
|---|---:|---:|
| 中央値 | 187.5 ms | **12.7 ms** |
| p95 | 1,022 ms | **497 ms** |
| 最小 | 52.4 ms | **8.9 ms** |
| 最大 | 1,022 ms | **497 ms** |

初回は root / TLD / ドメインの DNSKEY・DS を取得するため約 0.5 秒かかる。
2 回目以降は検証済みゾーン鍵を TTL の範囲で再利用するため、中央値は約 13ms になる。

CLI は 1 プロセスで 1 回しか discovery しないため、この短縮はプロセス内の反復利用
（サーバ、テスト、将来の監視処理）が対象である。CLI の初回起動も短縮するには、
検証済みゾーン鍵の永続キャッシュが必要になる。

## zstd level 10

16MiB のデータで `zstandard` level 10 を計測した。

| データ | 圧縮率 | 圧縮時間 | 圧縮速度 | 伸長時間 |
|---|---:|---:|---:|---:|
| テキスト寄り | 1.22% | 57.1 ms | 280 MiB/s | 2.5 ms |
| ランダム | 100% | 4.7 ms | 3,381 MiB/s | 0.7 ms |

圧縮可能なデータでは転送量を大きく削減できる一方、ランダムデータでは圧縮率が
1.0 のまま CPU だけを使う。zstd:10 はローカル L3 のホットパス（数十 ms）に対して
無視できないコストになるため、圧縮はデフォルト有効にせず、データ種別または
転送路に応じた明示的な指定が必要になる。

計測結果: `bench/results/20261112-zstd10-local.json`。

## 書き手索引の永続化

20 × 128KiB（2.62MB）を push した後、1 ファイルだけ変更して別プロセスから
再度 push した。

| 実行 | 送信量 |
|---|---:|
| 初回 push | 2,628,420 B |
| 1 ファイル変更後の push | **5,731 B** |

索引は `.clayfs/ost_index.json` に保存される。`tree_secret` から導出する
内容アドレス鍵が変わると `address_key` が一致せず、古い索引は無効化される。

計測結果: `bench/results/20261112-ost-index-local.json`。

## WAN（既存実測）

`specs/e2e_wan.md` の 20 × 128KB（2.13MB）:

| 経路 | RTT | push | pull |
|---|---:|---:|---:|
| Mac → Scaleway | 275.8 ms | 4.30 s | 4.01 s |
| Sakura → Scaleway | 275.1 ms | 3.70 s | 3.64 s |
| Mac → Sakura | 22.1 ms | 0.91 s | 0.53 s |

WAN は RTT と転送量が支配的で、L2 の署名検証を最適化しても往復回数は変わらない。

### 3 拠点（2026-11-12 再測）

Mac（primary）/ Sakura / Scaleway の 3 ノードで、20 × 128KiB（2.62MB）を push し、
primary と Sakura を順に停止して読み取り先を切り替えた。

| 操作 | 所要時間 | 内容一致 |
|---|---:|---|
| primary へ copy（2 secondary への複製込み） | **9.98 s** | — |
| primary から pull（`--force`） | **2.12 s** | 一致 |
| primary 停止後、Sakura から pull（`--force`） | **0.82 s** | 一致 |
| Sakura 停止後、Scaleway から pull（`--force`） | **4.15 s** | 一致 |

push はローカル OST への書き込み後、Sakura / Scaleway の複製 OST へも送るため、
2 拠点分の WAN 転送を直列に待つ。読み取りは残存する複製 OST に切り替わり、
3 拠点すべてで内容が一致した。

## 再測方法

```bash
python bench/l2_bench.py --dns-calls 50 --calls 5000 --verify-calls 500
python bench/l3_bench.py
python bench/e2e_wan.py --mode loopback --server-host 127.0.0.1
```

`e2e_wan.py` は既存の dfs サーバを `pkill` するため、共用環境では実行しないこと。
