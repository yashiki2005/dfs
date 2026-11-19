# BitTorrent archive

> [English](bittorrent.md) | **日本語**

## 位置付け

BitTorrent は dfs のホットパスを置き換えない。**版単位の読み取り専用アーカイブ**と、
OST / registry が全滅したときの最終復旧経路として使う。

- 主 OST: 書き込みと通常の読み取り
- 複製 OST: 読み取り可用性
- BitTorrent archive: 過去版の長期保存と最終復旧

BitTorrent は最新版を保証しない。復元できるのは「infohash と bundle を知っている版」だけである。

## bundle

`dfscli archive create` は、現在の先頭版について次のディレクトリを作る。

```text
<bundle>/
  meta.json
  chunks/<wire_id>
```

`meta.json` には次を保存する。

- サブツリーパス、版番号
- root の `plain_id` / `wire_id`
- 検証済みの委譲チェーン
- 署名済み locator と head log
- root 公開鍵
- 収録した chunk の一覧（`wire_id`, `plain_id`, `size`）

chunk は暗号化済み blob のまま保存する。平文パスや平文ファイル名は bundle の
ファイル名に使わない。

## torrent

`<bundle>.torrent` を生成する。現在の実装は BitTorrent v1 の file mode を使う。

- `meta.json` と `chunks/*` を 1 つの torrent にまとめる
- piece length は 256 KiB
- torrent の infohash は SHA-1（v1）
- chunk 自体の真正性は DFS の `wire_id`（SHA-256）で再検証する

v1 の SHA-1 は BitTorrent の transport 用であり、DFS の最終的な完全性判定には
使わない。BitTorrent v2 への移行は今後の課題。

## 作成・検証・復元

```bash
# 現在の先頭版をアーカイブする
dfscli archive create scw: --out ./scw-v1

# 過去の版を指定してアーカイブする
dfscli archive create scw: --version 3 --out ./scw-v3

# bundle の署名・chunk hash・サイズを検証する
dfscli archive verify ./scw-v1

# ローカルに復元する（tree_secret が必要）
dfscli archive extract ./scw-v1 ./restored

# descriptor から archive 一覧を表示する
dfscli archive catalog .
```

`archive create` は torrent の infohash と magnet link を表示する。`--publish` を
付けると、書き手署名付き archive descriptor を L2 に登録する。descriptor は
path、版、infohash、L4 entry hash、root wire ID を結び付ける。

```bash
# 作成と同時にL2へ公開
dfscli archive create scw: --version 3 --out ./scw-v3 --publish

# 既に作成済みのbundleを公開
dfscli --remote scw archive publish ./scw-v3

# L2からdescriptorを取得し、外部BT CLIのDHT/trackerで取得後に検証・復号
dfscli archive fetch scw: --version 3 \
  --out ./downloads --secret <tree_secret> ./restored
```

実際のpeer探索とdownloadingは `aria2c` または `transmission-cli` を使う。
`archive fetch` は両者を自動検出し、標準機能のDHT/trackerを利用する。
DFS はDHT・ピア交換を独自実装しない。

`archive create --version N` は、L2 の L4 履歴から指定版の署名済み head を取得する。
過去版には現在の locator を流用せず、locator なしで bundle を作る。bundle の
`meta.json` には選択した版の head / delegation が入る。

## 復元の条件

ある過去版を復元できるのは、次が揃った場合だけである。

- その版の bundle を完全に持つ seeder が存在する
- その版の infohash / torrent を知っている
- `meta.json` の L1/L2/L4 署名が検証できる
- 全 chunk の SHA-256 が一致する
- `tree_secret` を持っている

「一人でも seeder がいれば」は、その seeder が完全な bundle を持ち、到達可能である
ことが条件になる。可用性の保証ではなく best-effort のアーカイブと位置付ける。

## セキュリティと運用

- BitTorrent は IP アドレスや swarm 情報を露出する。private tracker / 認証付き
  swarm / 別 transport を検討する
- 一度配布した torrent は削除できない。失効は `tree_secret` のローテーションで行う
- infohash と bundle の対応は署名済み metadata と合わせて配布する
- 小さい版を大量に torrent 化すると overhead が大きい。版単位または一定期間単位で
  まとめる
- tracker が無い場合は DHT / 手動 peer 設定を使う。DHT は seeder の存在を保証しない
- DHTから得るのは既知infohashのpeer候補だけであり、最新版の判断には使わない
- descriptorはL2から取得できるが、必ず書き手署名とL4 headへの束縛を検証する

## 制約

- infohash の配布はL2の署名済みdescriptorが中心。L4へのarchive descriptor統合は未実装
- torrent は v1。v2、erasure coding、k-of-n 復元は未実装
- bundle の自動 retention / garbage collection は未実装

## 回帰試験

- `tests/test_archive.py`: bundle 作成、署名検証、chunk 改ざん検出、復元
- `tests/test_archive.py`: `archive verify` CLI
