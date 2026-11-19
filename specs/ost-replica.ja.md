# OST 読み取りレプリカと複数 endpoint

> [English](ost-replica.md) | **日本語**

## 前提

dfs はサブツリーごとに単一書き手を持つ。書き込みは書き手ノードの**主 OST**で完結させ、
別ノードの OST は読み取り専用の複製として扱う。

- 主 OST: 書き手がチャンクを最初に置く OST
- 複製 OST: 主 OST のチャンクをコピーして保持する OST
- locator: 主 OST と複製 OST の両方を `endpoints` に持つ

複製 OST は書き込み先ではない。書き手が複数いる構成や、複製 OST への直接
`announce` は対象外とする。

さらに長期保存・最終復旧用として、版単位の BitTorrent archive を別層で扱う。
詳細は `specs/bittorrent.md`。

読み取り専用の追加経路として、libp2p/QUIC の chunk source も利用できる。
詳細は `specs/libp2p.md`。

## 書き込み

1. 書き手はスナップショットを作り、チャンクを主 OST へ送る
2. 主 OST への送信が成功したら、その版に含まれる全チャンクを複製 OST へコピーする
3. 複製 OST には `batch_has` で不足分だけを送る
4. 複製 OST が停止・失敗しても主 OST への書き込みは成功とする
5. 複製失敗は警告として記録する
6. 次の push では、その時点のツリーに含まれる全チャンクを再度複製対象にする
   （前回の失敗分もここで追いつく）

チャンクは `wire_id` で内容検証される。複製 OST に同じ `wire_id` の塊が既にあれば
再送しない。

## 読み取り

locator の `endpoints` は主 OST を先頭に、複製 OST を続けて持つ。

- 読み取りクライアントは endpoint を順に試す
- 主 OST が停止・タイムアウト・チャンク欠損なら次の endpoint を試す
- 書き込み用の `OSTClient` は主 OST に固定する
- 読み取り専用の `FailoverOSTClient` は、接続できた endpoint をそのセッションの
  読み取り先として使う

`cat` / `pull` / `ls` のメタデータ取得は、L2 の複数名簿フォールバックと組み合わせる。

## 失敗時の意味

| 失敗 | 挙動 |
|---|---|
| 主 OST への書き込み失敗 | push は失敗。L4 head は進めない |
| 複製 OST へのコピー失敗 | push は成功。警告を出し、次回 push で再試行 |
| 主 OST の読み取り失敗 | 複製 OST を試す |
| 全 OST の読み取り失敗 | 読み取りは失敗 |
| 書き手ノードの停止 | 単一書き手なので書き込みは停止。読み取りは複製 OST と複数名簿で継続できる |

スプール方式は採用しない。書き込みは主 OST で完結することを前提とし、未コミットの
ローカル書き込みをためる機能は持たない。

## 設定

```bash
# 書き手: 主 OST と複製 OST を登録
dfscli create scw \
  --registry http://primary-registry:9440 \
  --registry-alternate http://secondary-registry:9440 \
  --ost 127.0.0.1:19443 \
  --ost-alternate 127.0.0.1:19453
```

`remotes.json` では次のように保持する。

```json
{
  "ost": "127.0.0.1:19443",
  "ost_alternates": ["127.0.0.1:19453"]
}
```

読み取り側はロケータの `endpoints` からも複製 OST を発見するため、通常は
`--ost-alternate` を省略できる。設定に書く場合は、主 OST が停止している初回読み取りの
フォールバックに使われる。

## 制約

- 複製 OST は読み取り専用。複製 OST だけを書き手に昇格させる機能はまだない
- 複製 OST の内容は、次の push まで一時的に古いことがある
- 書き手ノードと主 OST が同時に停止した場合、未複製のチャンクは読めない
- チャンク単位の完全な replication log / quorum は持たない

## 回帰試験

- `tests/test_availability.py::AvailabilityCase::test_read_fails_over_to_replicated_ost`
- 主 OST 停止後、複製 OST と locator endpoints から pull できること
- locator の endpoints が主 + 複製の 2 つになること
- 主 OST の全チャンクが複製 OST に存在すること
