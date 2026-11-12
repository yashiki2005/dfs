# libp2p/QUIC chunk source

## 位置付け

libp2p は OST を置き換えない。既存の OST / 複製 OST に続く**読み取り専用の
追加 ChunkSource** として使う。

- 主 OST: 書き込みと通常読み取り
- 複製 OST: 読み取り可用性
- libp2p/QUIC: peer から必要な chunk だけを取得
- BitTorrent: 版単位の長期アーカイブ

libp2p は HTTP 専用でも QUIC 専用でもないが、dfs では **QUIC transport** を使う。
TCP はこの環境で別プロセス間のカスタムストリームが動作しなかったため採用しない。

## プロトコル

```text
/dfs/chunk/1.0.0

request    = op(1) + count(4, BE) + wire_id[count](64 bytes)
H response = "O" + flags[count](1 byte each)
G response = "O" + (length(4, BE) + blob)[count]
```

`wire_id` は SHA-256。取得した blob は必ずクライアント側で SHA-256 を再検証する。
書き込み op は持たない。

## サーバ

py-libp2p のホストはプロセスごとの Trio ループで動かす。`dfs serve` のスレッドに
同居させず、専用プロセスで起動する。

```bash
dfscli libp2p-serve \
  --chunks-dir ~/.dfs_server/ost_chunks \
  --listen /ip4/0.0.0.0/udp/0/quic-v1
```

起動時に `peer: /ip4/.../udp/.../quic-v1/p2p/...` を表示する。この multiaddr を
読み取り側の `--libp2p-peer` に渡す。

`--chunks-dir` は `PersistentRegistryState.save_ost_chunks` が保存した
`<wire_id>.blk` を読む。OST のメモリ状態を直接共有するものではないため、直近の
announce 後に保存された chunk が対象になる。

## クライアント

```bash
dfscli create scw \
  --registry http://primary:9440 \
  --libp2p-peer /ip4/203.0.113.10/udp/19443/quic-v1/p2p/12D3KooW...
```

`DFSNode` の読み取り候補は次の順になる。

1. 主 OST
2. 複製 OST
3. libp2p peer

locator の OST endpoint が全滅しても、libp2p peer が chunk を持っていれば
`cat` / `pull` を継続できる。書き込みは主 OST のまま。

## private swarm

`--libp2p-psk` をサーバとクライアントの両方に設定すると、private swarm 用の
pre-shared key を libp2p host に渡す。PSK は設定ファイル内で秘密として扱う。

## 制約

- peer discovery はまだ静的設定。Kademlia provider record / mDNS は未実装
- libp2p サーバは独立プロセス。`dfs serve` からの自動起動は未実装
- サーバは chunk ディレクトリを読む。メモリ上の OST を直接配信するには IPC が必要
- QUIC の UDP ポート、NAT、firewall、relay の運用が必要
- libp2p 自体は retention / seeding incentive を持たない
- 書き込み、CAS、L4 の整合性は従来どおり OST / L2 / L4 が担う

## 回帰試験

- `tests/test_libp2p_chunk.py`: 別プロセスの QUIC サーバからの HAS / GET
- `tests/test_libp2p_chunk.py`: 欠損 chunk の拒否、読み取り専用の確認
