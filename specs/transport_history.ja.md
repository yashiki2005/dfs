# トランスポート変遷と「良いところ取り」Swarm 設計

> [English](transport_history.md) | **日本語**

## 1. これまでの経緯

1. **TLS/TCP カスタムフレーム (`OSTClient` / `ChunkStoreServer`)**
   - 最小のオーバーヘッドと明示的切断 (`QUIT_FRAME`) で高スループットを実現。
   - ただし `443/tcp` の HTTP プロキシや CDN の背後では直接接続できない。
2. **`libp2p` の TCP → QUIC 切り替え ([dfs/libp2p_chunk.py](../dfs/libp2p_chunk.py))**
   - 当初試した `py-libp2p` の TCP 経路で接続・多重化が不安定になり失敗したため、**QUIC (`/udp/.../quic-v1`)** へ切り替えた。
   - 読み取り補助の `ChunkSource` としては機能するが、`py-libp2p` + `trio` の依存が重く、また RunPod 等のクラウド GPU コンテナでは UDP (QUIC) が制限される場合がある。
3. **BitTorrent アーカイブ ([dfs/archive.py](../dfs/archive.py))**
   - 固定バージョンの巨大データセット配布には有効だが、UDP/DHT/着信ポート待ちが制限環境と相性が悪く、小刻みな差分更新にも向かない。
4. **HTTPS OST + Direct-first HTTP リレー ([dfs/l3_ost_adapter.py](../dfs/l3_ost_adapter.py), [dfs/relay.py](../dfs/relay.py))**
   - Python 標準ライブラリのみで `443/tcp` を確実に貫通し、直接通信できる場合はリレー (`dfs.example.com`) を使わない。

---

## 2. 「良いところ取り」(`SwarmOSTClient`) の方針

3 つの良いところだけを組み合わせ、重い外部依存（`libtorrent` 必須化等）は入れない：

- **BitTorrent の良いところ（マルチピア並列・部分補完）**:
  - 複数の読み取り候補（直接 OST・複製 OST・`libp2p/QUIC` ピア）があるとき、1 台だけに集中させず、`batch_has` で在庫を確認した上で **チャンクを並列ラウンドロビンで分散取得** する。
  - あるピアが一部チャンクを欠損していても、別ピアから欠損分だけ補完できる。
- **`libp2p` の良いところ（オプション P2P/QUIC ピア）**:
  - `dfs[libp2p]` が入っている環境では `Libp2pChunkClient` もそのまま Swarm プールに参加させられる。
- **HTTPS / HTTP リレーの良いところ（確実な最後の砦）**:
  - `/relay/` エンドポイントは **フォールバック層（Relay Tier）** に分離し、直接ピア／複製ピア／QUIC ピアのいずれでも取れなかったチャンクだけをリレー経由で取得する。
  - これにより、パブリックリレー (`dfs.example.com`) の負荷を抑えつつ、制限環境でも必ず完了する。
