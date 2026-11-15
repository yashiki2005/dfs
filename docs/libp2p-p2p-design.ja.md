# libp2p P2P 連携の設計方針

**dfs** は `libp2p` を **必須（標準依存）かつ最優先される P2P 読み取りトランスポート / ピア探索レイヤ** として位置づけています。

### 必須化の経緯
当初は任意（Optional）依存として位置づけていましたが、複数シード並列取得（Endgame レース・Rarest-First・動的バッチサイズ・マルチストリーム等）を用いた **512 MiB 実測ベンチマーク** において、1 シード（`1.36 MiB/s`、240 秒で 327/512 チャンク）から 2 シード分散取得（Pi5 にて `5.39 MiB/s`、94.92 秒で 512/512 チャンク完走）へと **約 4 倍の高速化** を確認しました。この結果を受け、全ノードで確実に P2P 分散転送の恩恵を受けられるよう `pyproject.toml` / `requirements.txt` の必須依存へ引き上げました。

なお、UDP/QUIC が遮断される厳格なネットワークや `DFS_LIBP2P=0` 指定時・接続切断時の安全網として、`TLS/TCP + HTTP + ICE + RelayHub` 経路への透過的フォールバック機構は引き続き維持しています。

---

## 基本方針（3 本柱）

### 1. ピア探索: Kademlia DHT 優先 + 既存ハブフォールバック
- `libp2p`（`KadDHT`）が利用可能な環境では、起動時から **Kademlia DHT** を有効化する。
  - `root dfs` / `domain dfs`（`dfssvc`）は `DHTMode.SERVER`、一般ノード（`DFSNode`）は `DHTMode.CLIENT` で動作する。
  - ドメイン識別子（`root_pubkey` または `sub_path`）から決定論的な CIDv1（`domain_cid("dfs:domain:<key>")`）を生成し、`provide_domain()` / `find_domain_providers()` で同一ドメインのピアを探索する。
- DHT でピアが見つからない場合や到達できない場合は、既存の HTTP ハブ（`/_p2p/peers` および `/_ice/candidates`）へ自動的にフォールバックし、候補一覧を取得する。

### 2. NAT 越え・データ転送: Circuit Relay v2 / DCUtR 優先 + RelayHub フォールバック
- `libp2p` 接続時は **ダイレクト接続（QUIC / TCP）** を最優先で試行し、失敗した場合は **Circuit Relay v2（`/p2p-circuit/p2p/<target_peer_id>`）および DCUtR（Direct Connection Upgrade through Relay）** を優先して使用する。
  - `enable_relay=True` の `dfssvc` ハブが `CircuitV2Protocol(..., allow_hop=True)` としてホップ中継を担う。
- `libp2p` のダイレクト接続および Circuit Relay v2 / DCUtR のいずれも成立しない場合や、`libp2p` 自体が未導入の場合は、既存の `RelayHub`（HTTP リバースリレー `/relay/<node_id>`）へフォールバックする。
- なお、`libp2p` 上の `/dfs/chunk/1.0.0` は **読み取り専用（`H`: バッチ在庫確認 / `G`: バッチ取得）** とし、書き込み（単一ライターからのチャンク PUT / L4 公開）は引き続き TLS/HTTP/RelayHub 経路を用いる。

### 3. ゼロコンフィグ認可: ドメインごとの `PeerID` 許可リスト
- `root dfs` / `domain dfs` のハブ（`RelayHub`）ごとに **許可済み `PeerID` リスト（allowlist）** を保持する。
- ノードは `join` / `announce` / `pull` 時に自身の `PeerID` とマルチアドレスを `/_p2p/peers` または `/_ice/announce` へ自動登録し、同時にドメイン内の許可リストを取得してローカルの `Libp2pHostManager` へ同期する（`DFS_RELAY_TOKEN` 設定時は `X-DFS-Relay-Token` で保護）。
- `/dfs/chunk/1.0.0` のストリームハンドラは受信した `stream.muxed_conn.peer_id` を検証し、許可リストに含まれない `PeerID` からのリクエストは即座に `reset()` / `close()` して拒否する。
- 失効・離脱時は `POST /_p2p/peers/revoke` によりハブの許可リストから削除し、`on_allowlist_change` コールバックでサーバ側の許可リストへ即時反映する。

---

## 実行アーキテクチャと負荷分散

### 常駐 Trio ホストと接続再利用 (`Libp2pHostManager`)
- `py-libp2p` は Trio ベースで動作するため、同期コード（`SwarmOSTClient` / `DFSNode` / `dfssvc`）からバッチごとにイベントループとホストを再生成すると QUIC ハンドシェイクコストが過大になる。
- `Libp2pHostManager` は **バックグラウンドの単一常駐スレッド上で Trio イベントループと単一 `Host` を維持** し、`trio.from_thread.run` 経由で同期呼び出しを橋渡しする。既に確立済みの `PeerID` への接続は `host.get_network().connections` から再利用する。

### ピア単位アダプタと比例並列負荷分散 (`Libp2pPeerClient` + `SwarmOSTClient`)
- 発見した各 libp2p ピアごとに `Libp2pPeerClient`（`endpoint_uri = "libp2p://<peer_id>"`）を生成し、`SwarmOSTClient` へ登録する。
- `SwarmOSTClient` は `libp2p` ピアと `TLS/HTTP/Relay` ピアを区別せず統一的に RTT 計測・EWMA 実測スループット計測を行い、重み付き比例並列取得（初期バッチ割り当て + ワークスティーリング）によって負荷分散する。

---

## フォールバックと環境互換性

| コンポーネント | `libp2p` 利用可能時 | `libp2p` 未導入 / 無効 (`DFS_LIBP2P=0`) 時 |
|---|---|---|
| **ピア探索** | `KadDHT` 優先 → `/_p2p/peers`, `/_ice/candidates` | `/_ice/candidates` のみ（`type == "libp2p"` は無視） |
| **NAT 越え** | Direct QUIC/TCP → `CircuitV2` + `DCUtR` → `RelayHub` | `RelayHub`（HTTP リバースリレー） |
| **チャンク取得** | `Libp2pPeerClient` + `TLS/HTTP` の比例並列 | `TLS/HTTP` + `RelayHub` の比例並列 |
| **認可** | ドメイン `PeerID` 許可リスト + `X-DFS-Relay-Token` | TLS 証明書ピン留め + `X-DFS-Relay-Token` |
