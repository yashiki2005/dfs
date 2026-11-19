# プロトコルと運用

> [English](protocol-and-operations.md) | **日本語**

このガイドでは、**dfs** におけるランタイムプロトコル、トランスポート選択、サービス管理（`dfssvc`）、および運用ワークフローについて説明します。

---

## L2 レジストリ & L3 OST プロトコル

### L2 レジストリ (HTTP)

L2 レジストリ（`dfs/cli.py`、`dfs/l2_registry.py`）は、調整および探索のための HTTP エンドポイントを提供します:

- `GET /v1/paths` / `POST /v1/paths`: サブツリーの署名付き L4 ヘッドおよび L1 委任レコードの照会または公開。
- `GET /v1/ost`: アクティブな L3 OST エンドポイントおよび任意の TLS 証明書 SHA-256 フィンガープリント（`cert_sha256`）の検出。
- `GET /_ice/candidates`: NAT 越え用のダイレクトホスト / サーバーリフレクシブ / リレー候補のアドバタイズ。
- `POST /v1/ost/batch-has`, `POST /v1/ost/batch-get`, `POST /v1/ost/batch-put`: HTTP/リレー経由のバッチオブジェクトストアエンドポイント。

### L3 OST (TLS バイナリプロトコル & ディスク永続化)

- **TLS フレーミング (`dfs/l3_ost_adapter.py`)**:
  - 明示的なフレーミングオペコード（`H` = バッチ HAS、`G` = バッチ GET、`P` = バッチ PUT、`B`/`M`/`F` = ストリーミング/メタデータ操作、`Q` = 受信デッドロックを防ぐための明示的終了フレーム）を使用します。
  - 上限付きフレームサイズ（`MAX_BATCH_ITEMS = 65,536`、`MAX_BLOB_BYTES = 256 MiB`）およびチャンク化されたクライアントバッチ処理（`CLIENT_BATCH_ITEMS = 1024`、`CLIENT_BATCH_BYTES = 64 MiB`）を採用しています。
- **ディスク永続化とクォータ**:
  - チャンクはアトミック書き込み + `fsync`（親ディレクトリの `fsync` を含む）によって `.blk` ファイルとしてディスクに永続化されます。
  - TLS および HTTP/リレー OST ハンドラの双方が同一の `_has_chunk` / `_get_chunk` / `_put_chunk` パスを共有し、トランスポート間で一貫して `DFS_OST_MAX_BYTES` を強制します。

---

## トランスポート選択 & NAT 越え

リモートへ接続する際（`dfs/remotes.py`、`dfs/relay.py`）:

1. **ダイレクト LAN / ICE**: `dfscli join` および `dfscli discover` は `/_ice/candidates` を照会し、利用可能な場合は直接到達可能なエンドポイントを優先します。
2. **暗号化 WebSocket リレー**: ピアが NAT の背後にある場合、トラフィックはエンドツーエンドの暗号化と署名を維持したままハブリレー（`/relay/...`）を経由してルーティングされます。
3. **オプションの libp2p / QUIC (`dfs/libp2p_chunk.py`)**: `dfscli libp2p-serve` は P2P 分散のために libp2p/QUIC 経由で OST チャンクを提供します。

---

## サービス管理 (`dfssvc`)

`dfssvc`（`dfs/svc.py`）は `$DFS_HOME/dfssvc/<name>`（デフォルトは `~/.dfs` またはプラットフォームのデータディレクトリ）配下のローカル L2 + L3 サーバーインスタンスを管理します:

- **サービス命名規則**: 名前は `^[A-Za-z0-9][A-Za-z0-9_.-]*$` に一致する必要があります。
- **再起動時の状態保持**: 停止および再起動（`dfssvc stop <name>` → `dfssvc start <name>`、または `--force`）では、CLI で明示的に上書きされない限り、以前に解決されたポート、状態/OST ディレクトリ、鍵、`root_anchor`、`sub_path`、およびハブ/リレー設定が保持されます。
- **フォアグラウンド & バックグラウンドモード**: `dfssvc start` と `dfssvc start --foreground` のいずれも L2 の準備完了を待機し、（`--no-delegate` が指定されない限り）L1 委任を登録し、サービスメタデータを `services.json` に永続化します。
- **DNSSEC レコード生成**: `dfssvc dnssec` は `_dfs.<domain>` DNS TXT レコードに公開する JSON ペイロードを出力し、クライアントが `dfscli discover` 経由でルート鍵の検証とエンドポイントの検出を行えるようにします。

---

## 運用ワークフロー

### フェイルオーバーと昇格

プライマリレジストリがオフラインになった場合、スタンバイレプリカの状態を次のコマンドで昇格できます:

```bash
dfscli promote ...
```

### アーカイブバンドルとオフライン転送

検証済みスナップショットをポータブルな `tar.gz` バンドル（オプションで PAR2 リカバリブロックや BitTorrent メタデータ付き）としてエクスポートし、別の場所へインポートします:

```bash
dfscli archive create local:dataset -o dataset-bundle.tar.gz
dfscli import dataset-bundle.tar.gz remote:dataset
```

### エフェメラルワーカー (RunPod / クラウド GPU)

スコープ付きの読み取り専用招待トークン、または 1 行のブートストラップスクリプトを生成します:

```bash
dfscli invite create local:dataset
dfscli share local:dataset
```

### ブラウザアクセス (`dfscli web`)

閲覧、アップロード、ダウンロード、および Web CLI コマンドの実行を行うためのローカルまたは LAN アクセス可能な Web UI を起動します:

```bash
dfscli web local: --host 0.0.0.0 --port 8080
```
