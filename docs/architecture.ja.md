# アーキテクチャ概要

> [English](architecture.md) | **日本語**

**dfs** は、信頼の起点・経路探索・暗号化チャンク保存・ファイルシステム状態・ユーザーインターフェースを **L0〜L6** の明確なレイヤに分離して設計されています。各レイヤは単一の責務を持ち、下位レイヤからの暗号学的証明または明示的に設定された信頼アンカーのみに依存します。

---

## レイヤ構成

| レイヤ | 名称 | 主なモジュール | 責務 |
|---|---|---|---|
| **L0** | ルート信頼 & 探索 | `dfs/dnssec.py`, `dfs/discovery.py` | ドメインルート鍵（`_dfs.<domain>` DNSSEC TXT）、明示的なルート公開鍵、接続先探索 |
| **L1** | 権限委譲 | `dfs/l1_delegation.py` | サブツリーに対する単一ライター鍵の署名付き委譲レコード（epoch・失効管理を含む） |
| **L2** | 署名付き名簿（Registry） | `dfs/l2_registry.py`, `dfs/l2_cache.py` | サブツリーの先頭リビジョン、シーケンス番号、署名付きロケータ、OST エンドポイントを管理する HTTP 名簿 |
| **L3** | 収束暗号 OST（Object Store） | `dfs/l3_ost_adapter.py`, `dfs/l3_store.py`, `dfs/crypto.py`, `dfs/compression.py` | 内容アドレス型の暗号化チャンク保管庫（TLS バイナリ / HTTP リレー / libp2p QUIC） |
| **L4** | 単一ライター追記ログ & Merkle ツリー | `dfs/l4_log.py` | 署名付き追記ログ、ディレクトリ/ファイル Merkle スナップショット、単調増加シーケンス検証 |
| **L5** | ローカル作業ツリー & CoW アダプタ | `dfs/l5_fs.py`, `dfs/fs/` | L4 ツリーとローカルディレクトリの同期（macOS APFS `clonefile` / Linux Btrfs サブボリューム / 通常コピー） |
| **L6** | CLI・Web UI・バンドル | `dfs/cli_main.py`, `dfs/commands/`, `dfs/svc.py`, `dfs/web.py`, `dfs/fuse_mount.py`, `dfs/archive.py`, `dfs/invite.py` | `rclone` 風 CLI（`dfscli`）、サービス管理（`dfssvc`）、Web UI、FUSE マウント、招待トークン、`tar.gz`/PAR2/BitTorrent バンドル |

---

## データフロー

### 書き込み / Push フロー

```text
ローカル作業ツリー (L5)
  │
  ├─► チャンク分割 + Zstandard 圧縮 + 収束 AEAD (ChaCha20-Poly1305)
  │     └─► L3 OST へバッチ HAS / PUT で暗号化チャンクを送信 (TLS / HTTP / Relay)
  │
  ├─► Merkle ディレクトリ & ファイルマニフェストを構築し、L4 ログに署名 (ライター Ed25519 鍵)
  │
  └─► 署名済み先頭版 + L1 委譲チェーンを L2 名簿へ公開 (POST /v1/paths)
```

1. **分割と暗号化 (`L3` + `L4`)**: ファイルはチャンクに分割され、Zstandard で圧縮されたのち、`tree_secret` から `HMAC-SHA256` で導出した鍵を用いて端末側で `ChaCha20-Poly1305` 暗号化されます。
2. **チャンク送信 (`L3`)**: バッチ `HAS` で未保存の `wire_id` のみを確認し、必要なチャンクだけをバッチ `PUT` で L3 OST へアップロードします。
3. **リビジョン確定 (`L4` → `L2`)**: ルート Merkle チャンクと単調増加する `seq` を含む L4 エントリにライター鍵で署名（`dfs-l4-log-v1`）し、L1 委譲（`dfs-delegation-v1`）とともに L2 名簿へ登録します。

### 読み込み / Pull フロー

```text
L2 名簿 (GET /v1/paths, /v1/ost)
  │
  ├─► ルート信頼の検証 (L0 DNSSEC / ピン留め root_pubkey / 明示的 TOFU)
  ├─► L1 委譲チェーン、L4 ライター署名、単調増加 seq の検証
  │
  ├─► L3 OST から Merkle ツリーとチャンクを取得 (TLS / HTTP / Relay / libp2p)
  │
  └─► AEAD タグと plain_id を検証・復号・展開し、L5 作業ツリーへ反映 (CoW スナップショット)
```

1. **信頼とログの検証**: クライアントは設定された `root_pubkey`（または DNSSEC / 明示的 TOFU）を起点に、L1 委譲チェーン、L4 エントリの署名とシーケンス番号を検証します。
2. **チャンク取得と復号**: 必要なチャンクを L3 OST（またはローカルキャッシュ・アーカイブ・libp2p ピア）からバッチ取得し、`tree_secret` で復号して AEAD タグと `plain_id` / `wire_id` の整合性を検証します。
3. **作業ツリーへの反映 (`L5`)**: 検証済みのファイルをステージング領域に展開し、作業ツリーへ安全に反映します。

---

## モジュール対応表

- **暗号・パス安全性**:
  - `dfs/crypto.py`: UTF-8 NFC パス正規化、SSH Ed25519 署名・検証、`ConvergentAEAD`
  - `dfs/path_safety.py`: ローカル復元・アーカイブ展開時のパストラバーサル / シンボリックリンク脱出防止
  - `dfs/compression.py`: Zstandard フレーミングおよび展開サイズ上限ガード
- **制御面・データ面**:
  - `dfs/l1_delegation.py`: 委譲レコード（`dfs-delegation-v1`）および epoch 検証
  - `dfs/l2_registry.py`, `dfs/l2_cache.py`: 名簿状態、署名付きロケータ、フェイルオーバー / 昇格
  - `dfs/l3_ost_adapter.py`: TLS フレーム（`H`, `G`, `P`, `B`, `M`, `F`, `Q`）、ディスクチャンク保存（`.blk`）、`DFS_OST_MAX_BYTES` 容量制限、HTTP / リレーバッチ処理
  - `dfs/l4_log.py`: `L4LogClient`、`L4Manifest`、ツリー走査・差分同期
  - `dfs/l5_fs.py`, `dfs/fs/`: `DFSNode`、`ClayFS` CoW アダプタ
- **ネットワーク・共有**:
  - `dfs/relay.py`: HTTP アップグレードによるリレー通信および ICE 候補探索（`/_ice/candidates`）
  - `dfs/libp2p_chunk.py`: オプションの libp2p/QUIC チャンクサーバー & クライアント
  - `dfs/invite.py`: 読み取り専用 Base64 招待トークン・ブートストラップスクリプト生成
  - `dfs/web.py`: セッション認証・レート制限付きブラウザファイル共有 & Web CLI
- **CLI・サービス**:
  - `dfs/cli.py`: `dfs serve`、L2 HTTP ハンドラ、OST + リレーホスト
  - `dfs/cli_main.py`, `dfs/commands/`: `dfscli` コマンドルーティングとリモート設定ストア（`dfs/remotes.py`）
  - `dfs/svc.py`: `dfssvc` サービスライフサイクル管理（`start`, `stop`, `status`, `list`, `env`, `dnssec`, `logs`）
  - `dfs/archive.py`: `tar.gz` バンドル作成・展開、PAR2 パリティ、BitTorrent 記述子対応
