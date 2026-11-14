# dfs

> [English](README.md) | **日本語**

**dfs** は、単一ライターの信頼モデルと `rclone` 風の CLI を備えた、エンドツーエンド暗号化・重複排除対応の分散ファイルシステムです。

ストレージサーバーやリレーサーバーに平文を見せることなく、PC・自宅サーバー・クラウド GPU ワーカー間でファイルツリーを安全に保存・同期・マウント・共有できます。

---

## 主な特徴

- **エンドツーエンド暗号化 & 重複排除**: ファイルは端末側でチャンク分割・Zstandard 圧縮されたのち、収束暗号（ChaCha20-Poly1305）で暗号化してから送信されます。
- **単一ライターによる改ざん防止**: サブツリーごとにドメインルート鍵から署名付き委譲を受けた 1 つのライター鍵のみが書き込み可能で、すべての更新は署名付き追記ログと Merkle ツリーで検証されます。
- **親しみやすい `rclone` 風 CLI (`dfscli`)**: `ls`、`cat`、`copy`、`sync`、`pull`、`mv`、`rm`、`check`、`mount`（FUSE / FUSE-T）など直感的なコマンドで操作できます。
- **1 コマンドでサーバー起動 (`dfssvc`)**: ローカルの名簿（L2）＋チャンク保管庫（L3）サービスを 1 コマンドで立ち上げ、接続設定や DNSSEC 用レコードも出力できます。
- **手軽な共有とブラウザ UI**:
  - `dfscli web`: スマホやブラウザから直接閲覧・操作できるファイル共有 & Web CLI サーバーを起動します。
  - `dfscli invite` / `dfscli share`: RunPod などの一時的なクラウド環境向けに、読み取り専用招待トークンや 1 行の `curl | bash` ブートストラップコマンドを発行します。
- **NAT 越え・柔軟なトランスポート**: LAN/ICE での直接接続を優先しつつ、NAT 越え時は暗号化 WebSocket リレーへ自動フォールバックし、オプションで libp2p/QUIC 配信にも対応します。
- **アーカイブ & オフライン配布**: `dfscli archive` / `dfscli import` で、可搬な `tar.gz` バンドル（PAR2 リカバリブロックや BitTorrent 対応）を作成・展開できます。
- **Copy-on-Write スナップショット**: macOS の APFS（`clonefile`）や Linux の Btrfs サブボリュームを活用した高速なローカルスナップショット（`dfscli fs`）に対応しています。

---

## 動作要件

- Python `3.10` 以上
- OpenSSH（`ssh-keygen`）— Ed25519 鍵の生成および署名に使用
- オプション:
  - `fuse-t` / `fusepy`（`dfscli mount` 用）
  - `par2` / `par2cmdline`（`dfscli archive` の PAR2 生成・修復用）
  - `libp2p` extra（`pip install -e ".[libp2p]"`、QUIC チャンク配信用）

---

## クイックスタート

### 1. インストール

[`uv`](https://docs.astral.sh/uv/) を使う場合（推奨）:

```bash
git clone <repo-url> dfs
cd dfs
uv sync
```

`pip` を使う場合:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

### 2. ローカルサーバーの起動 (`dfssvc`)

```bash
# ローカルに L2（名簿）+ L3（暗号化チャンク保管庫）を起動
dfssvc start

# 状態と接続先を確認
dfssvc status

# dfscli 用の設定コマンドを表示
dfssvc env
```

### 3. リモート設定とファイル同期 (`dfscli`)

`dfssvc env` が表示した `dfscli config create ...` コマンドを実行してリモートを登録します（任意の `tree_secret` を指定してください）。

```bash
# 登録済みリモートの一覧
dfscli listremotes

# ローカルのファイルやディレクトリをリモートへコピー
dfscli copy ./my-notes local:notes

# ローカルディレクトリをリモートへ同期
dfscli sync ./dataset local:dataset

# リモートのファイル一覧
dfscli ls local:dataset

# 別ディレクトリへ取り出す
dfscli pull local:dataset ./restored-dataset
```

### 4. 別端末・ブラウザでの共有

- **Web UI**（スマホやブラウザからアクセス）:
  ```bash
  dfscli web local:
  ```
- **読み取り専用招待トークン**（チームメンバーやクラウド GPU 向け）:
  ```bash
  dfscli invite create local:dataset
  # 参加側:
  dfscli invite join <token>
  ```
- **ドメインハブへの参加**（リレー / NAT 越え対応）:
  ```bash
  dfscli join https://hub.example.com --name team --path /example.com/alice --key ~/.ssh/id_ed25519 --secret <tree_secret>
  ```

---

## コマンド概要

### `dfscli`（クライアント）

| 分類 | コマンド |
|---|---|
| リモート管理・探索 | `listremotes`, `create`, `config`, `discover`, `join`, `quit`, `about` |
| ファイル操作 | `ls`, `lsd`, `lsl`, `lsjson`, `size`, `cat`, `copy`, `copyto`, `mv`, `rm`, `rmdir`, `purge`, `mkdir`, `touch` |
| 同期・マウント | `sync`, `pull`, `check`, `mount`, `history`, `fs` |
| 共有・アーカイブ | `web`, `invite`, `share`, `archive`, `import` |
| サーバー・権限管理 | `serve`, `delegate`, `promote`, `candidacy`, `libp2p-serve` |

### `dfssvc`（ローカルサービス管理）

| コマンド | 説明 |
|---|---|
| `dfssvc start` | ローカル L2 + L3 サービスを起動（ポート・パス・ハブ参加・`--foreground` 指定可） |
| `dfssvc stop` | サービスを安全に停止 |
| `dfssvc status` | 稼働状態・待受アドレス・パスを表示 |
| `dfssvc list` | 登録済みサービスを一覧表示 |
| `dfssvc env` | `dfscli config create` 用の設定コマンドを出力 |
| `dfssvc dnssec` | DNSSEC 公開用の `_dfs.<domain>` TXT レコード JSON を出力 |
| `dfssvc logs` | サービスログの末尾を表示 |

---

## ドキュメント

レイヤ構成・暗号設計・通信プロトコル・運用方法などの技術的詳細は `docs/` を参照してください:

- [アーキテクチャ概要](docs/architecture.ja.md) ([English](docs/architecture.md)) — L0〜L6 の層構造、データフロー、モジュール対応表
- [セキュリティと暗号設計](docs/security-and-crypto.md) — 脅威モデル、鍵階層、Convergent AEAD（ChaCha20-Poly1305）、SSH Ed25519 署名、DNSSEC / 証明書ピン留め / TOFU
- [プロトコルと運用](docs/protocol-and-operations.md) — L2 名簿 HTTP API、L3 OST プロトコル・ディスク永続化、NAT 越えリレー、`dfssvc`、アーカイブ、Web UI

各コンポーネントの個別仕様書は [`specs/`](specs/) にもあります。

---

## テストの実行

```bash
uv run --extra test pytest -q
```
