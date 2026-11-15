# dfs

> [English](README.md) | **日本語**

**dfs** は、単一ライターの信頼モデルと `rclone` 風の CLI を備えた、エンドツーエンド暗号化・重複排除対応の分散ファイルシステムです。

ストレージサーバーやリレーサーバーに平文を見せることなく、PC・自宅サーバー・クラウド GPU ワーカー間でファイルツリーを安全に保存・同期・マウント・共有できます。

> **プロジェクト状態:** `0.1.x` は初期リリース系列です。独立したセキュリティ監査は
> 受けていません。重要なデータへ適用する前に脅威モデルを確認してください。

---

## 主な特徴

- **エンドツーエンド暗号化 & 重複排除**: ファイルは端末側でチャンク分割・Zstandard 圧縮されたのち、収束暗号（ChaCha20-Poly1305）で暗号化してから送信されます。
- **単一ライターによる改ざん防止**: サブツリーごとにドメインルート鍵から署名付き委譲を受けた 1 つのライター鍵のみが書き込み可能で、すべての更新は署名付き追記ログと Merkle ツリーで検証されます。
- **親しみやすい `rclone` 風 CLI (`dfscli`)**: `ls`、`cat`、`copy`、`sync`、`pull`、`mv`、`rm`、`check`、`mount`（FUSE / FUSE-T）など直感的なコマンドで操作できます。
- **1 コマンドでサーバー起動 (`dfssvc`)**: ローカルの名簿（L2）＋チャンク保管庫（L3）サービスを 1 コマンドで立ち上げ、接続設定や DNSSEC 用レコードも出力できます。
- **手軽な共有とブラウザ UI**:
  - `dfscli web`: スマホやブラウザから直接閲覧・操作できるファイル共有 & Web CLI サーバーを起動します。
  - `dfscli invite` / `dfscli share`: RunPod などの一時的なクラウド環境向けに、読み取り専用招待トークンや 1 行の `curl | bash` ブートストラップコマンドを発行します。
- **NAT 越え・柔軟なトランスポート**: LAN/ICE での直接接続と libp2p/QUIC による複数シード分散配信を標準装備（512 MiB 実測で 1 シード比約 4 倍の高速化を確認したため必須依存化）しつつ、厳格な NAT 環境では暗号化 WebSocket/HTTP リレーへ自動フォールバックします。
- **アーカイブ & オフライン配布**: `dfscli archive` / `dfscli import` で、可搬な `tar.gz` バンドル（PAR2 リカバリブロックや BitTorrent 対応）を作成・展開できます。
- **Copy-on-Write スナップショット**: macOS の APFS（`clonefile`）や Linux の Btrfs サブボリュームを活用した高速なローカルスナップショット（`dfscli fs`）に対応しています。

---

## 動作要件

- Python `3.11` 以上
- [OpenSSH](https://www.openssh.com/)（`ssh-keygen`）— Ed25519 鍵の生成および署名に使用
- [OpenSSL](https://github.com/openssl/openssl)（`openssl`）— TLS 証明書の生成に使用
- 主要 Python ライブラリ:
  - [cryptography](https://github.com/pyca/cryptography)（ChaCha20-Poly1305 AEAD・HKDF・scrypt・TLS/X.509）
  - [dnspython](https://github.com/rthalley/dnspython)（DNS / DNSSEC レコード参照）
  - [py-libp2p](https://github.com/libp2p/py-libp2p)（QUIC/TCP P2P チャンク分散配信・DHT。複数シード分散による約 4 倍の高速化を受け必須依存化）
  - [python-zstandard](https://github.com/indygreg/python-zstandard)（Zstandard 圧縮）
- オプション:
  - **FUSE マウント（`dfscli mount`）**: [fusepy](https://github.com/fusepy/fusepy) + [macFUSE](https://github.com/macfuse/macfuse) / [FUSE-T](https://github.com/macos-fuse-t/fuse-t)（macOS）または [libfuse](https://github.com/libfuse/libfuse)（Linux）
  - [par2cmdline](https://github.com/Parchive/par2cmdline)（`par2`）— `dfscli archive` の PAR2 生成・修復用
  - [libqrencode](https://github.com/fukuchi/libqrencode)（`qrencode`）— `dfscli web` の QR コード表示用

---

## クイックスタート

### 1. インストール

[`uv`](https://docs.astral.sh/uv/) を使う場合（推奨）:

```bash
git clone https://github.com/yashiki2005/dfs.git dfs
cd dfs
uv sync
```

`pip` を使う場合:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

#### ビルド済みPython wheel

各GitHub Releaseには、`dfs`本体・CLIエントリーポイント・翻訳データを
含むOS非依存の`dfs-<version>-py3-none-any.whl`を添付します。
Python 3.11以上で利用できます。

```bash
python -m pip install dfs-<version>-py3-none-any.whl
```

サードパーティ依存は通常のPython wheelと同様に解決します。
`dfs`は`fastecdsa==4.0.0`を明示し、`py-libp2p 0.8.1`の古い推移依存を
overrideするため、以前必要だったmacOSのGMPビルドは不要です。

```bash
uv pip install \
  --overrides fastecdsa-overrides.txt \
  dfs-<version>-py3-none-any.whl
```

`py-libp2p 0.8.1`のmetadataは引き続き`fastecdsa==2.3.2`を宣言しており、
DFSが要求する4.0.0と衝突します。py-libp2p側でこの宣言が更新されるまでは、
通常の`pip`では解決できません。wheelと一緒に配布するoverrideファイルを
指定してuvでインストールしてください。

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

## 圧縮とファイルシステムの挙動

### 圧縮ポリシー（`auto`, `zstd`, `none`）
- **透過的な zstd 圧縮**: ファイルチャンクは暗号化（ChaCha20-Poly1305）の**直前**にクライアント側で Zstandard（レベル 10）圧縮されます。
- **重複排除への影響なし**: 平文の内容識別子（`plain_id`）は圧縮前の平文から計算されるため、圧縮の有無や設定に関わらず過去の版や別リモートとの重複排除が機能します。
- **インテリジェントな適応判定（`auto`）**: 4 KB 未満の小さなチャンクや、サンプリング試行で 5% 以上の削減効果が得られないデータ（すでに圧縮された動画・画像・ZIP等）は自動的に非圧縮（`none`）で保存され、CPU負荷と肥大化を防ぎます。
- **拡張属性（xattr）による階層的設定**: `xattr -w user.dfs.compression zstd ./src` のようにディレクトリ単位で指定でき、配下のファイルは親フォルダの設定を自動継承します。決定した実効ポリシーは署名付きマニフェストに記録され、別環境でも保持されます。

### ファイルシステムと OS による挙動の違い（macOS / Linux ext4 など）
- **CoW（コピーオンライト）スナップショット**:
  - **macOS（APFS）**: システムコール `clonefile(2)` を利用し、追加容量ゼロ・瞬時にローカルスナップショットを作成します。
  - **Linux（Btrfs / XFS / ZFS 等）**: `ioctl(FICLONE)` を自動プローブし、ブロック単位のクローン（Reflink）を行います。
  - **Linux（ext4）**: **完全に動作します。** ext4 のように Reflink 非対応のファイルシステムでは、自動的に標準の実コピー（`CopyBackend`）へフォールバックします。暗号化・同期・圧縮・FUSE マウントなど全機能が 100% 同様に動作します（スナップショット作成時に通常コピーが行われる点のみ異なります）。
  - **Windows（ReFS）**: `FSCTL_DUPLICATE_EXTENTS_TO_FILE` によるブロッククローンを利用します。
- **FUSE マウント (`dfscli mount`)**:
  - **Linux**: 標準のカーネル FUSE（[libfuse](https://github.com/libfuse/libfuse)、`libfuse.so`）で直接マウントします。
  - **macOS**: **[macFUSE](https://github.com/macfuse/macfuse) (FSKit バックエンド)** → **[FUSE-T](https://github.com/macos-fuse-t/fuse-t)**（NFS/SMB ループバック） → **[macFUSE](https://github.com/macfuse/macfuse)（通常）** の順で安全に自動試行・フォールバックします（`--backend` で固定も可能）。
- **拡張属性（xattr）**:
  - **Linux**: 標準の `user.*` 属性を操作・同期します。
  - **macOS**: libc を直接呼び出し、`user.*` に加えて macOS 固有の `com.apple.*` メタデータ属性も適切に処理します。

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

---

## プロジェクト方針

- [セキュリティポリシー](SECURITY.md)
- [コントリビューション](CONTRIBUTING.md)
- [変更履歴](CHANGELOG.md)

## ライセンス

[MIT License](LICENSE) で公開します。
