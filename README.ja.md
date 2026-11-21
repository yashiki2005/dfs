# dfs

[![CI](https://github.com/yashiki2005/dfs/actions/workflows/ci.yml/badge.svg)](https://github.com/yashiki2005/dfs/actions/workflows/ci.yml)

> [English](README.md) | **日本語**

**サーバーもリレーも、レンタル GPU すら信用せずに、暗号化データセットを 1 行で同期する。**

**dfs** は、単一ライターの信頼モデルと `rclone` 風 CLI（`ls`, `copy`, `sync`, `pull`, `mount`）を備えた、エンドツーエンド暗号化・重複排除対応の分散ファイルシステムです。チャンク分割・圧縮・暗号化・署名はすべて端末側で完結します。

> **プロジェクト状態:** `0.1.x` は初期リリース系列です。独立したセキュリティ監査は
> 受けていません。重要なデータへ適用する前に脅威モデルを確認してください。

---

## なぜ dfs なのか？（主なユースケース）

1. **クラウド GPU / 一時ワーカーへの 1 行データ配布（RunPod・Lambda 等）**
   - レンタル GPU に個人の SSH 鍵や S3 クレデンシャルを置いたり、毎回巨大な tarball を `scp` したりする必要はありません。
   - 手元で `dfscli share mydata --write-path out` を実行すると、`raw.githubusercontent.com` 上の `bootstrap.sh`（`git clone` + `uv sync`）を呼ぶ 1 行の `curl | bash` コマンドが生成されます。
   - 自宅 NAT 越えには既定でリレーハブ（`yashiki.top`）を利用しますが、リレーに復号鍵や平文は一切渡らず（E2E 暗号化）、`--no-hub` で無効化したり自分の VPS 等で `dfssvc start --hub ...` を自前ホストしたりすることもできます。
   - GPU ワーカーはデータセットを読み取り専用で取得（直接接続 / 複数シード libp2p-QUIC / 暗号化リレー）し、委譲された `out` サブパスにだけ結果を書き戻せます。
2. **Mac / Linux / Windows 間のゼロトラスト `rclone` 風同期**
   - 自宅サーバーや Raspberry Pi・VPS を暗号化チャンク保管庫（`dfssvc start`）にして、手元の PC から `dfscli sync`・`dfscli pull`・`dfscli mount` で同期できます。
   - ストレージサーバーやリレーサーバーには平文のファイル名も中身も一切見えません。
3. **単一ライターによる改ざん・巻き戻し・黙殺の自動検知**
   - すべての更新を署名付き追記ログと Merkle ツリーで連結し、サーバー側の勝手な巻き戻し（**B6**）や書き込みの黙った破棄（**B7**）をクライアント側で自動検知して拒否します。

---

## 60 秒で試す

```bash
# 0. 1 行インストール（macOS / Linux）
curl -sSL https://raw.githubusercontent.com/yashiki2005/dfs/main/scripts/install.sh | bash
```

```powershell
# 0. 1 行インストール（Windows PowerShell）
irm https://raw.githubusercontent.com/yashiki2005/dfs/main/scripts/install.ps1 | iex
```

```bash
# 1. ローカルサーバー起動＆初期設定（リポジトリ内からは ./cli でも可）
dfs start

# 2. 同期・一覧・復元
dfs push ./dataset
dfs ls
dfs pull ./restored
```

---

## 主な特徴

- **エンドツーエンド暗号化 & 重複排除**: ファイルは端末側でチャンク分割・Zstandard 圧縮されたのち、収束暗号（ChaCha20-Poly1305）で暗号化してから送信されます。
- **単一ライターによる改ざん防止**: サブツリーごとにドメインルート鍵から署名付き委譲を受けた 1 つのライター鍵のみが書き込み可能で、すべての更新は署名付き追記ログと Merkle ツリーで検証されます。
- **親しみやすい統合 CLI (`dfs` / `./cli`) と `rclone` 風詳細 CLI (`dfscli`)**: `dfs start` / `push` / `pull` / `ls` / `share` / `join` / `web` / `mount` のシンプルな統合コマンドに加え、`dfscli` で `copy`、`sync`、`mv`、`rm`、`check` などの細かな操作も行えます。
- **1 コマンドでサーバー起動 (`dfs start` / `dfssvc`)**: ローカルの名簿（L2）＋チャンク保管庫（L3）とリモート設定を `dfs start` 1 回で立ち上げられ、`dfssvc` でポートや DNSSEC レコード等の詳細制御も可能です。
- **手軽な共有とブラウザ UI**:
  - `dfs web`: スマホやブラウザから直接閲覧・操作できるファイル共有 & Web CLI サーバーを起動します。
  - `dfs share` / `dfscli invite`: RunPod などの一時的なクラウド環境向けに、読み取り専用招待トークンや 1 行の `curl | bash` ブートストラップコマンドを発行します。
- **NAT 越え・柔軟なトランスポート**: LAN/ICE での直接接続、暗号化 WebSocket/HTTP リレーへの自動フォールバックを標準装備し、`libp2p` extra 導入時には libp2p/QUIC による複数シード分散配信（512 MiB 実測で 1 シード比約 4 倍の高速化）も利用できます。
- **アーカイブ & オフライン配布**: `dfscli archive` / `dfscli import` で、可搬な `tar.gz` バンドル（PAR2 リカバリブロックや BitTorrent 対応）を作成・展開できます。
- **Copy-on-Write スナップショット**: macOS の APFS（`clonefile`）や Linux の Btrfs サブボリュームを活用した高速なローカルスナップショット（`dfscli fs`）に対応しています。

---

## 動作要件

- Python `3.11` 以上
- オプション外部ツール（未導入時は `cryptography` による内蔵処理へ自動フォールバック）:
  - [OpenSSH](https://www.openssh.com/)（`ssh-keygen`）— 導入済みなら Ed25519 鍵生成・パスフレーズ付き鍵の署名に優先使用
  - [OpenSSL](https://github.com/openssl/openssl)（`openssl`）— 導入済みなら TLS 証明書生成に優先使用
- 主要 Python ライブラリ:
  - [cryptography](https://github.com/pyca/cryptography)（ChaCha20-Poly1305 AEAD・HKDF・scrypt・TLS/X.509）
  - [dnspython](https://github.com/rthalley/dnspython)（DNS / DNSSEC レコード参照）
  - [python-zstandard](https://github.com/indygreg/python-zstandard)（Zstandard 圧縮）
- オプション:
  - **P2P 分散配信（`libp2p` extra）**: [py-libp2p](https://github.com/libp2p/py-libp2p)（`uv sync --extra libp2p` / `pip install 'dfs[libp2p]'`、ワンライナーは自動試行）
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

### 2. ローカルサーバー起動＆初期設定 (`dfs` / `./cli`)

リポジトリをクローンして直接動かす場合は `dfs` の代わりに `./cli`（Windows では `.\cli.cmd`）をそのまま使えます。

```bash
# ローカル L2 + L3 サーバーを起動し、リモート 'local' を自動設定
dfs start

# 状態やサービス・リモート一覧を確認
dfs status
dfs list

# 停止したいとき
dfs stop
```

> 既定では NAT 越え用に `yashiki.top` リレーハブへ自動参加します（E2E 暗号化のためハブに鍵や平文は渡りません）。ローカル完結にしたい場合は `dfs start --no-hub` を指定してください。

### 3. ファイル同期・一覧・復元 (`dfs push` / `ls` / `pull`)

`dfs push` は `'local'` 未起動時に自動起動まで行うため、最小構成では `dfs push` から始めることもできます。

```bash
# ローカルディレクトリをリモート（既定: local:）へ同期
dfs push ./dataset

# 変更点だけ確認（ドライラン） / リモート側の余分なファイルを削除して同期
dfs push ./dataset --dry-run
dfs push ./dataset --delete

# リモートのファイル一覧
dfs ls

# 別ディレクトリへ復元
dfs pull ./restored-dataset
```

`remote:path` を明示して別リモートやサブパスへ操作することも可能です（例: `dfs push ./notes local:notes`、`dfs pull local:notes ./out`）。より細かなファイル操作（`copy`、`cat`、`mv`、`rm`、`check` 等）には `dfscli` を使用します。

### 4. 別端末・ブラウザ・GPU ワーカーでの共有

- **Web UI**（スマホやブラウザからアクセス）:
  ```bash
  dfs web
  ```
- **別マシン / RunPod 等への 1 行共有**（`dfs share`）:
  ```bash
  # 読み取り専用 + out サブパスへの書き戻し許可つきブートストラップコマンドを生成
  dfs share --write-path out

  # 参加側（トークンまたは URL で参加して同期・監視）:
  dfs join <token_or_url>
  dfs join <token_or_url> --watch
  ```
- **FUSE マウント**（`dfs mount`）:
  ```bash
  dfs mount ./mnt
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
- **FUSE マウント (`dfs mount` / `dfscli mount`)**:
  - **Linux**: 標準のカーネル FUSE（[libfuse](https://github.com/libfuse/libfuse)、`libfuse.so`）で直接マウントします。
  - **macOS**: **[macFUSE](https://github.com/macfuse/macfuse) (FSKit バックエンド)** → **[FUSE-T](https://github.com/macos-fuse-t/fuse-t)**（NFS/SMB ループバック） → **[macFUSE](https://github.com/macfuse/macfuse)（通常）** の順で安全に自動試行・フォールバックします（`--backend` で固定も可能）。
- **拡張属性（xattr）**:
  - **Linux**: 標準の `user.*` 属性を操作・同期します。
  - **macOS**: libc を直接呼び出し、`user.*` に加えて macOS 固有の `com.apple.*` メタデータ属性も適切に処理します。

---

## コマンド概要

### `dfs` / `./cli`（統合 CLI・通常利用向け）

`dfscli` と `dfssvc` をラップし、日常操作を 1 コマンドにまとめたエントリポイントです（リポジトリ内からは `./cli`、Windows では `.\cli.cmd`）。

| コマンド | 説明 |
|---|---|
| `dfs start` (`serve`) | ローカル L2 + L3 サーバーを起動し、リモート `local` を自動設定（`--no-hub`, `--bind`, `--port`, `--advertise` 指定可） |
| `dfs stop` | ローカルサーバーを停止（`--forget` で設定削除） |
| `dfs status` | ローカルサーバーの稼働状態を表示 |
| `dfs list` | 登録済みのローカルサービスとリモート一覧を表示 |
| `dfs push` | ローカルのファイル/ディレクトリをリモートへ同期（`local:` 未起動時は自動起動、`--dry-run` / `--delete` 対応） |
| `dfs pull` | リモートからローカルディレクトリへ復元 |
| `dfs ls` | リモートのファイル一覧を表示 |
| `dfs share` | 別マシン・RunPod 向けの 1 行ブートストラップコマンド／トークンを生成（`--write-path` / `--token-only` 対応） |
| `dfs join` | 招待トークン（`dfs-ro-v1:` / `dfs-rw-v1:`）またはレジストリ URL から参加・同期（`--watch` 対応） |
| `dfs web` | ブラウザから閲覧・操作できる Web UI を起動 |
| `dfs mount` | FUSE 経由でリモートをローカルへマウント |

### `dfscli`（詳細クライアント・上級者向け）

| 分類 | コマンド |
|---|---|
| リモート管理・探索 | `listremotes`, `create`, `config`, `discover`, `join`, `quit`, `about` |
| ファイル操作 | `ls`, `lsd`, `lsl`, `lsjson`, `size`, `cat`, `copy`, `copyto`, `mv`, `rm`, `rmdir`, `purge`, `mkdir`, `touch` |
| 同期・マウント | `sync`, `pull`, `check`, `mount`, `history`, `fs` |
| 共有・アーカイブ | `web`, `invite`, `share`, `archive`, `import` |
| サーバー・権限管理 | `serve`, `delegate`, `promote`, `candidacy`, `libp2p-serve` |

### `dfssvc`（詳細サービス管理・上級者向け）

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

## 主な環境変数（運用・公開ハブ向け）

| 環境変数 | 既定値 | 説明 |
|---|---|---|
| `DFS_OST_MAX_BYTES` | 空き容量の 80%（1〜50 GiB） | L3 OST の全体保存容量上限（バイト、`0` で無制限） |
| `DFS_OST_MAX_WRITER_BYTES` | `10737418240` (10 GiB) | L3 OST のライター公開鍵ごとの現在使用量クォータ（`0` で無制限） |
| `DFS_AUTO_DELEGATE_TOKEN` | 未設定 | 公開ハブの `/v1/auto-delegate` をトークン保護する場合に設定（クライアント側も同変数で送信） |
| `DFS_AUTO_DELEGATE_RATE_LIMIT` | `10` | `/v1/auto-delegate` の非ループバック IP あたり 60 秒間のリクエスト上限 |
| `DFS_MAX_SNAPSHOTS` | 未設定 | ローカルスナップショットの保持世代数（CoW 環境にも適用、`0` で無制限） |
| `DFS_MAX_SNAPSHOTS_NON_COW` | `3` | ext4 等の非 CoW 環境における自動スナップショット保持世代数 |

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
