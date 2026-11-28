# インストールガイド (`INSTALL.ja.md`)

> [English](INSTALL.md) | **日本語**

このドキュメントでは、`dfs`（`dfs` / `dfscli` / `dfssvc`）のインストール方法、オプション機能、および **なぜスタンドアロンバイナリを配布しているのか** を説明します。

---

## なぜバイナリを配布するのか？

`dfs` は Python 製ですが、GitHub Releases では各 OS 向けのスタンドアロン実行バイナリ（`dfs` / `dfscli` / `dfssvc`）も配布しています。理由は主に次の 2 点です。

1. **Python / `uv` / `git` すら無い環境への即座の導入**
   - 新規サーバー・最小コンテナ・Windows 環境などで Python 3.11+ やパッケージマネージャを用意せず、アーカイブを展開するだけで `dfs` を実行できます。
2. **外部 CLI 依存の最小化**
   - `dfs` は `ssh-keygen`（OpenSSH）や `openssl` が入っていればそれを優先利用し、**入っていない環境では内蔵の `cryptography` 処理へ自動フォールバック**します。そのため最小コンテナ等でもバイナリ単体で鍵生成・署名・自己署名 TLS 証明書生成まで動作します。

---

## インストール方法の選び方

| 方法 | おすすめの場面 | `libp2p` (P2P) |
|---|---|---|
| **1. リリースバイナリ** | 手軽に試したい / Python を入れたくない | 同梱（対応環境） |
| **2. ワンライナー (`install.sh` / `install.ps1`)** | ソースから自動セットアップしたい / RunPod 等 | 自動試行（失敗時はコアへフォールバック） |
| **3. Homebrew (`dfs.rb`)** | macOS / Linuxbrew で管理したい | リリースバイナリ同等 |
| **4. ソース / Python wheel (`uv` / `pip`)** | 開発・カスタマイズしたい / 既存 Python 環境へ入れたい | `--extra libp2p` で選択 |

---

## 1. スタンドアロンバイナリ（GitHub Releases）

[GitHub Releases](https://github.com/yashiki2005/dfs/releases) から対象 OS のアーカイブを取得して展開します。

- **macOS (Apple Silicon / arm64)**: `dfs-v<version>-darwin-arm64.tar.gz`
- **Linux (x86_64)**: `dfs-v<version>-linux-x86_64.tar.gz`
- **Linux (arm64)**: `dfs-v<version>-linux-arm64.tar.gz`
- **Windows (x86_64)**: `dfs-v<version>-windows-x86_64.zip`

```bash
# 例: Linux x86_64 の展開と配置
tar -xzf dfs-v0.1.0-linux-x86_64.tar.gz
sudo install -m 755 dfs dfscli dfssvc /usr/local/bin/
```

ハッシュ検証を行う場合は、リリースに添付されている `SHA256SUMS.txt` を利用してください：

```bash
sha256sum -c --ignore-missing SHA256SUMS.txt
```

> **macOS での注意**: ブラウザからダウンロードした場合、Gatekeeper により初回実行がブロックされることがあります。その場合は展開先で `xattr -d com.apple.quarantine dfs dfscli dfssvc` を実行してください。

---

## 2. ワンライナーインストーラ

### macOS / Linux
```bash
curl -sSL https://raw.githubusercontent.com/yashiki2005/dfs/main/scripts/install.sh | bash
```

- 書き込み可能な `PATH` 上のディレクトリ（`/opt/homebrew/bin` または `/usr/local/bin`）があればそこへ、無ければ `~/.local/bin` へ配置し、必要に応じて `~/.zshrc` / `~/.bashrc` / `~/.profile` に `PATH` を自動追記します（`DFS_NO_MODIFY_PATH=1` で追記を抑止できます）。
- まず `uv sync --extra libp2p` を試行し、環境都合で失敗した場合は自動的にコア依存（`uv sync`）へフォールバックします。

### Windows (PowerShell)
```powershell
irm https://raw.githubusercontent.com/yashiki2005/dfs/main/scripts/install.ps1 | iex
```

---

## 3. Homebrew でのインストール (macOS / Linuxbrew)

各 GitHub Release には、リリースバイナリの SHA256 を埋め込んだ `dfs.rb`（[Formula/dfs.rb](Formula/dfs.rb) から自動生成）が添付されています。Homebrew 本家（`homebrew-core`）への登録や審査は不要で、以下の方法で利用できます。

### リリース添付の `dfs.rb` から直接インストール（追加リポジトリ不要）

```bash
curl -fsSLO https://github.com/yashiki2005/dfs/releases/latest/download/dfs.rb
brew install ./dfs.rb
```

- 対応プラットフォーム: macOS Apple Silicon (`darwin-arm64`)、Linux x86_64 (`linux-x86_64`)、Linux ARM64 (`linux-arm64`)。
- `dfs` / `dfscli` / `dfssvc` の3コマンドが Homebrew の `bin` にインストールされます。

> **カスタム Tap で配布する場合（メンテナー向け）**: GitHub に `homebrew-tap`（例: `yashiki2005/homebrew-tap`）という公開リポジトリを作成し、その `Formula/dfs.rb` にリリース生成物の `dfs.rb` を配置するだけで、`brew install yashiki2005/tap/dfs` の形式で配布・`brew upgrade` 対応ができます（公式登録・審査は不要です）。

---

## 4. ソース / Python wheel からのインストールと注意点

### `uv` を使う場合（推奨）

```bash
git clone https://github.com/yashiki2005/dfs.git
cd dfs

# コア機能のみ
uv sync

# P2P (libp2p) も含める場合
uv sync --extra libp2p
```

wheel からインストールする場合は、通常どおり `uv pip install` または `pip install` で導入できます：

```bash
uv pip install dfs-<version>-py3-none-any.whl
# または pip の場合:
python -m pip install dfs-<version>-py3-none-any.whl
```

> 補足: `py-libp2p>=0.8.3` で `fastecdsa` 依存が廃止され `cryptography` ベースに移行したため、`gmp.h` や `fastecdsa-overrides.txt` は不要になりました。

### ⚠️ オプション機能用の外部ツール

| 機能 | 必要なツール / ライブラリ | 備考 |
|---|---|---|
| 鍵生成・署名・TLS 証明書 | `ssh-keygen`, `openssl` | 任意。導入済みなら優先利用し、無ければ内蔵 `cryptography` で自動代替 |
| FUSE マウント (`dfs mount`) | `dfs[fuse]` (`fusepy`) + `macFUSE` / `FUSE-T` (macOS) または `libfuse` (Linux) | マウント機能を使う場合のみ必要 |
| PAR2 リカバリ (`dfscli archive --recovery`) | `par2cmdline` (`par2`) | 修復パリティを生成する場合のみ必要 |
| 端末 QR コード (`dfscli web`) | `libqrencode` (`qrencode`) | ターミナルに QR を出したい場合のみ必要 |
