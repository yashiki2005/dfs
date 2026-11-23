# インストールガイド (`INSTALL.ja.md`)

> [English](INSTALL.md) | **日本語**

このドキュメントでは、`dfs`（`dfs` / `dfscli` / `dfssvc`）のインストール方法、ビルド時の注意点（特に `gmp.h` や `fastecdsa` 周り）、および **なぜスタンドアロンバイナリを配布しているのか** を説明します。

---

## なぜバイナリを配布するのか？

`dfs` は Python 製ですが、GitHub Releases では各 OS 向けのスタンドアロン実行バイナリ（`dfs` / `dfscli` / `dfssvc`）も配布しています。理由は主に次の 3 点です。

1. **`gmp.h` や C コンパイラなしでも `py-libp2p` 同梱版をすぐ動かせるため**
   - P2P 分散配信（`libp2p` extra）が依存する `py-libp2p` は内部で `fastecdsa` を使用します。環境によってはソースビルド時に **`gmp.h`（GNU Multiple Precision Arithmetic Library のヘッダ）** と C コンパイラ（`gcc` / `clang`）が必須になり、`libgmp-dev` 未導入の環境では `fatal error: gmp.h: No such file or directory` で失敗します。
   - さらに `py-libp2p 0.8.1` のメタデータが古い `fastecdsa==2.3.2` を固定しているため、Python 3.12 以降や macOS では通常の `pip` だけで依存解決が通りません。
   - リリースバイナリは CI 上で **Miniconda（`conda-forge` の `gmp`・OpenSSL）＋ PyInstaller** を使ってビルドしており、`libgmp` / `libcrypto` / `libssl` と `py-libp2p` をすべて同梱済みです。
2. **Python / `uv` / `git` すら無い環境への即座の導入**
   - 新規サーバー・最小コンテナ・Windows 環境などで Python 3.11+ やパッケージマネージャを用意せず、アーカイブを展開するだけで `dfs` を実行できます。
3. **外部 CLI 依存の最小化**
   - `dfs` は `ssh-keygen`（OpenSSH）や `openssl` が入っていればそれを優先利用し、**入っていない環境では内蔵の `cryptography` 処理へ自動フォールバック**します。そのため最小コンテナ等でもバイナリ単体で鍵生成・署名・自己署名 TLS 証明書生成まで動作します。

---

## インストール方法の選び方

| 方法 | おすすめの場面 | `libp2p` (P2P) | `gmp.h` 要否 |
|---|---|---|---|
| **1. リリースバイナリ** | 手軽に試したい / C コンパイラや Python を入れたくない | 同梱（対応環境） | **不要** |
| **2. ワンライナー (`install.sh` / `install.ps1`)** | ソースから自動セットアップしたい / RunPod 等 | 自動試行（失敗時はコアへフォールバック） | 環境による |
| **3. Homebrew (`dfs.rb`)** | macOS / Linuxbrew で管理したい | リリースバイナリ同等 | **不要** |
| **4. ソース / Python wheel (`uv` / `pip`)** | 開発・カスタマイズしたい / 既存 Python 環境へ入れたい | `--extra libp2p` で選択 | ソースビルド時は要 |

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

# コア機能のみ（gmp.h 不要・最も安定）
uv sync

# P2P (libp2p) も含める場合
uv sync --extra libp2p
```

wheel からインストールする場合は、リポジトリ／リリース同梱の `fastecdsa-overrides.txt` を指定してください：

```bash
uv pip install --overrides fastecdsa-overrides.txt dfs-<version>-py3-none-any.whl
```

### ⚠️ 注意点 1: `gmp.h` が見つからずビルドに失敗する場合

`--extra libp2p` 導入時に `fastecdsa` のホイールが環境に合わずソースコンパイルが走ると、以下のエラーが出ることがあります：

```text
fatal error: gmp.h: No such file or directory
```

**対処法**:
- **Ubuntu / Debian**: `sudo apt-get update && sudo apt-get install -y libgmp-dev build-essential python3-dev`
- **Fedora / RHEL**: `sudo dnf install -y gmp-devel gcc python3-devel`
- **macOS (Homebrew)**: `brew install gmp`（必要なら `CPATH="$(brew --prefix gmp)/include" LIBRARY_PATH="$(brew --prefix gmp)/lib"` を指定）
- **conda / Miniconda**: `conda install -c conda-forge gmp`
- **P2P が不要な場合**: `uv sync` のみ（`--extra libp2p` なし）を使えば `gmp.h` は一切不要です。

### ⚠️ 注意点 2: `pip` での `libp2p` 解決衝突

`py-libp2p 0.8.1` が `fastecdsa==2.3.2` を宣言しているため、通常の `pip install 'dfs[libp2p]'` では `dfs` 側の `fastecdsa==4.0.0` 指定と衝突する場合があります。`libp2p` を含める場合は **`uv` + `fastecdsa-overrides.txt`** または **リリースバイナリ** を利用してください（コア機能だけの `pip install -e .` は通常どおり通ります）。

### ⚠️ 注意点 3: オプション機能用の外部ツール

| 機能 | 必要なツール / ライブラリ | 備考 |
|---|---|---|
| 鍵生成・署名・TLS 証明書 | `ssh-keygen`, `openssl` | 任意。導入済みなら優先利用し、無ければ内蔵 `cryptography` で自動代替 |
| FUSE マウント (`dfs mount`) | `dfs[fuse]` (`fusepy`) + `macFUSE` / `FUSE-T` (macOS) または `libfuse` (Linux) | マウント機能を使う場合のみ必要 |
| PAR2 リカバリ (`dfscli archive --recovery`) | `par2cmdline` (`par2`) | 修復パリティを生成する場合のみ必要 |
| 端末 QR コード (`dfscli web`) | `libqrencode` (`qrencode`) | ターミナルに QR を出したい場合のみ必要 |
