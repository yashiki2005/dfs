#!/usr/bin/env bash
set -euo pipefail

# RunPod 等の使い捨て環境向け dfs 自動セットアップ・同期ブートストラップ。
# 読み取り専用トークン (dfs-ro-v1:...) と出力先委譲付きトークン (dfs-rw-v1:...) の両方に対応。
# トークンは HTTP URL クエリに乗せず、引数または環境変数 DFS_INVITE_TOKEN で渡す。
#
# 使い方:
#   curl -sSL https://raw.githubusercontent.com/yashiki2005/dfs/main/scripts/bootstrap.sh | bash -s -- <TOKEN>
#   DFS_DEST=/workspace/data DFS_SYNC_ONLY=1 curl -sSL https://raw.githubusercontent.com/yashiki2005/dfs/main/scripts/bootstrap.sh | bash -s -- <TOKEN>

TOKEN="${1:-${DFS_INVITE_TOKEN:-}}"
if [ -z "$TOKEN" ]; then
  echo "Usage: curl -sSL https://raw.githubusercontent.com/yashiki2005/dfs/main/scripts/bootstrap.sh | bash -s -- <dfs-ro-v1:...|dfs-rw-v1:...>" >&2
  exit 2
fi

REPO_URL="${DFS_REPO_URL:-https://github.com/yashiki2005/dfs.git}"
INSTALL_DIR="${DFS_INSTALL_DIR:-$HOME/.local/share/dfs}"
BIN_DIR="$HOME/.local/bin"
DEST_DIR="${DFS_DEST:-./dfs-sync}"

export PATH="$BIN_DIR:$HOME/.cargo/bin:$PATH"

if ! command -v dfscli >/dev/null 2>&1; then
  if ! command -v git >/dev/null 2>&1; then
    echo "Error: git is required to install dfs." >&2
    exit 1
  fi
  if ! command -v uv >/dev/null 2>&1; then
    curl -LsSf https://astral.sh/uv/install.sh | sh
    export PATH="$BIN_DIR:$HOME/.cargo/bin:$PATH"
  fi
  if [ -d "$INSTALL_DIR/.git" ]; then
    git -C "$INSTALL_DIR" pull --ff-only
  else
    mkdir -p "$(dirname "$INSTALL_DIR")"
    git clone --depth 1 "$REPO_URL" "$INSTALL_DIR"
  fi
  uv sync --project "$INSTALL_DIR"
  mkdir -p "$BIN_DIR"
  ln -sf "$INSTALL_DIR/.venv/bin/dfscli" "$BIN_DIR/dfscli"
  ln -sf "$INSTALL_DIR/.venv/bin/dfssvc" "$BIN_DIR/dfssvc"
fi

if [ "${DFS_SYNC_ONLY:-0}" = "1" ]; then
  exec dfscli invite join "$TOKEN" --dest "$DEST_DIR" --sync
else
  exec dfscli invite join "$TOKEN" --dest "$DEST_DIR" --watch
fi
