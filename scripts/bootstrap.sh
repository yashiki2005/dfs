#!/usr/bin/env bash
set -euo pipefail

# RunPod 等の使い捨て環境向け dfs 自動セットアップ・同期ブートストラップ。
# 読み取り専用トークン (dfs-ro-v1:...) と出力先委譲付きトークン (dfs-rw-v1:...) の両方に対応。
# トークンは HTTP URL クエリに乗せず、引数または環境変数 DFS_INVITE_TOKEN で渡す。
#
# 使い方:
#   curl -sSL https://dfs.example.com/bootstrap.sh | bash -s -- <TOKEN>
#   DFS_DEST=/workspace/data DFS_SYNC_ONLY=1 curl -sSL https://dfs.example.com/bootstrap.sh | bash -s -- <TOKEN>

TOKEN="${1:-${DFS_INVITE_TOKEN:-}}"
if [ -z "$TOKEN" ]; then
  echo "Usage: curl -sSL https://dfs.example.com/bootstrap.sh | bash -s -- <dfs-ro-v1:...|dfs-rw-v1:...>" >&2
  exit 2
fi

INSTALL_SPEC="${DFS_INSTALL_SPEC:-dfs}"
DEST_DIR="${DFS_DEST:-./dfs-sync}"

if ! command -v dfscli >/dev/null 2>&1; then
  if ! command -v uv >/dev/null 2>&1; then
    curl -LsSf https://astral.sh/uv/install.sh | sh
    export PATH="$HOME/.local/bin:$PATH"
  fi
  uv tool install --force "$INSTALL_SPEC"
  export PATH="$HOME/.local/bin:$PATH"
fi

if [ "${DFS_SYNC_ONLY:-0}" = "1" ]; then
  exec dfscli invite join "$TOKEN" --dest "$DEST_DIR" --sync
else
  exec dfscli invite join "$TOKEN" --dest "$DEST_DIR" --watch
fi
