#!/usr/bin/env bash
set -euo pipefail

# RunPod 等の使い捨て環境向け・読み取り専用 dfs 自動同期ブートストラップ。
# トークンは HTTP URL クエリに乗せず、引数または環境変数 DFS_INVITE_TOKEN で渡す。
#
# 使い方:
#   curl -sSL https://example.com/bootstrap_ro.sh | bash -s -- <BASE64_TOKEN>
#   DFS_DEST=/workspace/data DFS_SYNC_ONLY=1 curl -sSL ... | bash -s -- <BASE64_TOKEN>

TOKEN="${1:-${DFS_INVITE_TOKEN:-}}"
if [ -z "$TOKEN" ]; then
  echo "Usage: curl -sSL <url>/bootstrap_ro.sh | bash -s -- <dfs-ro-v1:...>" >&2
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
