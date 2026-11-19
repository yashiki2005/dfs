#!/usr/bin/env bash
set -euo pipefail

# RunPod / ephemeral worker bootstrap for dfs.
# Supports both read-only tokens (dfs-ro-v1:...) and scoped write-back tokens (dfs-rw-v1:...).
# Pass the token as $1 or DFS_INVITE_TOKEN (never in HTTP URL query strings).
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/yashiki2005/dfs/main/scripts/bootstrap.sh | bash -s -- <TOKEN>
#   DFS_DEST=/workspace/data DFS_SYNC_ONLY=1 curl -sSL https://raw.githubusercontent.com/yashiki2005/dfs/main/scripts/bootstrap.sh | bash -s -- <TOKEN>

TOKEN="${1:-${DFS_INVITE_TOKEN:-}}"
if [ -z "$TOKEN" ]; then
  echo "Usage: curl -sSL https://raw.githubusercontent.com/yashiki2005/dfs/main/scripts/bootstrap.sh | bash -s -- <dfs-ro-v1:...|dfs-rw-v1:...>" >&2
  exit 2
fi

DEST_DIR="${DFS_DEST:-./dfs-sync}"
BIN_DIR="$HOME/.local/bin"
export PATH="$BIN_DIR:$HOME/.cargo/bin:$PATH"

if ! command -v dfscli >/dev/null 2>&1; then
  INSTALL_URL="${DFS_INSTALL_SCRIPT_URL:-https://raw.githubusercontent.com/yashiki2005/dfs/main/scripts/install.sh}"
  curl -sSL "$INSTALL_URL" | bash
  export PATH="$BIN_DIR:$HOME/.cargo/bin:$PATH"
fi

if [ "${DFS_SYNC_ONLY:-0}" = "1" ]; then
  exec dfscli invite join "$TOKEN" --dest "$DEST_DIR" --sync
else
  exec dfscli invite join "$TOKEN" --dest "$DEST_DIR" --watch
fi
