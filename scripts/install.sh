#!/usr/bin/env bash
set -euo pipefail

# One-line installer for dfscli & dfssvc (macOS / Linux).
# Usage:
#   curl -sSL https://raw.githubusercontent.com/yashiki2005/dfs/main/scripts/install.sh | bash

REPO_URL="${DFS_REPO_URL:-https://github.com/yashiki2005/dfs.git}"
TARBALL_URL="${DFS_TARBALL_URL:-https://github.com/yashiki2005/dfs/archive/refs/heads/main.tar.gz}"
INSTALL_DIR="${DFS_INSTALL_DIR:-$HOME/.local/share/dfs}"
BIN_DIR="$HOME/.local/bin"

export PATH="$BIN_DIR:$HOME/.cargo/bin:$PATH"

if ! command -v uv >/dev/null 2>&1; then
  curl -LsSf https://astral.sh/uv/install.sh | sh
  export PATH="$BIN_DIR:$HOME/.cargo/bin:$PATH"
fi

if command -v git >/dev/null 2>&1; then
  if [ -d "$INSTALL_DIR/.git" ]; then
    git -C "$INSTALL_DIR" pull --ff-only
  else
    rm -rf "$INSTALL_DIR"
    mkdir -p "$(dirname "$INSTALL_DIR")"
    git clone --depth 1 "$REPO_URL" "$INSTALL_DIR"
  fi
else
  TMP_DIR="$(mktemp -d)"
  trap 'rm -rf "$TMP_DIR"' EXIT
  curl -sSL "$TARBALL_URL" | tar -xz -C "$TMP_DIR"
  SRC_DIR="$(find "$TMP_DIR" -maxdepth 1 -mindepth 1 -type d | head -n 1)"
  rm -rf "$INSTALL_DIR"
  mkdir -p "$(dirname "$INSTALL_DIR")"
  mv "$SRC_DIR" "$INSTALL_DIR"
fi

if ! uv sync --project "$INSTALL_DIR" --extra libp2p; then
  echo "[dfs] libp2p extra failed on this environment; installing core dependencies..." >&2
  uv sync --project "$INSTALL_DIR"
fi

mkdir -p "$BIN_DIR"
ln -sf "$INSTALL_DIR/.venv/bin/dfs" "$BIN_DIR/dfs"
ln -sf "$INSTALL_DIR/.venv/bin/dfscli" "$BIN_DIR/dfscli"
ln -sf "$INSTALL_DIR/.venv/bin/dfssvc" "$BIN_DIR/dfssvc"

echo ""
echo "Installed dfs, dfscli, and dfssvc to $BIN_DIR"
echo "Make sure $BIN_DIR is in your PATH, then run:"
echo "  dfs start"
echo "  dfs push ./my-folder"
