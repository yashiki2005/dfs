#!/usr/bin/env bash
set -euo pipefail

# One-line installer for dfscli & dfssvc (macOS / Linux).
# Usage:
#   curl -sSL https://raw.githubusercontent.com/yashiki2005/dfs/main/scripts/install.sh | bash

REPO_URL="${DFS_REPO_URL:-https://github.com/yashiki2005/dfs.git}"
DFS_REF="${DFS_REF:-main}"
TARBALL_URL="${DFS_TARBALL_URL:-https://github.com/yashiki2005/dfs/archive/refs/heads/${DFS_REF}.tar.gz}"
TARBALL_SHA256="${DFS_TARBALL_SHA256:-}"
INSTALL_DIR="${DFS_INSTALL_DIR:-$HOME/.local/share/dfs}"

_in_path() {
  case ":$PATH:" in
    *":$1:"*) return 0 ;;
    *) return 1 ;;
  esac
}

# Prefer a writable directory already in PATH so `dfs` works immediately without restarting the shell.
if [ -n "${DFS_BIN_DIR:-}" ]; then
  BIN_DIR="$DFS_BIN_DIR"
elif _in_path "/opt/homebrew/bin" && [ -w "/opt/homebrew/bin" ]; then
  BIN_DIR="/opt/homebrew/bin"
elif _in_path "/usr/local/bin" && [ -w "/usr/local/bin" ]; then
  BIN_DIR="/usr/local/bin"
else
  BIN_DIR="$HOME/.local/bin"
fi

WAS_IN_PATH=0
if _in_path "$BIN_DIR"; then
  WAS_IN_PATH=1
fi

export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$BIN_DIR:$PATH"

if ! command -v uv >/dev/null 2>&1; then
  curl -LsSf https://astral.sh/uv/install.sh | sh
  export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$BIN_DIR:$PATH"
fi

if command -v git >/dev/null 2>&1; then
  if [ -d "$INSTALL_DIR/.git" ]; then
    git -C "$INSTALL_DIR" fetch --depth 1 origin "$DFS_REF"
    git -C "$INSTALL_DIR" checkout -q FETCH_HEAD || git -C "$INSTALL_DIR" pull --ff-only
  else
    rm -rf "$INSTALL_DIR"
    mkdir -p "$(dirname "$INSTALL_DIR")"
    git clone --depth 1 --branch "$DFS_REF" "$REPO_URL" "$INSTALL_DIR"
  fi
else
  TMP_DIR="$(mktemp -d)"
  trap 'rm -rf "$TMP_DIR"' EXIT
  TARBALL_PATH="$TMP_DIR/dfs.tar.gz"
  curl -sSL "$TARBALL_URL" -o "$TARBALL_PATH"
  if [ -n "$TARBALL_SHA256" ]; then
    if command -v sha256sum >/dev/null 2>&1; then
      echo "${TARBALL_SHA256}  ${TARBALL_PATH}" | sha256sum -c -
    elif command -v shasum >/dev/null 2>&1; then
      echo "${TARBALL_SHA256}  ${TARBALL_PATH}" | shasum -a 256 -c -
    else
      echo "[dfs] WARNING: sha256sum/shasum not found; cannot verify DFS_TARBALL_SHA256" >&2
      exit 1
    fi
  fi
  tar -xz -f "$TARBALL_PATH" -C "$TMP_DIR"
  SRC_DIR="$(find "$TMP_DIR" -maxdepth 1 -mindepth 1 -type d | head -n 1)"
  rm -rf "$INSTALL_DIR"
  mkdir -p "$(dirname "$INSTALL_DIR")"
  mv "$SRC_DIR" "$INSTALL_DIR"
fi

export UV_LINK_MODE="${UV_LINK_MODE:-copy}"
case "${UV_CACHE_DIR:-}" in
  /workspace|/workspace/*)
    export UV_CACHE_DIR="/tmp/dfs-uv-cache"
    ;;
esac

_uv_sync() {
  if ! uv sync --project "$INSTALL_DIR" "$@"; then
    local fallback_cache="/tmp/dfs-uv-cache"
    if [ "${UV_CACHE_DIR:-}" != "$fallback_cache" ]; then
      echo "[dfs] Retrying uv sync with local cache ($fallback_cache)..." >&2
      UV_CACHE_DIR="$fallback_cache" UV_LINK_MODE=copy uv sync --project "$INSTALL_DIR" "$@"
      return $?
    fi
    return 1
  fi
}

if ! _uv_sync --extra libp2p; then
  echo "[dfs] libp2p extra failed on this environment; installing core dependencies..." >&2
  _uv_sync
fi

mkdir -p "$BIN_DIR"
ln -sf "$INSTALL_DIR/.venv/bin/dfs" "$BIN_DIR/dfs"
ln -sf "$INSTALL_DIR/.venv/bin/dfscli" "$BIN_DIR/dfscli"
ln -sf "$INSTALL_DIR/.venv/bin/dfssvc" "$BIN_DIR/dfssvc"

_append_path_if_missing() {
  local rc_file="$1"
  local line="export PATH=\"$BIN_DIR:\$PATH\""
  if [ -f "$rc_file" ] && grep -Fq "$BIN_DIR" "$rc_file"; then
    return 0
  fi
  mkdir -p "$(dirname "$rc_file")"
  printf '\n# Added by dfs installer\n%s\n' "$line" >> "$rc_file"
  echo "[dfs] Added $BIN_DIR to $rc_file"
}

if [ "$WAS_IN_PATH" -eq 0 ] && [ "${DFS_NO_MODIFY_PATH:-0}" != "1" ]; then
  SHELL_NAME="$(basename "${SHELL:-}")"
  case "$SHELL_NAME" in
    zsh)
      _append_path_if_missing "$HOME/.zshrc"
      ;;
    bash)
      if [ -f "$HOME/.bashrc" ]; then
        _append_path_if_missing "$HOME/.bashrc"
      else
        _append_path_if_missing "$HOME/.bash_profile"
      fi
      ;;
    *)
      _append_path_if_missing "$HOME/.profile"
      ;;
  esac
fi

echo ""
echo "Installed dfs, dfscli, and dfssvc to $BIN_DIR"
if [ "$WAS_IN_PATH" -eq 0 ]; then
  echo "To use dfs in this terminal right now, run:"
  echo "  export PATH=\"$BIN_DIR:\$PATH\""
  echo ""
fi
echo "Then run:"
echo "  dfs start"
echo "  dfs push ./my-folder"
