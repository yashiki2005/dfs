# Installation Guide (`INSTALL.md`)

> **English** | [日本語](INSTALL.ja.md)

This document covers how to install `dfs` (`dfs` / `dfscli` / `dfssvc`), optional dependencies, and **why standalone binaries are distributed alongside Python packages**.

---

## Why Distribute Standalone Binaries?

Even though `dfs` is written in Python, GitHub Releases ship standalone native binaries (`dfs`, `dfscli`, `dfssvc`) for two main reasons:

1. **Zero-prerequisite setup on fresh machines**
   - Works on minimal servers, containers, or Windows machines without installing Python 3.11+, `uv`, or `git`.
2. **Minimal external CLI requirements**
   - `dfs` prefers `ssh-keygen` (OpenSSH) and `openssl` when present, and **automatically falls back to in-process `cryptography`** when they are absent—so the binary works even in stripped-down containers.

---

## Choosing an Installation Method

| Method | Best For | Includes `libp2p` (P2P) |
|---|---|---|
| **1. Release Binaries** | Quick start / no Python required | Bundled |
| **2. One-Line Installer (`install.sh` / `install.ps1`)** | Automated setup / RunPod & cloud GPUs | Auto-attempted (falls back to core) |
| **3. Homebrew (`Formula/dfs.rb`)** | macOS / Linuxbrew users | Same as release binaries |
| **4. Source / Wheel (`uv` / `pip`)** | Development / existing Python environments | Optional via `--extra libp2p` |

---

## 1. Standalone Binaries (GitHub Releases)

Download the archive for your platform from [GitHub Releases](https://github.com/yashiki2005/dfs/releases):

- **macOS (Apple Silicon / arm64)**: `dfs-v<version>-darwin-arm64.tar.gz`
- **Linux (x86_64)**: `dfs-v<version>-linux-x86_64.tar.gz`
- **Linux (arm64)**: `dfs-v<version>-linux-arm64.tar.gz`
- **Windows (x86_64)**: `dfs-v<version>-windows-x86_64.zip`

```bash
# Example: extract and install on Linux x86_64
tar -xzf dfs-v0.1.0-linux-x86_64.tar.gz
sudo install -m 755 dfs dfscli dfssvc /usr/local/bin/
```

Verify checksums with the attached `SHA256SUMS.txt`:

```bash
sha256sum -c --ignore-missing SHA256SUMS.txt
```

> **macOS note**: If Gatekeeper blocks execution of a browser-downloaded binary, run `xattr -d com.apple.quarantine dfs dfscli dfssvc` in the extracted directory.

---

## 2. One-Line Installers

### macOS / Linux
```bash
curl -sSL https://raw.githubusercontent.com/yashiki2005/dfs/main/scripts/install.sh | bash
```

- Places binaries in a writable directory already on `PATH` (`/opt/homebrew/bin` or `/usr/local/bin`) if available, or falls back to `~/.local/bin` and idempotently appends it to `~/.zshrc` / `~/.bashrc` / `~/.profile` (set `DFS_NO_MODIFY_PATH=1` to skip shell rc edits).
- Attempts `uv sync --extra libp2p` first and falls back to core dependencies (`uv sync`) if the environment cannot build/install `libp2p`.

### Windows (PowerShell)
```powershell
irm https://raw.githubusercontent.com/yashiki2005/dfs/main/scripts/install.ps1 | iex
```

---

## 3. Installing via Homebrew (macOS / Linuxbrew)

Each GitHub Release includes a rendered `dfs.rb` formula (generated from [Formula/dfs.rb](Formula/dfs.rb) with release SHA256 checksums populated). No `homebrew-core` registration or review is required.

### Install directly from the release `dfs.rb` asset

```bash
curl -fsSLO https://github.com/yashiki2005/dfs/releases/latest/download/dfs.rb
brew install ./dfs.rb
```

- Supported targets: macOS Apple Silicon (`darwin-arm64`), Linux x86_64 (`linux-x86_64`), and Linux ARM64 (`linux-arm64`).
- Installs `dfs`, `dfscli`, and `dfssvc` into Homebrew's `bin` directory.

> **For maintainers (custom Tap)**: If you publish the rendered `dfs.rb` as `Formula/dfs.rb` in a public `homebrew-tap` repository (e.g. `yashiki2005/homebrew-tap`), users can install and upgrade via `brew install yashiki2005/tap/dfs` without any `homebrew-core` submission.

---

## 4. Installing from Source or Python Wheel

### Using `uv` (Recommended)

```bash
git clone https://github.com/yashiki2005/dfs.git
cd dfs

# Core dependencies only
uv sync

# Include P2P (libp2p) transport
uv sync --extra libp2p
```

When installing the universal wheel (`dfs-<version>-py3-none-any.whl`):

```bash
uv pip install dfs-<version>-py3-none-any.whl
# Or with pip:
python -m pip install dfs-<version>-py3-none-any.whl
```

> Note: `py-libp2p>=0.8.3` removed the `fastecdsa` dependency in favor of `cryptography`, so `gmp.h` and `fastecdsa-overrides.txt` are no longer required.

### ⚠️ Optional External Tools

| Feature | Tool / Package | Notes |
|---|---|---|
| Keygen, signing, TLS certs | `ssh-keygen`, `openssl` | Optional: preferred when installed; automatically falls back to in-process `cryptography` |
| FUSE mount (`dfs mount`) | `dfs[fuse]` (`fusepy`) + `macFUSE` / `FUSE-T` (macOS) or `libfuse` (Linux) | Only needed for `mount` |
| PAR2 parity (`dfscli archive --recovery`) | `par2cmdline` (`par2`) | Only needed for parity generation/repair |
| Terminal QR (`dfscli web`) | `libqrencode` (`qrencode`) | Only needed for terminal QR display |
