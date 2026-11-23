# Installation Guide (`INSTALL.md`)

> **English** | [日本語](INSTALL.ja.md)

This document covers how to install `dfs` (`dfs` / `dfscli` / `dfssvc`), common build pitfalls (such as missing `gmp.h` and `fastecdsa` conflicts), and **why standalone binaries are distributed alongside Python packages**.

---

## Why Distribute Standalone Binaries?

Even though `dfs` is written in Python, GitHub Releases ship standalone native binaries (`dfs`, `dfscli`, `dfssvc`) for three main reasons:

1. **Bundle `py-libp2p` without requiring `gmp.h` or a C compiler on user machines**
   - The optional P2P multi-seed transport (`libp2p` extra) depends on `py-libp2p`, which pulls in `fastecdsa`. On environments without a matching prebuilt wheel, building `fastecdsa` from source requires **`gmp.h` (GNU MP headers)** and a C toolchain—failing with `fatal error: gmp.h: No such file or directory` if `libgmp-dev` is missing.
   - In addition, `py-libp2p 0.8.1` pins `fastecdsa==2.3.2`, which conflicts with `fastecdsa==4.0.0` needed on Python 3.12+ / macOS.
   - The GitHub Release binaries are built with **Miniconda (`conda-forge` `gmp` + OpenSSL) + PyInstaller**, bundling `libgmp`, `libcrypto`, `libssl`, and `py-libp2p` into a self-contained executable.
2. **Zero-prerequisite setup on fresh machines**
   - Works on minimal servers, containers, or Windows machines without installing Python 3.11+, `uv`, or `git`.
3. **Minimal external CLI requirements**
   - `dfs` prefers `ssh-keygen` (OpenSSH) and `openssl` when present, and **automatically falls back to in-process `cryptography`** when they are absent—so the binary works even in stripped-down containers.

---

## Choosing an Installation Method

| Method | Best For | Includes `libp2p` (P2P) | Needs `gmp.h`? |
|---|---|---|---|
| **1. Release Binaries** | Quick start / no Python or C compiler | Bundled | **No** |
| **2. One-Line Installer (`install.sh` / `install.ps1`)** | Automated setup / RunPod & cloud GPUs | Auto-attempted (falls back to core) | Depends on wheel availability |
| **3. Homebrew (`Formula/dfs.rb`)** | macOS / Linuxbrew users | Same as release binaries | **No** |
| **4. Source / Wheel (`uv` / `pip`)** | Development / existing Python environments | Optional via `--extra libp2p` | Only if building `fastecdsa` from source |

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

# Core dependencies only (no gmp.h needed)
uv sync

# Include P2P (libp2p) transport
uv sync --extra libp2p
```

When installing the universal wheel (`dfs-<version>-py3-none-any.whl`), pass `fastecdsa-overrides.txt`:

```bash
uv pip install --overrides fastecdsa-overrides.txt dfs-<version>-py3-none-any.whl
```

### ⚠️ Caveat 1: Build Failure Due to Missing `gmp.h`

If `--extra libp2p` compiles `fastecdsa` from source on your platform, it will fail unless GMP headers and a C compiler are installed:

```text
fatal error: gmp.h: No such file or directory
```

**How to fix**:
- **Ubuntu / Debian**: `sudo apt-get update && sudo apt-get install -y libgmp-dev build-essential python3-dev`
- **Fedora / RHEL**: `sudo dnf install -y gmp-devel gcc python3-devel`
- **macOS (Homebrew)**: `brew install gmp` (and if needed, export `CPATH="$(brew --prefix gmp)/include"` and `LIBRARY_PATH="$(brew --prefix gmp)/lib"`)
- **conda / Miniconda**: `conda install -c conda-forge gmp`
- **If you don't need P2P**: omit `--extra libp2p` and run `uv sync` (core TLS/HTTP/relay transport works without `gmp.h`).

### ⚠️ Caveat 2: `pip` Conflict on `fastecdsa`

Because `py-libp2p 0.8.1` still declares `fastecdsa==2.3.2` while `dfs` requires `fastecdsa==4.0.0`, plain `pip install 'dfs[libp2p]'` may fail dependency resolution. Use **`uv` with `fastecdsa-overrides.txt`** or the **release binaries** when you want `libp2p` support (core `pip install -e .` works normally).

### ⚠️ Caveat 3: Optional External Tools

| Feature | Tool / Package | Notes |
|---|---|---|
| Keygen, signing, TLS certs | `ssh-keygen`, `openssl` | Optional: preferred when installed; automatically falls back to in-process `cryptography` |
| FUSE mount (`dfs mount`) | `dfs[fuse]` (`fusepy`) + `macFUSE` / `FUSE-T` (macOS) or `libfuse` (Linux) | Only needed for `mount` |
| PAR2 parity (`dfscli archive --recovery`) | `par2cmdline` (`par2`) | Only needed for parity generation/repair |
| Terminal QR (`dfscli web`) | `libqrencode` (`qrencode`) | Only needed for terminal QR display |
