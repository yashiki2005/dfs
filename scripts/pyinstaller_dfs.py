#!/usr/bin/env python3
"""PyInstaller entrypoint for dfs (unified CLI)."""

from dfs.simple_cli import main

if __name__ == "__main__":
    raise SystemExit(main())
