#!/usr/bin/env python3
"""PyInstaller entrypoint for dfscli."""

from dfs.cli_main import main

if __name__ == "__main__":
    raise SystemExit(main())
