#!/usr/bin/env python3
"""PyInstaller entrypoint for dfssvc."""

from dfs.svc import main

if __name__ == "__main__":
    raise SystemExit(main())
