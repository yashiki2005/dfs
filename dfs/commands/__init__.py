"""Subcommand handler modules split out from :mod:`dfs.cli_main`."""

from __future__ import annotations

import importlib
import sys
from typing import Any


class _CliMainProxy:
    """Lazy proxy to :mod:`dfs.cli_main` (also when executed as ``__main__``)."""

    @staticmethod
    def _mod() -> Any:
        mod = sys.modules.get("dfs.cli_main")
        if mod is not None:
            return mod
        main_mod = sys.modules.get("__main__")
        if main_mod is not None and str(getattr(main_mod, "__file__", "")).endswith(
            "cli_main.py"
        ):
            return main_mod
        return importlib.import_module("dfs.cli_main")

    def __getattr__(self, name: str) -> Any:
        return getattr(self._mod(), name)


_cm = _CliMainProxy()
