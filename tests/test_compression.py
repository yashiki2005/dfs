#!/usr/bin/env python3
"""フォルダ xattr による圧縮ポリシー継承の試験。"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dfs5.compression import effective_policy, set_xattr


@unittest.skipIf(sys.platform == "win32", "xattr test is POSIX-only")
class CompressionPolicyTests(unittest.TestCase):
    def test_nearest_directory_xattr_wins(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dfs5_policy_") as tmp:
            root = Path(tmp) / "tree"
            nested = root / "src" / "vendor"
            other = root / "docs"
            nested.mkdir(parents=True)
            other.mkdir()
            if not set_xattr(root, "zstd"):
                self.skipTest("filesystem does not support user xattrs")
            set_xattr(root / "src", "none")

            self.assertEqual(effective_policy(nested, root, "none"), "none")
            self.assertEqual(effective_policy(other, root, "none"), "zstd")
            self.assertEqual(effective_policy(root, root, "none"), "zstd")


if __name__ == "__main__":
    unittest.main(verbosity=2)
