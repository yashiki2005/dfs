#!/usr/bin/env python3
"""FUSE 操作アダプタの回帰試験（実際のカーネルマウントは行わない）。"""

from __future__ import annotations

import errno
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dfs import cli_main
from dfs.cli_main import UsageError
from dfs.fuse_mount import LocalTreeFuse


class LocalTreeFuseTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="dfs_fuse_")
        self.root = Path(self._tmp.name) / "tree"
        self.root.mkdir()
        (self.root / "hello.txt").write_bytes(b"hello world")
        self.flushes = 0

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _flush(self) -> None:
        self.flushes += 1

    def test_read_write_and_flush(self) -> None:
        ops = LocalTreeFuse(self.root, self._flush)
        self.assertFalse(ops.use_ns, "st_mtime は秒単位で返している")
        self.assertTrue(ops.getattr("/")["st_mode"] & 0o040000)
        self.assertIn("hello.txt", ops.readdir("/"))
        self.assertEqual(ops.read("/hello.txt", 5, 0, 0), b"hello")

        ops.write("/hello.txt", b"HELLO", 0, 0)
        ops.release("/hello.txt", 0)
        self.assertEqual((self.root / "hello.txt").read_bytes(), b"HELLO world")
        self.assertEqual(self.flushes, 1)

        ops.create("/new.txt", 0o644, 0)
        ops.write("/new.txt", b"new", 6, 0)
        ops.release("/new.txt", 0)
        self.assertEqual((self.root / "new.txt").read_bytes(), b"\x00" * 6 + b"new")
        self.assertEqual(self.flushes, 2)

    def test_statfs_reports_backing_filesystem_capacity(self) -> None:
        ops = LocalTreeFuse(self.root, self._flush)
        attrs = ops.statfs("/")
        expected = os.statvfs(self.root)
        self.assertEqual(attrs["f_bsize"], expected.f_bsize)
        self.assertEqual(attrs["f_blocks"], expected.f_blocks)
        self.assertEqual(attrs["f_bavail"], expected.f_bavail)
        self.assertGreater(attrs["f_blocks"], 0)

    def test_directory_operations(self) -> None:
        ops = LocalTreeFuse(self.root, self._flush)
        ops.mkdir("/d", 0o755)
        ops.rename("/hello.txt", "/d/renamed.txt")
        ops.unlink("/d/renamed.txt")
        ops.rmdir("/d")
        self.assertFalse((self.root / "d").exists())
        self.assertEqual(self.flushes, 0)
        ops.release("/", None)
        self.assertEqual(self.flushes, 1)

    def test_read_only_rejects_writes(self) -> None:
        ops = LocalTreeFuse(self.root, self._flush, read_only=True)
        with self.assertRaises(OSError) as ctx:
            ops.write("/hello.txt", b"x", 0, 0)
        self.assertEqual(ctx.exception.errno, errno.EROFS)

    def test_truncate_creates_file_with_requested_length(self) -> None:
        ops = LocalTreeFuse(self.root, self._flush)
        ops.truncate("/sized.bin", 16)
        self.assertEqual((self.root / "sized.bin").stat().st_size, 16)


class FuseRequirementTests(unittest.TestCase):
    def test_macos_without_fuse_reports_clear_error(self) -> None:
        with (
            patch.object(cli_main.sys, "platform", "darwin"),
            patch("pathlib.Path.is_file", return_value=False),
            patch.dict(os.environ, {"FUSE_LIBRARY_PATH": ""}, clear=False),
        ):
            with self.assertRaisesRegex(UsageError, "マウント機能には macFUSE または fuse-t が必要です"):
                cli_main._configure_fuse_library()

    def test_mount_candidates_order_darwin(self) -> None:
        from dfs.commands.transfer import _mount_candidates_darwin

        with (
            patch("dfs.commands.transfer._find_macfuse_library", return_value=Path("/lib/macfuse.dylib")),
            patch("dfs.commands.transfer._find_fuse_t_library", return_value=Path("/lib/fuse-t.dylib")),
        ):
            candidates = _mount_candidates_darwin("auto")
            self.assertEqual(len(candidates), 3)
            self.assertEqual(candidates[0], ("macFUSE (fskit)", Path("/lib/macfuse.dylib"), "fskit"))
            self.assertEqual(candidates[1], ("fuse-t", Path("/lib/fuse-t.dylib"), None))
            self.assertEqual(candidates[2], ("macFUSE", Path("/lib/macfuse.dylib"), None))

    def test_mount_candidates_explicit_backend(self) -> None:
        from dfs.commands.transfer import _mount_candidates_darwin

        with (
            patch("dfs.commands.transfer._find_macfuse_library", return_value=Path("/lib/macfuse.dylib")),
            patch("dfs.commands.transfer._find_fuse_t_library", return_value=Path("/lib/fuse-t.dylib")),
        ):
            cand_fskit = _mount_candidates_darwin("fskit")
            self.assertEqual(cand_fskit, [("macFUSE (fskit)", Path("/lib/macfuse.dylib"), "fskit")])

            cand_fuset = _mount_candidates_darwin("fuse-t")
            self.assertEqual(cand_fuset, [("fuse-t", Path("/lib/fuse-t.dylib"), None)])

            cand_macfuse = _mount_candidates_darwin("macfuse")
            self.assertEqual(cand_macfuse, [("macFUSE", Path("/lib/macfuse.dylib"), None)])


if __name__ == "__main__":
    unittest.main(verbosity=2)
