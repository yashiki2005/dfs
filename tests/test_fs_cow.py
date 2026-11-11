#!/usr/bin/env python3
"""
dfs5/tests/test_fs_cow.py
`dfs5.fs` (CoW があれば CoW、無ければ OS 既定) の試験。

CoW の有無によらず、スナップショットが作業ツリーから独立していることを確認する。
ここが崩れるとロールバックの安全性が成立しない。
"""

import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dfs5.fs import CopyBackend, FileSystem, detect_backends, fs
from dfs5.fs import core as fs_core
from dfs5.fs.core import Capability


class TestBackendDetection(unittest.TestCase):
    def test_copy_backend_is_always_available(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dfs5_fs_") as tmp:
            infos = detect_backends(Path(tmp))
            names = [i.name for i in infos]
            self.assertIn("copy", names)

    def test_auto_never_raises_and_picks_something(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dfs5_fs_") as tmp:
            f = fs(tmp)
            self.assertIsNotNone(f.backend)
            self.assertIn("capability", f.info())

    def test_detection_is_stable_across_calls(self) -> None:
        """probe の残留ファイルで 2 回目以降が誤検出しないこと。"""
        with tempfile.TemporaryDirectory(prefix="dfs5_fs_") as tmp:
            root = Path(tmp)
            first = [i.name for i in detect_backends(root)]
            for _ in range(4):
                again = [i.name for i in detect_backends(root)]
                self.assertEqual(first, again)


class TestCopyBackendIsolation(unittest.TestCase):
    """実コピー backend で、スナップショットが独立していることを確かめる。"""

    def test_snapshot_survives_work_tree_overwrite(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dfs5_fs_") as tmp:
            root = Path(tmp)
            f = FileSystem(root, backend="copy")
            target = f.work_tree / "note.txt"
            target.write_text("original", encoding="utf-8")

            f.take_snapshot("v1")
            target.write_text("changed", encoding="utf-8")

            snap = f.read_snapshot("v1") / "note.txt"
            self.assertEqual(snap.read_text(encoding="utf-8"), "original")

    def test_snapshot_survives_file_deletion(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dfs5_fs_") as tmp:
            f = FileSystem(Path(tmp), backend="copy")
            (f.work_tree / "a.txt").write_text("a", encoding="utf-8")
            (f.work_tree / "b.txt").write_text("b", encoding="utf-8")
            f.take_snapshot("v1")
            (f.work_tree / "a.txt").unlink()
            snap_dir = f.read_snapshot("v1")
            self.assertTrue((snap_dir / "a.txt").exists())
            self.assertTrue((snap_dir / "b.txt").exists())

    def test_snapshot_excludes_clayfs_and_noise(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dfs5_fs_") as tmp:
            root = Path(tmp)
            f = FileSystem(root, backend="copy")
            (f.work_tree / "keep.txt").write_text("k", encoding="utf-8")
            (f.work_tree / ".DS_Store").write_text("noise", encoding="utf-8")
            (f.work_tree / "._keep.txt").write_text("noise", encoding="utf-8")
            snap = f.take_snapshot("v1")
            self.assertTrue((snap.path / "keep.txt").exists())
            self.assertFalse((snap.path / ".DS_Store").exists())
            self.assertFalse((snap.path / "._keep.txt").exists())

    def test_symlink_is_recreated_not_followed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dfs5_fs_") as tmp:
            f = FileSystem(Path(tmp), backend="copy")
            (f.work_tree / "real.txt").write_text("real", encoding="utf-8")
            try:
                os.symlink("real.txt", f.work_tree / "link.txt")
            except (OSError, NotImplementedError) as exc:
                # Windows の Developer Mode 無効時などは作れない
                self.skipTest(f"symlink を作れない: {exc}")
            f.take_snapshot("v1")
            link = f.read_snapshot("v1") / "link.txt"
            self.assertTrue(link.is_symlink())
            self.assertEqual(os.readlink(link), "real.txt")

    def test_take_snapshot_replaces_existing_snapshot(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dfs5_fs_") as tmp:
            f = FileSystem(Path(tmp), backend="copy")
            (f.work_tree / "a.txt").write_text("one", encoding="utf-8")
            f.take_snapshot("v1")
            (f.work_tree / "a.txt").write_text("two", encoding="utf-8")
            f.take_snapshot("v1")
            self.assertEqual(
                (f.read_snapshot("v1") / "a.txt").read_text(encoding="utf-8"), "two"
            )


class TestMaterialize(unittest.TestCase):
    def test_materialize_creates_independent_copy(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dfs5_fs_") as tmp:
            root = Path(tmp)
            f = FileSystem(root, backend="copy")
            (f.work_tree / "a.txt").write_text("a", encoding="utf-8")
            snap = f.take_snapshot("v1")
            out = root / "restored"
            f.materialize(snap.path, out)
            self.assertEqual((out / "a.txt").read_text(encoding="utf-8"), "a")
            out.joinpath("a.txt").write_text("changed", encoding="utf-8")
            self.assertEqual(
                (snap.path / "a.txt").read_text(encoding="utf-8"), "a"
            )


class TestBackendSelection(unittest.TestCase):
    def test_copy_forced_never_probes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dfs5_fs_") as tmp:
            f = FileSystem(Path(tmp), backend="copy")
            self.assertEqual(f.backend.name, "copy")
            self.assertFalse(f.is_cow)

    def test_unknown_backend_raises(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dfs5_fs_") as tmp:
            with self.assertRaises(ValueError):
                FileSystem(Path(tmp), backend="nonexistent")

    def test_fast_clone_without_support_raises(self) -> None:
        """Windows 以外で fast_clone を明示したら、黙って copy に落とさず断る。"""
        if sys.platform == "win32":
            self.skipTest("Windows では実機検出になるため対象外")
        with tempfile.TemporaryDirectory(prefix="dfs5_fs_") as tmp:
            with self.assertRaises(RuntimeError):
                FileSystem(Path(tmp), backend="fast_clone")


class TestSpecialFiles(unittest.TestCase):
    def test_fifo_is_skipped_not_copied(self) -> None:
        if not hasattr(os, "mkfifo"):
            self.skipTest("この OS に FIFO は無い")
        with tempfile.TemporaryDirectory(prefix="dfs5_fs_") as tmp:
            f = FileSystem(Path(tmp), backend="copy")
            (f.work_tree / "a.txt").write_text("a", encoding="utf-8")
            os.mkfifo(f.work_tree / "pipe")
            result = f.take_snapshot("v1")
            self.assertTrue((result.path / "a.txt").exists())
            self.assertFalse((result.path / "pipe").exists())
            self.assertEqual(result.files, 1)
            self.assertTrue(result.skipped)


class TestReadOnlyAttribute(unittest.TestCase):
    """read-only 属性のファイルがあっても、スナップショットの作り直しが通る。

    Windows では read-only 属性のファイルを ``shutil.rmtree`` が消せない。
    ``shutil.copy2`` は属性を引き継ぐので、一度入ると詰む。
    """

    def test_snapshot_replacement_survives_read_only_file(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dfs5_fs_") as tmp:
            f = FileSystem(Path(tmp), backend="copy")
            target = f.work_tree / "ro.txt"
            target.write_text("one", encoding="utf-8")
            os.chmod(target, stat.S_IREAD)
            try:
                f.take_snapshot("v1")
                result = f.take_snapshot("v1")  # 既存スナップショットの置き換え
            finally:
                os.chmod(target, stat.S_IRUSR | stat.S_IWUSR)
            self.assertEqual(
                (result.path / "ro.txt").read_text(encoding="utf-8"), "one"
            )

    def test_materialize_twice_survives_read_only_file(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dfs5_fs_") as tmp:
            root = Path(tmp)
            f = FileSystem(root, backend="copy")
            target = f.work_tree / "ro.txt"
            target.write_text("one", encoding="utf-8")
            os.chmod(target, stat.S_IREAD)
            try:
                snap = f.take_snapshot("v1")
                out = root / "restored"
                f.materialize(snap.path, out)
                f.materialize(snap.path, out)  # 2 回目は既存を消してから
            finally:
                os.chmod(target, stat.S_IRUSR | stat.S_IWUSR)
            self.assertEqual((out / "ro.txt").read_text(encoding="utf-8"), "one")


class TestWindowsReparsePoints(unittest.TestCase):
    """ジャンクション（ディレクトリの再解析ポイント）は辿らない。"""

    def test_junction_is_skipped_not_followed(self) -> None:
        if sys.platform != "win32":
            self.skipTest("Windows 専用")
        import subprocess

        with tempfile.TemporaryDirectory(prefix="dfs5_fs_") as tmp:
            root = Path(tmp)
            outside = root / "outside"
            outside.mkdir()
            (outside / "secret.txt").write_text("outside-of-tree", encoding="utf-8")
            f = FileSystem(root / "vol", backend="copy")
            link = f.work_tree / "linkdir"
            subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(link), str(outside)],
                capture_output=True, check=True,
            )
            result = f.take_snapshot("v1")
            # ツリー外の中身はスナップショットに入らない
            self.assertFalse((result.path / "linkdir" / "secret.txt").exists())
            self.assertEqual(result.files, 0)
            self.assertTrue(result.skipped)
            # clone は黙って落とさず断る
            with self.assertRaises(OSError):
                f.clone(f.work_tree, root / "copy_of_tree")


class TestWindowsBlockClone(unittest.TestCase):
    def test_fast_clone_is_only_advertised_when_probe_succeeds(self) -> None:
        """probe が成功したときだけ fast_clone を名乗る（NTFS では出ない）。"""
        with tempfile.TemporaryDirectory(prefix="dfs5_fs_") as tmp:
            root = Path(tmp)
            probe = fs_core._probe_block_clone(root)
            names = [i.name for i in detect_backends(root)]
            if probe is None:
                self.assertNotIn("fast_clone", names)
            else:
                self.assertIn("fast_clone", names)


class TestCapabilityDoesNotAffectCorrectness(unittest.TestCase):
    def test_cow_and_copy_backends_agree_on_content(self) -> None:
        """CoW が使える環境と copy の両方で、同じ内容のスナップショットになる。"""
        with tempfile.TemporaryDirectory(prefix="dfs5_fs_") as tmp:
            root = Path(tmp)
            for backend in ("copy", "auto"):
                f = FileSystem(root, backend=backend)
                (f.work_tree / "d").mkdir(exist_ok=True)
                (f.work_tree / "d" / "x.bin").write_bytes(b"\x00\x01\x02")
                result = f.take_snapshot(backend)
                self.assertTrue(result.path.is_dir())
                self.assertEqual(
                    (result.path / "d" / "x.bin").read_bytes(), b"\x00\x01\x02"
                )
                self.assertIn(
                    result.backend,
                    ("copy", "reflink", "fast_clone"),
                )


if __name__ == "__main__":
    unittest.main()
