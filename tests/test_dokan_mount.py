#!/usr/bin/env python3
"""Tests for Windows Dokany2 mount backend (dfs/dokan_mount.py)."""

from __future__ import annotations

import ctypes
import tempfile
import unittest
from pathlib import Path

from dfs.dokan_mount import (
    BY_HANDLE_FILE_INFORMATION,
    DOKAN_OPERATIONS,
    DOKAN_OPTIONS,
    FILE_ATTRIBUTE_DIRECTORY,
    FILE_CREATE,
    FILE_DELETE_ON_CLOSE,
    FILE_DIRECTORY_FILE,
    FILE_OPEN,
    FILE_OVERWRITE,
    STATUS_MEDIA_WRITE_PROTECTED,
    STATUS_OBJECT_NAME_COLLISION,
    STATUS_OBJECT_NAME_NOT_FOUND,
    STATUS_OBJECT_PATH_INVALID,
    STATUS_SUCCESS,
    WIN32_FIND_DATAW,
    LocalTreeDokan,
    _to_signed_ntstatus,
    is_windows_drive_mountpoint,
)


class _DummyFileInfo(ctypes.Structure):
    _fields_ = [
        ("Context", ctypes.c_uint64),
        ("DokanContext", ctypes.c_uint64),
        ("DokanOptions", ctypes.c_void_p),
        ("ProcessingContext", ctypes.c_void_p),
        ("ProcessId", ctypes.c_uint32),
        ("IsDirectory", ctypes.c_ubyte),
        ("DeleteOnClose", ctypes.c_ubyte),
        ("PagingIo", ctypes.c_ubyte),
        ("SynchronousIo", ctypes.c_ubyte),
        ("Nocache", ctypes.c_ubyte),
        ("WriteToEndOfFile", ctypes.c_ubyte),
    ]


class DokanMountTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="dfs_dokan_test_")
        self.root = Path(self._tmp.name) / "tree"
        self.root.mkdir()
        (self.root / "hello.txt").write_bytes(b"hello dokan\n")
        (self.root / ".clayfs").mkdir()
        (self.root / ".clayfs" / "secret").write_text("hidden\n", encoding="utf-8")
        self.flushes = 0

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _flush(self) -> None:
        self.flushes += 1

    def test_drive_mountpoint_detection(self) -> None:
        self.assertTrue(is_windows_drive_mountpoint("Z:"))
        self.assertTrue(is_windows_drive_mountpoint("z:\\"))
        self.assertTrue(is_windows_drive_mountpoint("M:/"))
        self.assertFalse(is_windows_drive_mountpoint("C:\\mnt\\dfs"))
        self.assertFalse(is_windows_drive_mountpoint("/tmp/mnt"))

    def test_structs_and_operations_table_build(self) -> None:
        self.assertGreater(ctypes.sizeof(DOKAN_OPTIONS), 16384)
        dokan = LocalTreeDokan(self.root, self._flush, sync_delay=0.0)
        ops = dokan.build_operations()
        self.assertIsInstance(ops, DOKAN_OPERATIONS)

    def test_create_write_read_cleanup_and_flush(self) -> None:
        dokan = LocalTreeDokan(self.root, self._flush, sync_delay=0.0)
        fi = _DummyFileInfo()
        fi_p = ctypes.pointer(fi)
        rc = dokan.zw_create_file(
            "\\new.txt", None, 0, 0, 0, FILE_CREATE, 0, fi_p
        )
        self.assertEqual(rc, _to_signed_ntstatus(STATUS_SUCCESS))
        self.assertNotEqual(fi.Context, 0)

        payload = b"written via dokan"
        buf = ctypes.create_string_buffer(payload)
        written = (ctypes.c_uint32 * 1)()
        rc_w = dokan.write_file(
            "\\new.txt", ctypes.addressof(buf), len(payload), written, 0, fi_p
        )
        self.assertEqual(rc_w, _to_signed_ntstatus(STATUS_SUCCESS))
        self.assertEqual(written[0], len(payload))

        out_buf = ctypes.create_string_buffer(64)
        read_len = (ctypes.c_uint32 * 1)()
        rc_r = dokan.read_file(
            "\\new.txt", ctypes.addressof(out_buf), 64, read_len, 0, fi_p
        )
        self.assertEqual(rc_r, _to_signed_ntstatus(STATUS_SUCCESS))
        self.assertEqual(out_buf.raw[: read_len[0]], payload)

        dokan.cleanup("\\new.txt", fi_p)
        dokan.close_file("\\new.txt", fi_p)
        self.assertEqual(self.flushes, 1)
        self.assertEqual((self.root / "new.txt").read_bytes(), payload)

    def test_get_info_find_files_and_clayfs_hidden(self) -> None:
        dokan = LocalTreeDokan(self.root, self._flush, sync_delay=0.0)
        fi = _DummyFileInfo()
        fi_p = ctypes.pointer(fi)
        info = BY_HANDLE_FILE_INFORMATION()
        self.assertEqual(
            dokan.get_file_information("\\hello.txt", ctypes.pointer(info), fi_p),
            _to_signed_ntstatus(STATUS_SUCCESS),
        )
        self.assertEqual(info.nFileSizeLow, len(b"hello dokan\n"))
        self.assertEqual(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY, 0)

        names = []

        def _fill(fd_ptr: ctypes.POINTER(WIN32_FIND_DATAW), _fi_ptr: object) -> int:
            names.append(fd_ptr.contents.cFileName)
            return 0

        self.assertEqual(
            dokan.find_files("\\", _fill, fi_p),
            _to_signed_ntstatus(STATUS_SUCCESS),
        )
        self.assertEqual(names, ["hello.txt"])

        self.assertEqual(
            dokan.zw_create_file("\\.clayfs\\secret", None, 0, 0, 0, FILE_OPEN, 0, fi_p),
            _to_signed_ntstatus(STATUS_OBJECT_PATH_INVALID),
        )
        self.assertEqual(
            dokan.zw_create_file("\\..\\escape.txt", None, 0, 0, 0, FILE_CREATE, 0, fi_p),
            _to_signed_ntstatus(STATUS_OBJECT_PATH_INVALID),
        )

    def test_mkdir_move_and_delete_on_close(self) -> None:
        dokan = LocalTreeDokan(self.root, self._flush, sync_delay=0.0)
        fi = _DummyFileInfo()
        fi_p = ctypes.pointer(fi)
        self.assertEqual(
            dokan.zw_create_file("\\sub", None, 0, 0, 0, FILE_CREATE, FILE_DIRECTORY_FILE, fi_p),
            _to_signed_ntstatus(STATUS_SUCCESS),
        )
        self.assertEqual(fi.IsDirectory, 1)
        self.assertEqual(
            dokan.move_file("\\hello.txt", "\\sub\\moved.txt", False, fi_p),
            _to_signed_ntstatus(STATUS_SUCCESS),
        )
        self.assertTrue((self.root / "sub" / "moved.txt").is_file())

        fi_del = _DummyFileInfo()
        rc = dokan.zw_create_file(
            "\\sub\\moved.txt",
            None,
            0,
            0,
            0,
            FILE_OPEN,
            FILE_DELETE_ON_CLOSE,
            ctypes.pointer(fi_del),
        )
        self.assertEqual(rc, _to_signed_ntstatus(STATUS_SUCCESS))
        dokan.cleanup("\\sub\\moved.txt", ctypes.pointer(fi_del))
        self.assertFalse((self.root / "sub" / "moved.txt").exists())

    def test_read_only_rejects_mutations(self) -> None:
        dokan = LocalTreeDokan(self.root, self._flush, read_only=True, sync_delay=0.0)
        fi = _DummyFileInfo()
        fi_p = ctypes.pointer(fi)
        self.assertEqual(
            dokan.zw_create_file("\\ro_new.txt", None, 0, 0, 0, FILE_CREATE, 0, fi_p),
            _to_signed_ntstatus(STATUS_MEDIA_WRITE_PROTECTED),
        )
        self.assertEqual(
            dokan.zw_create_file("\\hello.txt", None, 0, 0, 0, FILE_OVERWRITE, 0, fi_p),
            _to_signed_ntstatus(STATUS_MEDIA_WRITE_PROTECTED),
        )
        self.assertEqual(
            dokan.delete_file("\\hello.txt", fi_p),
            _to_signed_ntstatus(STATUS_MEDIA_WRITE_PROTECTED),
        )
        self.assertEqual(
            dokan.zw_create_file("\\missing.txt", None, 0, 0, 0, FILE_OPEN, 0, fi_p),
            _to_signed_ntstatus(STATUS_OBJECT_NAME_NOT_FOUND),
        )
        self.assertEqual(
            dokan.zw_create_file("\\hello.txt", None, 0, 0, 0, FILE_CREATE, 0, fi_p),
            _to_signed_ntstatus(STATUS_OBJECT_NAME_COLLISION),
        )


if __name__ == "__main__":
    unittest.main()
