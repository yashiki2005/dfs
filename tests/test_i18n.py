# -*- coding: utf-8 -*-
import io
import os
import unittest
from unittest.mock import patch

from dfs import cli_main, svc
from dfs.i18n import (
    _,
    detect_system_language,
    normalize_lang_code,
    set_current_language,
    translate_parser,
)


class TestI18n(unittest.TestCase):
    def setUp(self) -> None:
        set_current_language(None)

    def tearDown(self) -> None:
        set_current_language(None)

    def test_normalize_lang_code(self) -> None:
        self.assertEqual(normalize_lang_code("ja_JP.UTF-8"), "ja")
        self.assertEqual(normalize_lang_code("en-US"), "en")
        self.assertEqual(normalize_lang_code("zh_CN"), "zh-Hans")
        self.assertEqual(normalize_lang_code("zh-Hant-HK"), "zh-Hant")
        self.assertEqual(normalize_lang_code("zh_TW"), "zh-Hant")
        self.assertEqual(normalize_lang_code("fr_FR.ISO8859-1"), "fr")
        self.assertEqual(normalize_lang_code("de_DE"), "de")
        self.assertEqual(normalize_lang_code("es_ES"), "es")
        self.assertEqual(normalize_lang_code("ko_KR"), "ko")
        self.assertEqual(normalize_lang_code("pt_BR"), "pt-BR")
        self.assertEqual(normalize_lang_code("ru_RU"), "ru")
        self.assertEqual(normalize_lang_code("it_IT"), "it")
        self.assertIsNone(normalize_lang_code("unsupported-lang"))

    def test_detect_system_language_env_priority(self) -> None:
        with patch.dict(os.environ, {"DFS_LANG": "de_DE"}, clear=False):
            self.assertEqual(detect_system_language(), "de")

        with patch.dict(os.environ, {"DFS_LANG": "", "LC_ALL": "fr_FR.UTF-8"}, clear=False):
            self.assertEqual(detect_system_language(), "fr")

        with patch.dict(os.environ, {"DFS_LANG": "", "LC_ALL": "", "LANG": "zh_CN.UTF-8"}, clear=False):
            self.assertEqual(detect_system_language(), "zh-Hans")

    def test_macos_defaults_read_detection(self) -> None:
        with patch.dict(os.environ, {"DFS_LANG": "", "LC_ALL": "", "LC_MESSAGES": "", "LANG": ""}, clear=False):
            with patch("dfs.i18n.get_macos_preferred_languages", return_value=["ko-KR", "en-US"]):
                self.assertEqual(detect_system_language(), "ko")

    def test_translation_switch(self) -> None:
        set_current_language("ja")
        self.assertEqual(_("リモートを登録する（= config create）"), "リモートを登録する（= config create）")

        set_current_language("en")
        self.assertEqual(_("リモートを登録する（= config create）"), "Register remote (= config create)")

        set_current_language("zh-Hans")
        self.assertEqual(_("リモートを登録する（= config create）"), "注册远程（等同于 config create）")

        set_current_language("fr")
        self.assertEqual(_("リモートを登録する（= config create）"), "Enregistrer un remote (= config create)")

    def test_cli_main_help_localized(self) -> None:
        parser = cli_main.build_parser()
        with patch.dict(os.environ, {"DFS_LANG": "en"}, clear=False):
            set_current_language("en")
            translated = translate_parser(parser, _)
            buf = io.StringIO()
            with patch("sys.stdout", buf):
                translated.print_help(buf)
            out = buf.getvalue()
            self.assertIn("rclone-like CLI for dfs", out)
            self.assertIn("Register remote (= config create)", out)

    def test_dfssvc_help_localized(self) -> None:
        parser = svc.build_parser()
        with patch.dict(os.environ, {"DFS_LANG": "de"}, clear=False):
            set_current_language("de")
            translated = translate_parser(parser, _)
            buf = io.StringIO()
            with patch("sys.stdout", buf):
                translated.print_help(buf)
            out = buf.getvalue()
            self.assertIn("Lokalen dfs-Server (L2 + L3) starten", out)

    def test_friendly_error_localized(self) -> None:
        err = cli_main.ConflictError("sub-1")
        err_buf = io.StringIO()
        with patch.dict(os.environ, {"DFS_LANG": "en"}, clear=False):
            set_current_language("en")
            with patch("sys.stderr", err_buf):
                rc = cli_main._friendly_error(err)
            self.assertEqual(rc, 7)
            self.assertIn("Single-writer conflict", err_buf.getvalue())
            self.assertIn("Another client wrote first", err_buf.getvalue())


if __name__ == "__main__":
    unittest.main()
