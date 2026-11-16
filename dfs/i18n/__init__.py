# -*- coding: utf-8 -*-
"""
dfs.i18n: macOS / POSIX 多言語対応 (Localization & Internationalization) モジュール。

macOS のシステム言語設定 (`AppleLanguages`) やロケール環境変数 (`DFS_LANG`, `LC_ALL`, `LC_MESSAGES`, `LANG`)
から最適な表示言語を自動判定し、CLI のヘルプメッセージ、エラーメッセージ、各種通知を適切な言語で出力します。
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional

SUPPORTED_LANGUAGES = (
    "en",     # English (Default)
    "ja",     # 日本語 (Japanese)
    "zh-Hans",# 简体中文 (Simplified Chinese)
    "zh-Hant",# 繁體中文 (Traditional Chinese)
    "fr",     # Français (French)
    "de",     # Deutsch (German)
    "es",     # Español (Spanish)
    "ko",     # 한국어 (Korean)
    "it",     # Italiano (Italian)
    "pt-BR",  # Português do Brasil (Brazilian Portuguese)
    "ru",     # Русский (Russian)
)

_CURRENT_LANG: Optional[str] = None
TRANSLATIONS: Dict[str, Dict[str, str]] = {}


def normalize_lang_code(code: str) -> Optional[str]:
    """言語・ロケール文字列を正規化し、サポート対象の言語コードにマッピングする。"""
    if not code:
        return None
    raw = code.strip().split(".")[0].split("@")[0].replace("_", "-")
    parts = raw.split("-")
    base = parts[0].lower()

    if base == "ja":
        return "ja"
    if base == "en":
        return "en"
    if base == "ko":
        return "ko"
    if base == "fr":
        return "fr"
    if base == "de":
        return "de"
    if base == "es":
        return "es"
    if base == "it":
        return "it"
    if base == "ru":
        return "ru"
    if base in ("pt", "pt-br"):
        return "pt-BR"
    if base == "zh":
        joined = "-".join(parts).lower()
        if any(h in joined for h in ("hant", "tw", "hk", "mo")):
            return "zh-Hant"
        return "zh-Hans"
    return None


def get_macos_preferred_languages() -> List[str]:
    """macOS の defaults read -g AppleLanguages からユーザーの優先言語リストを取得する。"""
    if sys.platform != "darwin":
        return []
    try:
        res = subprocess.run(
            ["defaults", "read", "-g", "AppleLanguages"],
            capture_output=True,
            text=True,
            timeout=1.0,
            check=False,
        )
        if res.returncode == 0 and res.stdout:
            matches = re.findall(r'"([^"]+)"', res.stdout)
            if matches:
                return matches
    except Exception:
        pass
    return []


def detect_system_language() -> str:
    """OS の言語設定およびロケール環境変数から最も適切な言語コードを特定する。"""
    # 1. 明示的な上書き環境変数 (テストや手動指定用)
    forced = os.environ.get("DFS_LANG")
    if forced:
        matched = normalize_lang_code(forced)
        if matched:
            return matched

    # 2. ロケール環境変数 (LC_ALL, LC_MESSAGES, LANG)
    for env_var in ("LC_ALL", "LC_MESSAGES", "LANG"):
        val = os.environ.get(env_var)
        if val:
            matched = normalize_lang_code(val)
            if matched:
                return matched

    # 3. macOS のシステム優先言語 (AppleLanguages)
    for mac_lang in get_macos_preferred_languages():
        matched = normalize_lang_code(mac_lang)
        if matched:
            return matched

    # デフォルトは英語
    return "en"


def _load_catalogs() -> None:
    global TRANSLATIONS
    if TRANSLATIONS:
        return
    cat_path = Path(__file__).parent / "catalogs.json"
    if cat_path.is_file():
        try:
            TRANSLATIONS = json.loads(cat_path.read_text(encoding="utf-8"))
        except Exception:
            TRANSLATIONS = {}


def get_current_language() -> str:
    """現在アクティブな言語コードを取得する。"""
    global _CURRENT_LANG
    if _CURRENT_LANG is None:
        _CURRENT_LANG = detect_system_language()
    return _CURRENT_LANG


def set_current_language(lang: Optional[str]) -> None:
    """表示言語を明示的に切り替える（None で自動検出に戻す）。"""
    global _CURRENT_LANG
    if lang is None:
        _CURRENT_LANG = detect_system_language()
    else:
        normalized = normalize_lang_code(lang)
        _CURRENT_LANG = normalized if normalized else "en"


def _(text: str) -> str:
    """メッセージを現在の言語に翻訳する。"""
    lang = get_current_language()
    if lang == "ja":
        return text
    _load_catalogs()
    table = TRANSLATIONS.get(lang)
    if table and text in table:
        return table[text]
    # 英語フォールバック
    en_table = TRANSLATIONS.get("en")
    if en_table and text in en_table:
        return en_table[text]
    return text


def configure_stdio() -> None:
    """CLI出力の文字コードを保ち、WindowsのCP1252等でもヘルプ表示を落とさない。"""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if not callable(reconfigure):
            continue
        try:
            reconfigure(errors="backslashreplace")
        except (AttributeError, OSError, ValueError):
            # テストの文字列ストリームや特殊なコンソールでは元の設定を使う。
            pass


def translate_parser(parser, tr_func=None):
    """argparse.ArgumentParser インスタンス内の description / help 文字列を翻訳する。"""
    import argparse
    if tr_func is None:
        tr_func = _
    if parser.description:
        parser.description = tr_func(parser.description)
    for action in parser._actions:
        if action.help:
            action.help = tr_func(action.help)
        if isinstance(action, argparse._SubParsersAction):
            for choice_name, subparser in action.choices.items():
                translate_parser(subparser, tr_func)
            for choice_action in getattr(action, "_choices_actions", []):
                if choice_action.help:
                    choice_action.help = tr_func(choice_action.help)
    return parser
