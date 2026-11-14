#!/usr/bin/env python3
"""
dfs/web.py
スマホからブラウザで使える軽量ファイル共有 & Web CLI サーバ（`dfscli web`）。

LAN / Tailscale での即時共有（A）と、Caddy 等のリバースプロキシ配下での
限定共有（B: --base-path / --read-only / --ttl / HttpOnly セッションクッキー）
の両方に対応する。外部 JS/CSS ライブラリや Node ビルドは一切不要。
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import http.cookies
import json
import mimetypes
import os
import posixpath
import secrets
import shlex
import shutil
import socket
import threading
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, quote, unquote, urlsplit

from .path_safety import UnsafePathError, safe_target

DEFAULT_MAX_UPLOAD_BYTES = 256 * 1024 * 1024
MAX_JSON_BODY_BYTES = 256 * 1024
MAX_TEXT_PREVIEW_BYTES = 512 * 1024

_INLINE_IMAGE_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".ico", ".avif",
}
_INLINE_TEXT_EXTS = {
    ".txt", ".md", ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg",
    ".py", ".js", ".ts", ".css", ".csv", ".log", ".sh", ".xml", ".rs", ".go",
}


class WebAppError(Exception):
    """Web CLI 内部エラー（HTTP ステータス付き）。"""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


@dataclass
class WebConfig:
    remote_name: str
    token: str
    read_only: bool = False
    ttl_seconds: int = 0
    base_path: str = ""
    secure_cookie: bool = False
    max_upload_bytes: int = DEFAULT_MAX_UPLOAD_BYTES
    started_at: float = 0.0

    @property
    def expires_at(self) -> float:
        if self.ttl_seconds <= 0:
            return 0.0
        base = self.started_at or time.time()
        return base + float(self.ttl_seconds)

    def is_expired(self, now: Optional[float] = None) -> bool:
        exp = self.expires_at
        if exp <= 0:
            return False
        cur = time.time() if now is None else now
        return cur > exp


def normalize_rel_path(raw: str) -> str:
    """相対パスを正規化し、トラバーサルを拒否する。"""
    cleaned = (raw or "").replace("\\", "/").strip()
    if not cleaned or cleaned == "/":
        return ""
    parts: List[str] = []
    for part in cleaned.split("/"):
        if not part or part == ".":
            continue
        if part == ".." or "\x00" in part:
            raise WebAppError(400, f"Invalid path: {raw!r}")
        parts.append(part)
    return "/".join(parts)


def sign_session_cookie(token: str, expires_at: float) -> str:
    """HMAC-SHA256 署名付きのセッションクッキー値を生成する。"""
    nonce = secrets.token_urlsafe(12)
    exp = int(expires_at) if expires_at > 0 else int(time.time()) + 86400 * 7
    payload = f"{exp}.{nonce}"
    sig = hmac.new(token.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{payload}.{sig}"


def verify_session_cookie(token: str, raw_value: str, now: Optional[float] = None) -> bool:
    """署名付きセッションクッキーを検証する。"""
    if not token or not raw_value:
        return False
    parts = raw_value.split(".")
    if len(parts) != 3:
        return False
    exp_str, nonce, sig = parts
    if not exp_str.isdigit() or not nonce or not sig:
        return False
    payload = f"{exp_str}.{nonce}"
    expected = hmac.new(token.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        return False
    cur = time.time() if now is None else now
    return int(exp_str) >= int(cur)


class DFSWebBackend:
    """DFSNode 操作をスレッドセーフに仲介するバックエンド。"""

    def __init__(
        self,
        work_tree: Path,
        remote_name: str,
        read_only: bool,
        sync_fn: Callable[[bool], int],
        push_fn: Callable[[], int],
        status_fn: Optional[Callable[[], Dict[str, Any]]] = None,
    ) -> None:
        self.work_tree = work_tree.resolve()
        self.remote_name = remote_name
        self.read_only = read_only
        self._sync_fn = sync_fn
        self._push_fn = push_fn
        self._status_fn = status_fn
        self._lock = threading.RLock()
        self._current_version = 0

    def _resolve_target(self, rel_path: str) -> Path:
        norm = normalize_rel_path(rel_path)
        if not norm:
            return self.work_tree
        try:
            return safe_target(self.work_tree, norm)
        except UnsafePathError as e:
            raise WebAppError(400, f"Unsafe path: {e}") from e

    def sync(self, force: bool = False) -> int:
        with self._lock:
            self._current_version = int(self._sync_fn(force))
            return self._current_version

    def _ensure_writable(self) -> None:
        if self.read_only:
            raise WebAppError(403, "Read-only mode: write operations are disabled")

    def list_dir(self, rel_path: str) -> Dict[str, Any]:
        with self._lock:
            norm = normalize_rel_path(rel_path)
            target = self._resolve_target(norm)
            if not target.exists():
                raise WebAppError(404, f"Directory not found: /{norm}")
            if not target.is_dir():
                raise WebAppError(400, f"Not a directory: /{norm}")
            entries: List[Dict[str, Any]] = []
            for item in sorted(target.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower())):
                if item.name.startswith("._") or item.name == ".dfs":
                    continue
                if item.is_symlink():
                    continue
                st = item.stat()
                is_dir = item.is_dir()
                ext = item.suffix.lower()
                preview_kind = "none"
                if not is_dir:
                    if ext in _INLINE_IMAGE_EXTS:
                        preview_kind = "image"
                    elif ext in _INLINE_TEXT_EXTS or st.st_size <= 64 * 1024 and _looks_text(item):
                        preview_kind = "text"
                item_rel = f"{norm}/{item.name}" if norm else item.name
                entries.append(
                    {
                        "name": item.name,
                        "path": item_rel,
                        "is_dir": is_dir,
                        "size": 0 if is_dir else int(st.st_size),
                        "mtime": int(st.st_mtime),
                        "preview": preview_kind,
                    }
                )
            return {
                "path": norm,
                "version": self._current_version,
                "read_only": self.read_only,
                "entries": entries,
            }

    def read_file_info(self, rel_path: str) -> Tuple[Path, str, int]:
        with self._lock:
            norm = normalize_rel_path(rel_path)
            if not norm:
                raise WebAppError(400, "File path is required")
            target = self._resolve_target(norm)
            if not target.is_file() or target.is_symlink():
                raise WebAppError(404, f"File not found: /{norm}")
            mime, _ = mimetypes.guess_type(target.name)
            return target, mime or "application/octet-stream", int(target.stat().st_size)

    def save_upload(self, rel_path: str, data: bytes) -> Dict[str, Any]:
        with self._lock:
            self._ensure_writable()
            norm = normalize_rel_path(rel_path)
            if not norm:
                raise WebAppError(400, "Target file path is required")
            target = self._resolve_target(norm)
            target.parent.mkdir(parents=True, exist_ok=True)
            tmp = target.with_name(f".upload_{secrets.token_hex(6)}_{target.name}")
            tmp.write_bytes(data)
            tmp.replace(target)
            self._current_version = int(self._push_fn())
            return {"path": norm, "size": len(data), "version": self._current_version}

    def make_dir(self, rel_path: str) -> Dict[str, Any]:
        with self._lock:
            self._ensure_writable()
            norm = normalize_rel_path(rel_path)
            if not norm:
                raise WebAppError(400, "Directory path is required")
            target = self._resolve_target(norm)
            if target.exists() and not target.is_dir():
                raise WebAppError(409, f"File already exists at /{norm}")
            target.mkdir(parents=True, exist_ok=True)
            self._current_version = int(self._push_fn())
            return {"path": norm, "version": self._current_version}

    def remove_path(self, rel_path: str) -> Dict[str, Any]:
        with self._lock:
            self._ensure_writable()
            norm = normalize_rel_path(rel_path)
            if not norm:
                raise WebAppError(400, "Cannot remove root directory")
            target = self._resolve_target(norm)
            if not target.exists():
                raise WebAppError(404, f"Not found: /{norm}")
            if target.is_dir():
                shutil.rmtree(target)
            else:
                target.unlink()
            self._current_version = int(self._push_fn())
            return {"removed": norm, "version": self._current_version}

    def move_path(self, src_rel: str, dst_rel: str) -> Dict[str, Any]:
        with self._lock:
            self._ensure_writable()
            src_norm = normalize_rel_path(src_rel)
            dst_norm = normalize_rel_path(dst_rel)
            if not src_norm or not dst_norm:
                raise WebAppError(400, "Both src and dst paths are required")
            src = self._resolve_target(src_norm)
            dst = self._resolve_target(dst_norm)
            if not src.exists():
                raise WebAppError(404, f"Source not found: /{src_norm}")
            if dst.exists():
                raise WebAppError(409, f"Destination already exists: /{dst_norm}")
            dst.parent.mkdir(parents=True, exist_ok=True)
            src.replace(dst)
            self._current_version = int(self._push_fn())
            return {"src": src_norm, "dst": dst_norm, "version": self._current_version}

    def run_cli(self, command: str, cwd_rel: str = "") -> Dict[str, Any]:
        """安全な許可リスト方式のミニ CLI コマンドを実行する。"""
        with self._lock:
            cwd = normalize_rel_path(cwd_rel)
            try:
                tokens = shlex.split(command or "")
            except ValueError as e:
                return {"ok": False, "cwd": cwd, "output": f"Parse error: {e}"}
            if not tokens:
                return {"ok": True, "cwd": cwd, "output": ""}
            cmd = tokens[0].lower()
            args = tokens[1:]

            def _join(arg: str) -> str:
                if arg.startswith("/"):
                    return normalize_rel_path(arg)
                joined = posixpath.normpath(posixpath.join(cwd or ".", arg))
                if joined == ".":
                    return ""
                if joined.startswith(".."):
                    raise WebAppError(400, f"Path escapes root: {arg!r}")
                return joined

            try:
                if cmd == "help":
                    return {
                        "ok": True,
                        "cwd": cwd,
                        "output": (
                            "Commands: ls [path], cd [path], pwd, cat <file>, "
                            "mkdir <dir>, mv <src> <dst>, rm <path>, sync, status"
                        ),
                    }
                if cmd == "pwd":
                    return {"ok": True, "cwd": cwd, "output": f"/{cwd}"}
                if cmd == "cd":
                    target = _join(args[0]) if args else ""
                    info = self.list_dir(target)
                    return {"ok": True, "cwd": info["path"], "output": f"/{info['path']}"}
                if cmd == "ls":
                    target = _join(args[0]) if args else cwd
                    info = self.list_dir(target)
                    lines = [
                        f"{'d' if e['is_dir'] else '-'} {e['size']:>10}  {e['name']}{'/' if e['is_dir'] else ''}"
                        for e in info["entries"]
                    ]
                    return {"ok": True, "cwd": cwd, "output": "\n".join(lines) or "(empty)"}
                if cmd == "cat":
                    if not args:
                        return {"ok": False, "cwd": cwd, "output": "Usage: cat <file>"}
                    fpath, _mime, size = self.read_file_info(_join(args[0]))
                    if size > MAX_TEXT_PREVIEW_BYTES:
                        return {
                            "ok": False,
                            "cwd": cwd,
                            "output": f"File too large for cat ({size} bytes; limit {MAX_TEXT_PREVIEW_BYTES})",
                        }
                    raw = fpath.read_bytes()
                    return {"ok": True, "cwd": cwd, "output": raw.decode("utf-8", errors="replace")}
                if cmd == "sync":
                    ver = self.sync(force="--force" in args)
                    return {"ok": True, "cwd": cwd, "output": f"Synced to v{ver}"}
                if cmd == "status":
                    extra = self._status_fn() if self._status_fn else {}
                    return {
                        "ok": True,
                        "cwd": cwd,
                        "output": json.dumps(
                            {
                                "remote": self.remote_name,
                                "version": self._current_version,
                                "read_only": self.read_only,
                                **extra,
                            },
                            ensure_ascii=False,
                            indent=2,
                        ),
                    }
                if cmd == "mkdir":
                    if not args:
                        return {"ok": False, "cwd": cwd, "output": "Usage: mkdir <dir>"}
                    res = self.make_dir(_join(args[0]))
                    return {"ok": True, "cwd": cwd, "output": f"Created /{res['path']} (v{res['version']})"}
                if cmd == "rm":
                    if not args:
                        return {"ok": False, "cwd": cwd, "output": "Usage: rm <path>"}
                    res = self.remove_path(_join(args[0]))
                    return {"ok": True, "cwd": cwd, "output": f"Removed /{res['removed']} (v{res['version']})"}
                if cmd == "mv":
                    if len(args) < 2:
                        return {"ok": False, "cwd": cwd, "output": "Usage: mv <src> <dst>"}
                    res = self.move_path(_join(args[0]), _join(args[1]))
                    return {
                        "ok": True,
                        "cwd": cwd,
                        "output": f"Moved /{res['src']} -> /{res['dst']} (v{res['version']})",
                    }
                return {"ok": False, "cwd": cwd, "output": f"Unknown command: {cmd} (type 'help')"}
            except WebAppError as e:
                return {"ok": False, "cwd": cwd, "output": f"Error: {e.message}"}


def _looks_text(path: Path) -> bool:
    try:
        sample = path.read_bytes()[:4096]
    except OSError:
        return False
    if b"\x00" in sample:
        return False
    try:
        sample.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


def _render_html(nonce: str, remote_name: str, authenticated: bool, read_only: bool) -> str:
    safe_name = (
        remote_name.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )
    ro_badge = "READ-ONLY" if read_only else "READ-WRITE"
    auth_flag = "true" if authenticated else "false"
    ro_flag = "true" if read_only else "false"
    return f"""<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
  <meta name="color-scheme" content="light dark">
  <title>dfs web — {safe_name}</title>
  <style nonce="{nonce}">
    :root {{
      --bg-light: #f6f7f9;
      --surface-light: #ffffff;
      --border-light: #d8dee6;
      --text-light: #161b22;
      --muted-light: #57606a;
      --accent-light: #0969da;
      --danger-light: #cf222e;

      --bg-dark: #0d1117;
      --surface-dark: #161b22;
      --border-dark: #30363d;
      --text-dark: #e6edf3;
      --muted-dark: #8b949e;
      --accent-dark: #58a6ff;
      --danger-dark: #f85149;

      --bg: var(--bg-light);
      --surface: var(--surface-light);
      --border: var(--border-light);
      --text: var(--text-light);
      --muted: var(--muted-light);
      --accent: var(--accent-light);
      --danger: var(--danger-light);

      color-scheme: light dark;
      accent-color: var(--accent);
    }}
    @media (prefers-color-scheme: dark) {{
      :root {{
        --bg: var(--bg-dark);
        --surface: var(--surface-dark);
        --border: var(--border-dark);
        --text: var(--text-dark);
        --muted: var(--muted-dark);
        --accent: var(--accent-dark);
        --danger: var(--danger-dark);
      }}
    }}
    @supports (color: light-dark(white, black)) {{
      :root {{
        --bg: light-dark(var(--bg-light), var(--bg-dark));
        --surface: light-dark(var(--surface-light), var(--surface-dark));
        --border: light-dark(var(--border-light), var(--border-dark));
        --text: light-dark(var(--text-light), var(--text-dark));
        --muted: light-dark(var(--muted-light), var(--muted-dark));
        --accent: light-dark(var(--accent-light), var(--accent-dark));
        --danger: light-dark(var(--danger-light), var(--danger-dark));
      }}
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.45;
      padding-bottom: env(safe-area-inset-bottom);
    }}
    header {{
      position: sticky;
      top: 0;
      z-index: 10;
      background: var(--surface);
      border-bottom: 1px solid var(--border);
      padding: 12px 14px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 8px;
    }}
    .brand {{
      display: flex;
      align-items: center;
      gap: 8px;
      font-weight: 700;
      font-size: 16px;
      min-width: 0;
    }}
    .badge {{
      font-size: 11px;
      padding: 2px 7px;
      border-radius: 999px;
      border: 1px solid var(--border);
      color: var(--muted);
      white-space: nowrap;
    }}
    main {{
      max-width: 820px;
      margin: 0 auto;
      padding: 12px;
      display: flex;
      flex-direction: column;
      gap: 12px;
    }}
    .tabs {{
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 6px;
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 4px;
    }}
    button {{
      font: inherit;
      cursor: pointer;
      border-radius: 10px;
      border: 1px solid var(--border);
      background: var(--surface);
      color: var(--text);
      min-height: 44px;
      padding: 8px 12px;
    }}
    button.primary {{
      background: var(--accent);
      color: #fff;
      border-color: var(--accent);
      font-weight: 600;
    }}
    button.danger {{
      color: var(--danger);
      border-color: var(--danger);
    }}
    .tab-btn {{
      border: none;
      background: transparent;
      font-weight: 600;
    }}
    .tab-btn[aria-selected="true"] {{
      background: var(--accent);
      color: #fff;
    }}
    .toolbar {{
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
    }}
    .crumbs {{
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 4px;
      font-size: 14px;
      color: var(--muted);
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 8px 10px;
    }}
    .crumbs button {{
      min-height: 32px;
      padding: 2px 8px;
      border: none;
      background: transparent;
      color: var(--accent);
      font-weight: 600;
    }}
    .card {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 12px;
      overflow: hidden;
    }}
    .file-row {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 10px;
      padding: 10px 12px;
      border-bottom: 1px solid var(--border);
    }}
    .file-row:last-child {{ border-bottom: none; }}
    .file-main {{
      display: flex;
      align-items: center;
      gap: 10px;
      min-width: 0;
      flex: 1;
      text-align: left;
      border: none;
      background: transparent;
      padding: 4px 0;
    }}
    .file-name {{
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      font-weight: 500;
    }}
    .file-meta {{
      font-size: 12px;
      color: var(--muted);
    }}
    .row-actions {{
      display: flex;
      gap: 6px;
      flex-shrink: 0;
    }}
    .row-actions button {{
      min-height: 38px;
      padding: 4px 10px;
      font-size: 13px;
    }}
    .cli-out {{
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: 13px;
      background: #0d1117;
      color: #e6edf3;
      padding: 12px;
      border-radius: 10px;
      min-height: 220px;
      max-height: 55vh;
      overflow: auto;
      white-space: pre-wrap;
      word-break: break-word;
    }}
    .cli-form {{
      display: flex;
      gap: 8px;
    }}
    input[type="text"], input[type="password"] {{
      flex: 1;
      min-height: 44px;
      padding: 8px 12px;
      border-radius: 10px;
      border: 1px solid var(--border);
      background: var(--surface);
      color: var(--text);
      font: inherit;
    }}
    .chips {{
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
    }}
    .chips button {{
      min-height: 34px;
      padding: 4px 10px;
      font-size: 13px;
    }}
    .status-bar {{
      font-size: 13px;
      color: var(--muted);
      min-height: 20px;
    }}
    .hidden {{ display: none !important; }}
    dialog {{
      border: 1px solid var(--border);
      border-radius: 14px;
      background: var(--surface);
      color: var(--text);
      max-width: min(92vw, 560px);
      width: 100%;
      padding: 16px;
    }}
    dialog:modal {{
      overscroll-behavior: contain;
    }}
    dialog::backdrop {{
      background: rgba(0, 0, 0, 0.55);
      overflow: hidden;
      overscroll-behavior: contain;
    }}
    .dialog-actions {{
      display: flex;
      justify-content: flex-end;
      gap: 8px;
      margin-top: 14px;
    }}
    .preview-img {{
      max-width: 100%;
      max-height: 60vh;
      display: block;
      margin: 8px auto;
      border-radius: 8px;
    }}
    .preview-text {{
      max-height: 55vh;
      overflow: auto;
      padding: 10px;
      border-radius: 8px;
      border: 1px solid var(--border);
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      font-size: 12px;
      white-space: pre-wrap;
      word-break: break-word;
    }}
    #drop-zone {{
      border: 2px dashed var(--border);
      border-radius: 12px;
      padding: 14px;
      text-align: center;
      color: var(--muted);
      font-size: 14px;
    }}
    #drop-zone.active {{
      border-color: var(--accent);
      color: var(--accent);
    }}
  </style>
</head>
<body>
  <header>
    <div class="brand">
      <span>dfs</span>
      <span id="remote-label">{safe_name}</span>
      <span class="badge">{ro_badge}</span>
    </div>
    <button id="logout-btn" type="button" class="hidden">ログアウト</button>
  </header>

  <main>
    <section id="login-view" class="card hidden" style="padding: 16px;">
      <h2 style="margin-top: 0;">アクセストークンを入力</h2>
      <form id="login-form" class="cli-form">
        <input id="login-token" type="password" autocomplete="current-password" placeholder="token" required>
        <button type="submit" class="primary">ログイン</button>
      </form>
      <p id="login-error" class="status-bar"></p>
    </section>

    <section id="app-view" class="hidden">
      <div class="tabs" role="tablist">
        <button id="tab-files" class="tab-btn" type="button" role="tab" aria-selected="true">ファイル共有</button>
        <button id="tab-cli" class="tab-btn" type="button" role="tab" aria-selected="false">Web CLI</button>
      </div>

      <div id="status-bar" class="status-bar"></div>

      <div id="panel-files">
        <div class="toolbar">
          <button id="sync-btn" type="button">↻ 同期</button>
          <button id="upload-btn" type="button" class="primary">↑ アップロード</button>
          <button id="mkdir-btn" type="button">＋ フォルダ</button>
          <input id="file-input" type="file" multiple class="hidden">
        </div>

        <div id="drop-zone">ここにファイルをドロップ、または「アップロード」で選択</div>
        <div id="crumbs" class="crumbs"></div>
        <div id="file-list" class="card"></div>
      </div>

      <div id="panel-cli" class="hidden">
        <div class="chips" id="cli-chips">
          <button type="button" data-cmd="ls">ls</button>
          <button type="button" data-cmd="sync">sync</button>
          <button type="button" data-cmd="status">status</button>
          <button type="button" data-cmd="pwd">pwd</button>
          <button type="button" data-cmd="mkdir ">mkdir</button>
          <button type="button" data-cmd="cat ">cat</button>
          <button type="button" data-cmd="help">help</button>
        </div>
        <pre id="cli-out" class="cli-out">dfs web cli ready. Type 'help'.</pre>
        <form id="cli-form" class="cli-form">
          <input id="cli-input" type="text" placeholder="ls / cat file.txt / sync ..." autocomplete="off" autocapitalize="none">
          <button type="submit" class="primary">実行</button>
        </form>
      </div>
    </section>
  </main>

  <dialog id="preview-dialog" aria-labelledby="preview-title">
    <h3 id="preview-title" style="margin-top:0;"></h3>
    <div id="preview-body"></div>
    <div class="dialog-actions">
      <a id="preview-download" download><button type="button" class="primary">ダウンロード</button></a>
      <form method="dialog"><button value="close">閉じる</button></form>
    </div>
  </dialog>

  <dialog id="confirm-dialog" aria-labelledby="confirm-title">
    <h3 id="confirm-title" style="margin-top:0;">削除の確認</h3>
    <p id="confirm-message"></p>
    <form method="dialog" class="dialog-actions">
      <button value="cancel" autofocus>キャンセル</button>
      <button value="delete" class="danger">削除する</button>
    </form>
  </dialog>

  <dialog id="mkdir-dialog" aria-labelledby="mkdir-title">
    <h3 id="mkdir-title" style="margin-top:0;">新しいフォルダ</h3>
    <form id="mkdir-form">
      <input id="mkdir-name" type="text" placeholder="folder_name" required style="width:100%;">
      <div class="dialog-actions">
        <button id="mkdir-cancel" type="button">キャンセル</button>
        <button type="submit" class="primary">作成</button>
      </div>
    </form>
  </dialog>

  <script nonce="{nonce}">
    const INITIAL_AUTH = {auth_flag};
    const READ_ONLY = {ro_flag};
    let currentPath = "";
    let cliCwd = "";

    const loginView = document.getElementById("login-view");
    const appView = document.getElementById("app-view");
    const logoutBtn = document.getElementById("logout-btn");
    const statusBar = document.getElementById("status-bar");
    const fileListEl = document.getElementById("file-list");
    const crumbsEl = document.getElementById("crumbs");
    const fileInput = document.getElementById("file-input");
    const dropZone = document.getElementById("drop-zone");
    const uploadBtn = document.getElementById("upload-btn");
    const mkdirBtn = document.getElementById("mkdir-btn");
    const syncBtn = document.getElementById("sync-btn");
    const previewDialog = document.getElementById("preview-dialog");
    const confirmDialog = document.getElementById("confirm-dialog");
    const mkdirDialog = document.getElementById("mkdir-dialog");

    function setStatus(msg) {{
      statusBar.textContent = msg || "";
    }}

    function fmtSize(n) {{
      if (n < 1024) return n + " B";
      if (n < 1024 * 1024) return (n / 1024).toFixed(1) + " KiB";
      if (n < 1024 * 1024 * 1024) return (n / (1024 * 1024)).toFixed(1) + " MiB";
      return (n / (1024 * 1024 * 1024)).toFixed(2) + " GiB";
    }}

    async function apiJson(url, opts = {{}}) {{
      const resp = await fetch(url, opts);
      const data = await resp.json().catch(() => ({{}}));
      if (resp.status === 401) {{
        showLogin();
        throw new Error("Authentication required");
      }}
      if (!resp.ok) {{
        throw new Error(data.error || ("HTTP " + resp.status));
      }}
      return data;
    }}

    function showLogin() {{
      loginView.classList.remove("hidden");
      appView.classList.add("hidden");
      logoutBtn.classList.add("hidden");
    }}

    function showApp() {{
      loginView.classList.add("hidden");
      appView.classList.remove("hidden");
      logoutBtn.classList.remove("hidden");
      if (READ_ONLY) {{
        uploadBtn.classList.add("hidden");
        mkdirBtn.classList.add("hidden");
        dropZone.classList.add("hidden");
      }}
      loadDir(currentPath);
    }}

    function renderCrumbs(pathStr) {{
      crumbsEl.replaceChildren();
      const rootBtn = document.createElement("button");
      rootBtn.type = "button";
      rootBtn.textContent = "/";
      rootBtn.addEventListener("click", () => loadDir(""));
      crumbsEl.appendChild(rootBtn);
      const parts = pathStr ? pathStr.split("/") : [];
      let acc = "";
      for (const part of parts) {{
        const sep = document.createElement("span");
        sep.textContent = "/";
        crumbsEl.appendChild(sep);
        acc = acc ? (acc + "/" + part) : part;
        const target = acc;
        const btn = document.createElement("button");
        btn.type = "button";
        btn.textContent = part;
        btn.addEventListener("click", () => loadDir(target));
        crumbsEl.appendChild(btn);
      }}
    }}

    async function loadDir(pathStr) {{
      setStatus("読み込み中...");
      try {{
        const data = await apiJson("./api/ls?path=" + encodeURIComponent(pathStr || ""));
        currentPath = data.path || "";
        renderCrumbs(currentPath);
        fileListEl.replaceChildren();
        if (!data.entries.length) {{
          const empty = document.createElement("div");
          empty.className = "file-row";
          empty.textContent = "（空のフォルダ）";
          fileListEl.appendChild(empty);
        }}
        for (const entry of data.entries) {{
          const row = document.createElement("div");
          row.className = "file-row";

          const mainBtn = document.createElement("button");
          mainBtn.type = "button";
          mainBtn.className = "file-main";
          const icon = document.createElement("span");
          icon.textContent = entry.is_dir ? "📁" : (entry.preview === "image" ? "🖼️" : "📄");
          const info = document.createElement("div");
          info.style.minWidth = "0";
          const nameEl = document.createElement("div");
          nameEl.className = "file-name";
          nameEl.textContent = entry.name;
          const metaEl = document.createElement("div");
          metaEl.className = "file-meta";
          metaEl.textContent = entry.is_dir ? "フォルダ" : fmtSize(entry.size);
          info.append(nameEl, metaEl);
          mainBtn.append(icon, info);
          mainBtn.addEventListener("click", () => {{
            if (entry.is_dir) {{
              loadDir(entry.path);
            }} else {{
              openPreview(entry);
            }}
          }});

          const actions = document.createElement("div");
          actions.className = "row-actions";
          if (!entry.is_dir) {{
            const dlLink = document.createElement("a");
            dlLink.href = "./api/download?path=" + encodeURIComponent(entry.path);
            dlLink.download = entry.name;
            const dlBtn = document.createElement("button");
            dlBtn.type = "button";
            dlBtn.textContent = "↓";
            dlBtn.setAttribute("aria-label", entry.name + " をダウンロード");
            dlLink.appendChild(dlBtn);
            actions.appendChild(dlLink);
          }}
          if (!READ_ONLY) {{
            const rmBtn = document.createElement("button");
            rmBtn.type = "button";
            rmBtn.className = "danger";
            rmBtn.textContent = "削除";
            rmBtn.addEventListener("click", () => confirmDelete(entry));
            actions.appendChild(rmBtn);
          }}

          row.append(mainBtn, actions);
          fileListEl.appendChild(row);
        }}
        setStatus("v" + data.version + " / " + data.entries.length + " 件");
      }} catch (err) {{
        setStatus("エラー: " + err.message);
      }}
    }}

    async function openPreview(entry) {{
      const titleEl = document.getElementById("preview-title");
      const bodyEl = document.getElementById("preview-body");
      const dlLink = document.getElementById("preview-download");
      titleEl.textContent = entry.name;
      dlLink.href = "./api/download?path=" + encodeURIComponent(entry.path);
      dlLink.download = entry.name;
      bodyEl.replaceChildren();
      if (entry.preview === "image") {{
        const img = document.createElement("img");
        img.className = "preview-img";
        img.alt = entry.name;
        img.src = "./api/download?inline=1&path=" + encodeURIComponent(entry.path);
        bodyEl.appendChild(img);
      }} else if (entry.preview === "text") {{
        const pre = document.createElement("pre");
        pre.className = "preview-text";
        pre.textContent = "読み込み中...";
        bodyEl.appendChild(pre);
        fetch("./api/download?inline=1&path=" + encodeURIComponent(entry.path))
          .then((r) => r.text())
          .then((txt) => {{ pre.textContent = txt.slice(0, 65536); }})
          .catch((e) => {{ pre.textContent = "読み込み失敗: " + e.message; }});
      }} else {{
        const p = document.createElement("p");
        p.textContent = "サイズ: " + fmtSize(entry.size) + "（ダウンロードして確認できます）";
        bodyEl.appendChild(p);
      }}
      previewDialog.showModal();
    }}

    let pendingDeleteEntry = null;
    function confirmDelete(entry) {{
      pendingDeleteEntry = entry;
      document.getElementById("confirm-message").textContent =
        "「" + entry.name + "」を削除しますか？";
      confirmDialog.showModal();
    }}

    confirmDialog.addEventListener("close", async () => {{
      const action = confirmDialog.returnValue;
      confirmDialog.returnValue = "";
      const target = pendingDeleteEntry;
      pendingDeleteEntry = null;
      if (action === "delete" && target) {{
        setStatus("削除中...");
        try {{
          await apiJson("./api/rm", {{
            method: "POST",
            headers: {{ "Content-Type": "application/json" }},
            body: JSON.stringify({{ path: target.path }}),
          }});
          await loadDir(currentPath);
        }} catch (err) {{
          setStatus("削除失敗: " + err.message);
        }}
      }}
    }});

    async function uploadFiles(files) {{
      if (!files || !files.length || READ_ONLY) return;
      for (let i = 0; i < files.length; i++) {{
        const file = files[i];
        const rel = currentPath ? (currentPath + "/" + file.name) : file.name;
        setStatus("アップロード中 (" + (i + 1) + "/" + files.length + "): " + file.name);
        try {{
          await apiJson("./api/upload?path=" + encodeURIComponent(rel), {{
            method: "POST",
            headers: {{ "Content-Type": "application/octet-stream" }},
            body: file,
          }});
        }} catch (err) {{
          setStatus("アップロード失敗 (" + file.name + "): " + err.message);
          return;
        }}
      }}
      await loadDir(currentPath);
    }}

    uploadBtn.addEventListener("click", () => fileInput.click());
    fileInput.addEventListener("change", () => {{
      uploadFiles(fileInput.files);
      fileInput.value = "";
    }});

    dropZone.addEventListener("dragover", (e) => {{
      e.preventDefault();
      dropZone.classList.add("active");
    }});
    dropZone.addEventListener("dragleave", () => dropZone.classList.remove("active"));
    dropZone.addEventListener("drop", (e) => {{
      e.preventDefault();
      dropZone.classList.remove("active");
      uploadFiles(e.dataTransfer.files);
    }});

    syncBtn.addEventListener("click", async () => {{
      setStatus("同期中...");
      try {{
        await apiJson("./api/sync", {{ method: "POST" }});
        await loadDir(currentPath);
      }} catch (err) {{
        setStatus("同期失敗: " + err.message);
      }}
    }});

    mkdirBtn.addEventListener("click", () => {{
      document.getElementById("mkdir-name").value = "";
      mkdirDialog.showModal();
    }});
    document.getElementById("mkdir-cancel").addEventListener("click", () => mkdirDialog.close());
    document.getElementById("mkdir-form").addEventListener("submit", async (e) => {{
      e.preventDefault();
      const name = document.getElementById("mkdir-name").value.trim();
      if (!name) return;
      const rel = currentPath ? (currentPath + "/" + name) : name;
      mkdirDialog.close();
      setStatus("フォルダ作成中...");
      try {{
        await apiJson("./api/mkdir", {{
          method: "POST",
          headers: {{ "Content-Type": "application/json" }},
          body: JSON.stringify({{ path: rel }}),
        }});
        await loadDir(currentPath);
      }} catch (err) {{
        setStatus("作成失敗: " + err.message);
      }}
    }});

    // Tabs
    const tabFiles = document.getElementById("tab-files");
    const tabCli = document.getElementById("tab-cli");
    const panelFiles = document.getElementById("panel-files");
    const panelCli = document.getElementById("panel-cli");
    tabFiles.addEventListener("click", () => {{
      tabFiles.setAttribute("aria-selected", "true");
      tabCli.setAttribute("aria-selected", "false");
      panelFiles.classList.remove("hidden");
      panelCli.classList.add("hidden");
    }});
    tabCli.addEventListener("click", () => {{
      tabCli.setAttribute("aria-selected", "true");
      tabFiles.setAttribute("aria-selected", "false");
      panelCli.classList.remove("hidden");
      panelFiles.classList.add("hidden");
      document.getElementById("cli-input").focus();
    }});

    // Web CLI
    const cliOut = document.getElementById("cli-out");
    const cliInput = document.getElementById("cli-input");
    for (const chip of document.querySelectorAll("#cli-chips button")) {{
      chip.addEventListener("click", () => {{
        const cmd = chip.getAttribute("data-cmd") || "";
        cliInput.value = cmd;
        if (!cmd.endsWith(" ")) {{
          document.getElementById("cli-form").requestSubmit();
        }} else {{
          cliInput.focus();
        }}
      }});
    }}
    document.getElementById("cli-form").addEventListener("submit", async (e) => {{
      e.preventDefault();
      const command = cliInput.value.trim();
      if (!command) return;
      cliInput.value = "";
      cliOut.textContent += "\\n$ " + command + "\\n";
      try {{
        const res = await apiJson("./api/cli", {{
          method: "POST",
          headers: {{ "Content-Type": "application/json" }},
          body: JSON.stringify({{ command, cwd: cliCwd }}),
        }});
        cliCwd = res.cwd || "";
        if (res.output) {{
          cliOut.textContent += res.output + "\\n";
        }}
      }} catch (err) {{
        cliOut.textContent += "Error: " + err.message + "\\n";
      }}
      cliOut.scrollTop = cliOut.scrollHeight;
    }});

    // Login / Logout
    document.getElementById("login-form").addEventListener("submit", async (e) => {{
      e.preventDefault();
      const token = document.getElementById("login-token").value;
      try {{
        await apiJson("./api/login", {{
          method: "POST",
          headers: {{ "Content-Type": "application/json" }},
          body: JSON.stringify({{ token }}),
        }});
        document.getElementById("login-error").textContent = "";
        showApp();
      }} catch (err) {{
        document.getElementById("login-error").textContent = "ログイン失敗: " + err.message;
      }}
    }});

    logoutBtn.addEventListener("click", async () => {{
      await fetch("./api/logout", {{ method: "POST" }}).catch(() => {{}});
      showLogin();
    }});

    if (INITIAL_AUTH) {{
      showApp();
    }} else {{
      showLogin();
    }}
  </script>
</body>
</html>
"""


def make_web_handler(backend: DFSWebBackend, config: WebConfig):
    """スマホ向け Web CLI HTTP ハンドラを生成する。"""
    base_prefix = "/" + config.base_path.strip("/") if config.base_path.strip("/") else ""
    cookie_name = "dfs_web_session"

    class DFSWebHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt: str, *args: Any) -> None:
            pass

        def _is_https(self) -> bool:
            proto = (self.headers.get("X-Forwarded-Proto") or "").split(",")[0].strip().lower()
            return bool(config.secure_cookie or proto == "https")

        def _strip_base(self, path: str) -> str:
            if base_prefix and path.startswith(base_prefix):
                rest = path[len(base_prefix) :]
                return rest if rest.startswith("/") else "/" + rest
            return path

        def _set_common_headers(self, csp_nonce: Optional[str] = None) -> None:
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Cross-Origin-Resource-Policy", "same-origin")
            self.send_header("Vary", "Sec-Fetch-Dest, Sec-Fetch-Mode, Sec-Fetch-Site")
            if csp_nonce:
                csp = (
                    f"script-src 'nonce-{csp_nonce}' 'strict-dynamic' 'report-sample'; "
                    "object-src 'none'; base-uri 'none'; frame-ancestors 'none';"
                )
                self.send_header("Content-Security-Policy", csp)

        def _send_json(
            self,
            status: int,
            payload: Dict[str, Any],
            extra_headers: Optional[List[Tuple[str, str]]] = None,
        ) -> None:
            raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self._set_common_headers()
            for k, v in extra_headers or []:
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(raw)

        def _cookie_header(self, value: str, max_age: Optional[int] = None) -> str:
            parts = [f"{cookie_name}={value}", "HttpOnly", "SameSite=Lax", "Path=/"]
            if max_age is not None:
                parts.append(f"Max-Age={int(max_age)}")
            if self._is_https():
                parts.append("Secure")
            return "; ".join(parts)

        def _is_authenticated(self) -> bool:
            if config.is_expired():
                return False
            auth = self.headers.get("Authorization") or ""
            if auth.startswith("Bearer "):
                presented = auth[len("Bearer ") :].strip()
                if hmac.compare_digest(presented, config.token):
                    return True
            hdr_tok = (self.headers.get("X-DFS-Web-Token") or "").strip()
            if hdr_tok and hmac.compare_digest(hdr_tok, config.token):
                return True
            raw_cookie = self.headers.get("Cookie") or ""
            if raw_cookie:
                c = http.cookies.SimpleCookie()
                try:
                    c.load(raw_cookie)
                except http.cookies.CookieError:
                    return False
                if cookie_name in c and verify_session_cookie(config.token, c[cookie_name].value):
                    return True
            return False

        def _check_fetch_metadata(self) -> bool:
            site = (self.headers.get("Sec-Fetch-Site") or "").strip().lower()
            if site == "cross-site":
                mode = (self.headers.get("Sec-Fetch-Mode") or "").strip().lower()
                if not (self.command == "GET" and mode == "navigate"):
                    self._send_json(403, {"error": "Cross-site request blocked"})
                    return False
            return True

        def _read_body(self, limit: int) -> Optional[bytes]:
            if self.headers.get("Transfer-Encoding"):
                self.close_connection = True
                self._send_json(400, {"error": "Transfer-Encoding is not supported"})
                return None
            raw_len = self.headers.get("Content-Length", "0")
            try:
                length = int(raw_len)
            except (TypeError, ValueError):
                self.close_connection = True
                self._send_json(400, {"error": "Invalid Content-Length"})
                return None
            if length < 0 or length > limit:
                self.close_connection = True
                self._send_json(413, {"error": f"Payload exceeds limit ({limit} bytes)"})
                return None
            return self.rfile.read(length) if length else b""

        def do_GET(self) -> None:
            if not self._check_fetch_metadata():
                return
            if config.is_expired():
                self._send_json(403, {"error": "Share link has expired"})
                return
            parsed = urlsplit(self.path)
            route = self._strip_base(parsed.path)
            qs = parse_qs(parsed.query)

            if route in ("/", "/index.html"):
                q_tok = (qs.get("token") or [""])[0]
                if q_tok and hmac.compare_digest(q_tok, config.token):
                    sess = sign_session_cookie(config.token, config.expires_at)
                    clean_target = parsed.path or "/"
                    self.send_response(302)
                    self.send_header("Location", clean_target)
                    self.send_header("Set-Cookie", self._cookie_header(sess))
                    self.send_header("Content-Length", "0")
                    self._set_common_headers()
                    self.end_headers()
                    return
                nonce = base64.b64encode(secrets.token_bytes(16)).decode("ascii")
                html_doc = _render_html(
                    nonce=nonce,
                    remote_name=config.remote_name,
                    authenticated=self._is_authenticated(),
                    read_only=config.read_only,
                ).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(html_doc)))
                self._set_common_headers(csp_nonce=nonce)
                self.end_headers()
                self.wfile.write(html_doc)
                return

            if not self._is_authenticated():
                self._send_json(401, {"error": "Unauthorized"})
                return

            try:
                if route == "/api/info":
                    self._send_json(
                        200,
                        {
                            "remote": config.remote_name,
                            "read_only": config.read_only,
                            "expires_at": config.expires_at,
                        },
                    )
                    return
                if route == "/api/ls":
                    rel = (qs.get("path") or [""])[0]
                    self._send_json(200, backend.list_dir(rel))
                    return
                if route == "/api/download":
                    rel = (qs.get("path") or [""])[0]
                    inline = (qs.get("inline") or ["0"])[0] == "1"
                    target, mime, size = backend.read_file_info(rel)
                    # HTML/SVG 等をインラインで返すと XSS リスクがあるため安全側に倒す
                    if mime in ("text/html", "image/svg+xml", "application/xhtml+xml"):
                        inline = False
                        mime = "application/octet-stream"
                    disp = "inline" if inline else "attachment"
                    fname = quote(target.name)
                    self.send_response(200)
                    self.send_header("Content-Type", mime)
                    self.send_header("Content-Length", str(size))
                    self.send_header("Content-Disposition", f"{disp}; filename*=UTF-8''{fname}")
                    self._set_common_headers()
                    self.end_headers()
                    with target.open("rb") as f:
                        while True:
                            chunk = f.read(65536)
                            if not chunk:
                                break
                            self.wfile.write(chunk)
                    return
                self._send_json(404, {"error": f"Unknown path {route}"})
            except WebAppError as e:
                self._send_json(e.status, {"error": e.message})

        def do_POST(self) -> None:
            if not self._check_fetch_metadata():
                return
            if config.is_expired():
                self._send_json(403, {"error": "Share link has expired"})
                return
            parsed = urlsplit(self.path)
            route = self._strip_base(parsed.path)
            qs = parse_qs(parsed.query)

            if route == "/api/login":
                body = self._read_body(MAX_JSON_BODY_BYTES)
                if body is None:
                    return
                try:
                    data = json.loads(body.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    self._send_json(400, {"error": "Invalid JSON"})
                    return
                presented = str(data.get("token") or "")
                if not hmac.compare_digest(presented, config.token):
                    self._send_json(401, {"error": "Invalid token"})
                    return
                sess = sign_session_cookie(config.token, config.expires_at)
                self._send_json(
                    200,
                    {"ok": True},
                    extra_headers=[("Set-Cookie", self._cookie_header(sess))],
                )
                return

            if route == "/api/logout":
                self._send_json(
                    200,
                    {"ok": True},
                    extra_headers=[
                        ("Set-Cookie", self._cookie_header("", max_age=0)),
                        ("Clear-Site-Data", '"cookies", "storage", "cache"'),
                    ],
                )
                return

            if not self._is_authenticated():
                self._send_json(401, {"error": "Unauthorized"})
                return

            try:
                if route == "/api/upload":
                    rel = (qs.get("path") or [""])[0]
                    body = self._read_body(config.max_upload_bytes)
                    if body is None:
                        return
                    self._send_json(200, backend.save_upload(rel, body))
                    return

                if route == "/api/sync":
                    body = self._read_body(MAX_JSON_BODY_BYTES)
                    if body is None:
                        return
                    ver = backend.sync(force=False)
                    self._send_json(200, {"version": ver})
                    return

                body = self._read_body(MAX_JSON_BODY_BYTES)
                if body is None:
                    return
                try:
                    data = json.loads(body.decode("utf-8")) if body else {}
                except (UnicodeDecodeError, json.JSONDecodeError):
                    self._send_json(400, {"error": "Invalid JSON"})
                    return

                if route == "/api/mkdir":
                    self._send_json(200, backend.make_dir(str(data.get("path") or "")))
                    return
                if route == "/api/rm":
                    self._send_json(200, backend.remove_path(str(data.get("path") or "")))
                    return
                if route == "/api/mv":
                    self._send_json(
                        200,
                        backend.move_path(str(data.get("src") or ""), str(data.get("dst") or "")),
                    )
                    return
                if route == "/api/cli":
                    res = backend.run_cli(
                        str(data.get("command") or ""),
                        cwd_rel=str(data.get("cwd") or ""),
                    )
                    self._send_json(200, res)
                    return

                self._send_json(404, {"error": f"Unknown path {route}"})
            except WebAppError as e:
                self._send_json(e.status, {"error": e.message})

    return DFSWebHandler


def find_free_port(bind: str = "0.0.0.0", start_port: int = 8080, attempts: int = 100) -> int:
    """``start_port`` から順に空いている TCP ポートを探す。"""
    family = socket.AF_INET6 if ":" in bind else socket.AF_INET
    for port in range(int(start_port), int(start_port) + attempts):
        with socket.socket(family, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind((bind, port))
                return port
            except OSError:
                continue
    return 0


def start_web_server(
    backend: DFSWebBackend,
    config: WebConfig,
    bind: str = "127.0.0.1",
    port: int = 8080,
) -> ThreadingHTTPServer:
    """Web CLI 用の HTTP サーバを起動して返す。"""
    if config.started_at <= 0:
        config.started_at = time.time()
    handler = make_web_handler(backend, config)
    return ThreadingHTTPServer((bind, int(port)), handler)
