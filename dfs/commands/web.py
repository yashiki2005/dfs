"""Web UI / QR file-sharing subcommand (``dfscli web``)."""

from __future__ import annotations

import argparse
import secrets
import shutil
import subprocess
import sys
from typing import Any, Dict


def cmd_web(args: argparse.Namespace) -> int:
    """スマホ等のブラウザ向けファイル共有 & Web CLI サーバを起動する。"""
    from dfs import cli_main as _cm
    from dfs.svc import ServiceStore
    from dfs.web import DFSWebBackend, WebConfig, find_free_port, start_web_server

    store = _cm.RemoteStore()
    remote_name = args.remote
    if remote_name:
        if remote_name not in store.remotes:
            _cm._ensure_remote_from_service(store, remote_name)
        remote = store.get(remote_name)
    else:
        svc_store = ServiceStore()
        running_svcs = [n for n, s in svc_store.services.items() if s.is_running()]
        names = store.names()
        if running_svcs:
            pick = "local" if "local" in running_svcs else running_svcs[0]
            if pick not in store.remotes:
                _cm._ensure_remote_from_service(store, pick)
            remote_name = pick
        elif names:
            remote_name = "local" if "local" in names else names[0]
        elif svc_store.services:
            pick = "local" if "local" in svc_store.services else next(iter(svc_store.services))
            _cm._ensure_remote_from_service(store, pick)
            remote_name = pick
        else:
            raise _cm.UsageError(
                "リモートが未登録です。先に 'dfssvc start' または 'dfscli config create' を実行してください。"
            )
        print(f"[dfscli web] 自動選択: {remote_name}")
        remote = store.get(remote_name)
    read_only = bool(args.read_only or remote.read_only)
    node = _cm.open_remote(remote, create=True)

    def _sync(force: bool) -> int:
        return _cm.refresh_cache(node, force=force)

    def _push_now() -> int:
        env, _wire = _cm._push(node, remote)
        return int(env["payload"]["version"])

    def _status_now() -> Dict[str, Any]:
        return {
            "registry": remote.registry,
            "path": remote.path or "/",
            "workdir": str(node.clayfs.work_tree),
        }

    backend = DFSWebBackend(
        work_tree=node.clayfs.work_tree,
        remote_name=remote.name,
        read_only=read_only,
        sync_fn=_sync,
        push_fn=_push_now,
        status_fn=_status_now,
    )
    version = backend.sync(force=False)
    token = (args.token or "").strip() or secrets.token_urlsafe(18)
    base_path = (args.base_path or "").strip()
    if base_path and not base_path.startswith("/"):
        base_path = "/" + base_path
    base_path = base_path.rstrip("/")

    bind = args.bind
    if bind is None:
        bind = "127.0.0.1"
    if bind in ("0.0.0.0", "::"):
        print(
            "[dfscli web] 警告: TLS なしでネットワーク全体に公開します（--bind 0.0.0.0）。"
            "信頼できる LAN 外ではリバースプロキシ等で保護してください。",
            file=sys.stderr,
        )
    port = int(args.port) if args.port is not None else find_free_port(bind, 8080)

    cfg = WebConfig(
        remote_name=remote.name,
        token=token,
        read_only=read_only,
        ttl_seconds=max(0, int(args.ttl or 0)),
        base_path=base_path,
        secure_cookie=bool(args.secure_cookie),
        trusted_proxies=tuple(getattr(args, "trusted_proxy", None) or ()),
    )
    httpd = start_web_server(backend, cfg, bind=bind, port=port)
    bound_port = httpd.server_address[1]
    host_display = _cm._lan_ip() if bind in ("0.0.0.0", "::") else bind
    host_display = f"[{host_display}]" if ":" in host_display else host_display
    prefix_display = base_path + "/" if base_path else "/"
    access_url = f"http://{host_display}:{bound_port}{prefix_display}?token={token}"

    print(
        f"[dfscli web] Remote   : {remote.name} (v{version}, "
        f"{'read-only' if read_only else 'read-write'})"
    )
    print(f"[dfscli web] Listen   : {bind}:{bound_port}")
    print(f"[dfscli web] Open URL : {access_url}")
    if bind in ("127.0.0.1", "::1", "localhost") and not args.public_url:
        print(
            "[dfscli web] ヒント   : ローカル (127.0.0.1) のみ待機中です。"
            "LAN 内のスマホ等から直接接続する場合は --bind 0.0.0.0 を指定してください。"
        )
    if args.public_url:
        pub_base = args.public_url.rstrip("/")
        qr_target = f"{pub_base}/?token={token}"
        print(f"[dfscli web] Public   : {qr_target}")
    else:
        qr_target = access_url
    if cfg.ttl_seconds > 0:
        print(f"[dfscli web] TTL      : {cfg.ttl_seconds}s")
    if shutil.which("qrencode"):
        try:
            qr = subprocess.run(
                ["qrencode", "-t", "UTF8", qr_target],
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
            )
            if qr.returncode == 0 and qr.stdout.strip():
                print(qr.stdout.rstrip())
        except OSError:
            pass
    print("[dfscli web] Ctrl-C で停止します")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[dfscli web] 停止しました")
    finally:
        httpd.server_close()
    return 0
