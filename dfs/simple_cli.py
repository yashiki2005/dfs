#!/usr/bin/env python3
"""
dfs/simple_cli.py
Unified, beginner-friendly CLI wrapper (``dfs`` / ``./cli``) over ``dfscli`` and ``dfssvc``.

Simplifies the common workflow into single commands:
  dfs start                  # start local server + auto-configure 'local' remote
  dfs push ./dir [remote]    # sync local directory (auto-starts 'local' if needed)
  dfs pull [remote] ./dir    # pull files back
  dfs ls [remote]            # list remote files
  dfs share [remote]         # generate 1-line bootstrap command
  dfs join <token|url>       # join from invite token or URL
  dfs web [remote]           # start browser UI
  dfs mount [remote] ./mnt   # FUSE mount
  dfs status / stop          # inspect or stop local server
"""

from __future__ import annotations

import argparse
import os
import secrets
import sys
from pathlib import Path
from typing import List, Optional, Sequence


DEFAULT_PUBLIC_HUBS = (
    "https://l2.yashiki.top",
    "https://eu.yashiki.top",
)
DEFAULT_PUBLIC_HUB = DEFAULT_PUBLIC_HUBS[0]
_NAT_HUB_MSG = "NAT を突破するために yashiki.top を利用します（--no-hub で無効化できます）"


def _resolve_hub_urls(hub: Optional[str | Sequence[str]], no_hub: bool) -> List[str]:
    if no_hub:
        return []
    if hub is not None:
        items = [hub] if isinstance(hub, str) else list(hub)
    elif "DFS_DEFAULT_HUB" in os.environ:
        raw_env = os.environ.get("DFS_DEFAULT_HUB", "").strip()
        if not raw_env:
            return []
        items = [raw_env]
    else:
        items = list(DEFAULT_PUBLIC_HUBS)
    urls: List[str] = []
    seen = set()
    for item in items:
        for part in str(item or "").split(","):
            val = part.strip()
            if val and val not in seen:
                seen.add(val)
                urls.append(val)
    return urls


def _ensure_local_ready(
    name: str = "local",
    *,
    port: Optional[int] = None,
    secret: Optional[str] = None,
    bind: str = "127.0.0.1",
    advertise: Optional[str] = None,
    hub: Optional[str] = None,
    no_hub: bool = False,
) -> None:
    """Start ``dfssvc`` if not running and register the remote in ``RemoteStore``."""
    from . import cli_main
    from . import svc as svc_mod
    from .i18n import _
    from .remotes import RemoteStore

    svc_store = svc_mod.ServiceStore()
    existing_svc = svc_store.services.get(name)
    if existing_svc is None or not existing_svc.is_running():
        start_argv = ["start", "--name", name]
        if bind and bind != "127.0.0.1":
            start_argv.extend(["--host", bind])
        if port is not None:
            start_argv.extend(["--port", str(port)])
        if advertise:
            start_argv.extend(["--advertise", advertise])
        effective_hubs = _resolve_hub_urls(hub, no_hub)
        if effective_hubs:
            print(f"[dfs] {_(_NAT_HUB_MSG)}", file=sys.stderr)
            for hub_url in effective_hubs:
                start_argv.extend(["--join", hub_url])
        rc = svc_mod.main(start_argv)
        if rc != 0:
            raise SystemExit(rc)
        svc_store = svc_mod.ServiceStore()
        existing_svc = svc_store.services.get(name)

    if existing_svc is None:
        raise SystemExit(1)

    remote_store = RemoteStore()
    if name not in remote_store.remotes:
        chosen_secret = secret or os.environ.get("DFS_SECRET") or secrets.token_urlsafe(24)
        root_key_path = Path(existing_svc.root_key).expanduser()
        root_pub = Path(f"{root_key_path}.pub")
        cfg_argv = [
            "config",
            "create",
            name,
            "--registry",
            existing_svc.registry_url,
            "--key",
            existing_svc.writer_key,
            "--secret",
            chosen_secret,
        ]
        if root_pub.is_file():
            cfg_argv.extend(["--root-pubkey", str(root_pub)])
        else:
            cfg_argv.append("--allow-tofu")
        rc = cli_main.main(cfg_argv)
        if rc != 0:
            raise SystemExit(rc)


def _normalize_remote_target(target: Optional[str], default_remote: str = "local") -> str:
    if not target:
        return f"{default_remote}:"
    if target.startswith("dfs://") or ":" in target:
        return target
    return f"{target}:"


def _cmd_start(args: argparse.Namespace) -> int:
    _ensure_local_ready(
        args.name,
        port=args.port,
        secret=args.secret,
        bind=args.bind,
        advertise=args.advertise,
        hub=args.hub,
        no_hub=args.no_hub,
    )
    return 0


def _cmd_stop(args: argparse.Namespace) -> int:
    from . import svc as svc_mod

    argv = ["stop", args.name]
    if args.forget:
        argv.append("--forget")
    return int(svc_mod.main(argv) or 0)


def _cmd_status(args: argparse.Namespace) -> int:
    from . import svc as svc_mod

    argv = ["status"]
    if args.name:
        argv.append(args.name)
    return int(svc_mod.main(argv) or 0)


def _cmd_push(args: argparse.Namespace) -> int:
    from . import cli_main
    from .remotes import RemoteStore

    target = _normalize_remote_target(args.target)
    remote_name = target.split(":", 1)[0]
    if target.startswith("dfs://"):
        remote_name = target[len("dfs://") :].split("/", 1)[0].split(":", 1)[0]
    if remote_name == "local":
        from . import svc as svc_mod

        svc_rec = svc_mod.ServiceStore().services.get("local")
        if (
            "local" not in RemoteStore().remotes
            or svc_rec is None
            or not (svc_rec.is_running() or svc_mod._recorded_server_is_alive(svc_rec))
        ):
            _ensure_local_ready("local", no_hub=args.no_hub)
    argv = ["sync", args.src, target]
    if args.dry_run:
        argv.append("--dry-run")
    if args.delete:
        argv.append("--delete")
    return int(cli_main.main(argv) or 0)


def _cmd_pull(args: argparse.Namespace) -> int:
    from . import cli_main

    if args.dest is None:
        source = "local:"
        dest = args.source
    else:
        source = _normalize_remote_target(args.source)
        dest = args.dest
    return int(cli_main.main(["pull", source, dest]) or 0)


def _cmd_ls(args: argparse.Namespace) -> int:
    from . import cli_main

    return int(cli_main.main(["ls", _normalize_remote_target(args.target)]) or 0)


def _cmd_share(args: argparse.Namespace) -> int:
    from . import cli_main

    argv = ["share", args.remote]
    if args.name:
        argv.extend(["--name", args.name])
    if args.write_path:
        argv.extend(["--write-path", args.write_path])
    if args.token_only:
        argv.append("--token-only")
    return int(cli_main.main(argv) or 0)


def _cmd_join(args: argparse.Namespace) -> int:
    from . import cli_main

    target = args.target.strip()
    if target.startswith(("dfs-ro-v1:", "dfs-rw-v1:")):
        argv = ["invite", "join", target]
        if args.name:
            argv.extend(["--name", args.name])
        if args.dest:
            argv.extend(["--dest", args.dest])
        if args.watch:
            argv.append("--watch")
        else:
            argv.append("--sync")
        return int(cli_main.main(argv) or 0)

    argv = ["join", target]
    if args.name:
        argv.extend(["--name", args.name])
    if args.secret:
        argv.extend(["--secret", args.secret])
    if args.allow_tofu:
        argv.append("--allow-tofu")
    if args.sync:
        argv.append("--sync")
    return int(cli_main.main(argv) or 0)


def _cmd_web(args: argparse.Namespace) -> int:
    from . import cli_main

    argv = ["web", _normalize_remote_target(args.remote)]
    if args.bind:
        argv.extend(["--bind", args.bind])
    if args.port is not None:
        argv.extend(["--port", str(args.port)])
    if args.read_only:
        argv.append("--read-only")
    return int(cli_main.main(argv) or 0)


def _cmd_mount(args: argparse.Namespace) -> int:
    from . import cli_main

    if args.mountpoint is None:
        remote = "local:"
        mountpoint = args.remote
    else:
        remote = _normalize_remote_target(args.remote)
        mountpoint = args.mountpoint
    argv = ["mount", remote, mountpoint]
    if args.read_only:
        argv.append("--read-only")
    return int(cli_main.main(argv) or 0)


def _cmd_list(args: argparse.Namespace) -> int:
    from . import cli_main, svc as svc_mod

    svc_mod.main(["list"])
    return int(cli_main.main(["listremotes", "--no-check"]) or 0)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dfs",
        description="dfs: simple unified CLI for encrypted sync & sharing (wraps dfscli + dfssvc)",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("start", aliases=["serve"], help="Start local server and auto-configure 'local' remote")
    p.add_argument("--name", default="local", help="Service/remote name (default: local)")
    p.add_argument("--port", type=int, help="Starting port for L2/L3")
    p.add_argument("--secret", help="Tree secret (auto-generated if omitted)")
    p.add_argument("--bind", default="127.0.0.1", help="Bind address (default: 127.0.0.1)")
    p.add_argument("--advertise", help="Advertised host/IP for remote clients")
    p.add_argument(
        "--hub",
        action="append",
        default=None,
        help=f"NAT traversal hub URL (default: {', '.join(DEFAULT_PUBLIC_HUBS)})",
    )
    p.add_argument("--no-hub", action="store_true", help="Disable automatic join to yashiki.top")
    p.set_defaults(func=_cmd_start)

    p = sub.add_parser("stop", help="Stop local server")
    p.add_argument("name", nargs="?", default="local", help="Service name (default: local)")
    p.add_argument("--forget", action="store_true", help="Also remove service record")
    p.set_defaults(func=_cmd_stop)

    p = sub.add_parser("status", help="Show local server status")
    p.add_argument("name", nargs="?", default=None, help="Service name")
    p.set_defaults(func=_cmd_status)

    p = sub.add_parser("push", help="Sync a local file/directory to a remote (auto-starts 'local')")
    p.add_argument("src", help="Local file or directory")
    p.add_argument("target", nargs="?", default=None, help="Remote target (default: local:)")
    p.add_argument("-n", "--dry-run", action="store_true", help="Show planned changes only")
    p.add_argument("--delete", action="store_true", help="Delete remote files missing locally")
    p.add_argument("--no-hub", action="store_true", help="Disable automatic join to yashiki.top if auto-starting")
    p.set_defaults(func=_cmd_push)

    p = sub.add_parser("pull", help="Pull files from a remote into a local directory")
    p.add_argument("source", help="Remote source (or local dest if using default 'local:')")
    p.add_argument("dest", nargs="?", default=None, help="Local destination directory")
    p.set_defaults(func=_cmd_pull)

    p = sub.add_parser("ls", help="List remote files")
    p.add_argument("target", nargs="?", default=None, help="Remote path (default: local:)")
    p.set_defaults(func=_cmd_ls)

    p = sub.add_parser("share", help="Generate a 1-line bootstrap command for another machine / RunPod")
    p.add_argument("remote", nargs="?", default="local", help="Remote name (default: local)")
    p.add_argument("--name", help="Remote name on the target machine")
    p.add_argument("--write-path", help="Allow scoped write-back to this subpath (e.g. out)")
    p.add_argument("--token-only", action="store_true", help="Print only the invite token")
    p.set_defaults(func=_cmd_share)

    p = sub.add_parser("join", help="Join from an invite token or registry URL")
    p.add_argument("target", help="Invite token (dfs-ro-v1:.../dfs-rw-v1:...) or registry URL")
    p.add_argument("--name", help="Local remote name")
    p.add_argument("--dest", default="./dfs-sync", help="Destination directory for invite sync (default: ./dfs-sync)")
    p.add_argument("--secret", help="Tree secret (when joining a URL)")
    p.add_argument("--allow-tofu", action="store_true", help="Allow TOFU when root_pubkey is not pinned")
    p.add_argument("--sync", action="store_true", help="Sync once")
    p.add_argument("--watch", action="store_true", help="Keep watching and syncing")
    p.set_defaults(func=_cmd_join)

    p = sub.add_parser("web", help="Start browser file-sharing UI")
    p.add_argument("remote", nargs="?", default=None, help="Remote name (default: local:)")
    p.add_argument("--bind", help="Bind address")
    p.add_argument("--port", type=int, help="Port")
    p.add_argument("--read-only", action="store_true", help="Read-only mode")
    p.set_defaults(func=_cmd_web)

    p = sub.add_parser("mount", help="Mount remote via FUSE")
    p.add_argument("remote", help="Remote (or mountpoint if using default 'local:')")
    p.add_argument("mountpoint", nargs="?", default=None, help="Local mountpoint")
    p.add_argument("--read-only", action="store_true", help="Read-only mount")
    p.set_defaults(func=_cmd_mount)

    p = sub.add_parser("list", help="List local services and remotes")
    p.set_defaults(func=_cmd_list)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    from .i18n import configure_stdio, set_current_language

    configure_stdio()
    set_current_language(None)
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args) or 0)


if __name__ == "__main__":
    raise SystemExit(main())
