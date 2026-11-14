"""Remote management, discovery, candidacy, invite, join, quit, and delegate subcommands."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Dict, List, Optional

from dfs.commands import _cm
from dfs.discovery import (
    CandidacyError,
    create_candidacy_envelope,
    fetch_candidacy,
    verify_candidacy_envelope,
)
from dfs.dnssec import Discovery, DiscoveryError
from dfs.invite import InviteError, decode_invite
from dfs.remotes import config_dir, restrict_to_owner


def _remote_domain_candidate(remote: _cm.Remote) -> str:
    """リモート定義から DNSSEC 検証対象のドメイン名候補を取り出す。"""
    import ipaddress
    from urllib.parse import urlsplit

    def _is_domain(val: str) -> bool:
        s = (val or "").strip().rstrip(".")
        if not s or "." not in s or s == "localhost":
            return False
        try:
            ipaddress.ip_address(s.strip("[]"))
            return False
        except ValueError:
            pass
        tld = s.rsplit(".", 1)[-1]
        return len(tld) >= 2 and tld.isalpha()

    name = (remote.name or "").strip().rstrip(".")
    host = (urlsplit(remote.registry).hostname or "").strip().rstrip(".")
    if _is_domain(host):
        # 例: name="yashiki.top", registry="https://l2.yashiki.top" は親ドメイン名を優先。
        # 例: name="backup.v1", registry="https://dfs.example.com" は registry ホストを優先。
        if _is_domain(name) and (host == name or host.endswith(f".{name}")):
            return name
        return host
    if _is_domain(name):
        return name
    return ""


def _probe_remote_status(remote: _cm.Remote) -> Dict[str, Any]:
    """L2 (root/domain dfs) への問い合わせと ``_dfs.<domain>`` DNSSEC 検証を行う。"""
    from dfs.dnssec import DEFAULT_RECORD_PREFIX, has_txt_record

    online = _cm._probe_registry_tcp(remote.registry)
    status: Dict[str, Any] = {
        "online": online,
        "l2_ok": None,
        "l2_error": "",
        "role": None,
        "root_anchor": "",
        "paths_count": None,
        "pubkey_match": None,
        "dnssec": None,
        "dnssec_record": "",
        "dnssec_error": "",
    }
    if online:
        try:
            urls = [u for u in [remote.registry, *remote.registry_alternates] if u]
            client = _cm.cli_mod.RemoteRegistryClient(urls)
            if hasattr(client, "default_timeout"):
                client.default_timeout = 1.5
            info = client.list_paths()
            anchor = str(info.get("root_anchor") or "")
            server_pub = str(info.get("root_pubkey") or "").strip()
            paths = info.get("paths")
            status["l2_ok"] = True
            status["root_anchor"] = anchor
            domain_cand = _remote_domain_candidate(remote)
            if anchor == "/" or remote.name in _cm.DEFAULT_ROOT_DFS_DOMAINS or domain_cand in _cm.DEFAULT_ROOT_DFS_DOMAINS:
                status["role"] = "root"
            elif anchor:
                status["role"] = "domain"
            status["paths_count"] = len(paths) if isinstance(paths, dict) else 0
            if remote.root_pubkey and server_pub:
                status["pubkey_match"] = (remote.root_pubkey == server_pub)
        except Exception as e:  # noqa: BLE001
            status["l2_ok"] = False
            status["l2_error"] = str(e)

    domain = _remote_domain_candidate(remote)
    if domain:
        record_name = f"{DEFAULT_RECORD_PREFIX}.{domain}"
        try:
            if has_txt_record(record_name):
                status["dnssec_record"] = record_name
                try:
                    disc = _cm.discover_domain(domain, record_name=record_name)
                    if remote.root_pubkey and disc.root_pubkey and remote.root_pubkey != disc.root_pubkey:
                        status["dnssec"] = "mismatch"
                        status["dnssec_error"] = "root_pubkey mismatch with DNSSEC"
                    else:
                        status["dnssec"] = "verified"
                except DiscoveryError as e:
                    status["dnssec"] = "failed"
                    status["dnssec_error"] = str(e)
        except Exception:  # noqa: BLE001
            pass

    return status


DEFAULT_ROOT_DFS_DOMAINS = ("yashiki.top",)


def _probe_root_dfs_domain(domain: str) -> Dict[str, Any]:
    """既定の root dfs ドメインを決め打ちで DNSSEC 検証し、L2 へ問い合わせる。"""
    from dfs.dnssec import DEFAULT_RECORD_PREFIX, has_txt_record

    record_name = f"{DEFAULT_RECORD_PREFIX}.{domain}"
    status: Dict[str, Any] = {
        "name": domain,
        "registered": False,
        "registry": "",
        "path": f"/{domain}",
        "online": False,
        "l2_ok": None,
        "l2_error": "",
        "role": "root",
        "root_anchor": "",
        "paths_count": None,
        "dnssec": None,
        "dnssec_record": record_name,
        "dnssec_error": "",
    }
    try:
        if not has_txt_record(record_name):
            status["dnssec"] = "none"
            status["dnssec_error"] = f"{record_name} TXT not found"
            return status
        disc = _cm.discover_domain(domain, record_name=record_name)
        status["dnssec"] = "verified"
        status["registry"] = disc.primary_url
        status["path"] = disc.root_anchor or f"/{domain}"
        urls = [u for u in [disc.primary_url, *disc.alternate_urls] if u]
        online = _cm._probe_registry_tcp(disc.primary_url) if disc.primary_url else False
        status["online"] = online
        if online and urls:
            try:
                info = _cm.cli_mod.RemoteRegistryClient(urls).list_paths()
                paths = info.get("paths")
                status["l2_ok"] = True
                status["root_anchor"] = str(info.get("root_anchor") or status["path"])
                status["paths_count"] = len(paths) if isinstance(paths, dict) else 0
            except Exception as e:  # noqa: BLE001
                status["l2_ok"] = False
                status["l2_error"] = str(e)
    except DiscoveryError as e:
        status["dnssec"] = "failed"
        status["dnssec_error"] = str(e)
    except Exception as e:  # noqa: BLE001
        status["dnssec"] = "failed"
        status["dnssec_error"] = str(e)
    return status


def _format_remote_status_details(st: Dict[str, Any]) -> str:
    """``_probe_remote_status`` / ``_cm._probe_root_dfs_domain`` の詳細文字列を組み立てる。"""
    details: List[str] = []
    if st.get("l2_ok") is True:
        role_label = "root dfs" if st.get("role") == "root" else "domain dfs"
        anchor = st.get("root_anchor") or "/"
        paths_count = st.get("paths_count")
        l2_part = f"{role_label} (anchor={anchor}"
        if paths_count is not None:
            l2_part += f", paths={paths_count}"
        if st.get("pubkey_match") is False:
            l2_part += ", pubkey=MISMATCH"
        l2_part += ")"
        details.append(l2_part)
    elif st.get("l2_ok") is False and st.get("l2_error"):
        details.append(f"L2 error ({st['l2_error']})")
    dnssec_state = st.get("dnssec")
    if dnssec_state == "verified":
        details.append(f"DNSSEC: verified ({st.get('dnssec_record')})")
    elif dnssec_state in ("failed", "mismatch"):
        details.append(f"DNSSEC: FAILED ({st.get('dnssec_record')}: {st.get('dnssec_error')})")
    elif dnssec_state == "none":
        details.append(f"DNSSEC: none ({st.get('dnssec_record')})")
    return ", ".join(details)


def cmd_listremotes(args: argparse.Namespace) -> int:
    from concurrent.futures import ThreadPoolExecutor
    from dfs.svc import ServiceStore

    store = _cm.RemoteStore()
    names = store.names()
    no_check = bool(getattr(args, "no_check", False))
    is_prune = bool(getattr(args, "prune", False))

    known_domains = {n for n in names} | {
        _remote_domain_candidate(store.remotes[n]) for n in names
    }
    builtin_roots_to_probe = (
        []
        if (no_check or is_prune)
        else [d for d in _cm.DEFAULT_ROOT_DFS_DOMAINS if d not in known_domains]
    )

    if not names:
        root_statuses: List[Dict[str, Any]] = []
        if builtin_roots_to_probe:
            with ThreadPoolExecutor(max_workers=len(builtin_roots_to_probe)) as pool:
                root_statuses = list(pool.map(_cm._probe_root_dfs_domain, builtin_roots_to_probe))
        if getattr(args, "json", False):
            print(json.dumps(root_statuses, ensure_ascii=False, indent=2))
            return 0
        print("(登録済みリモートはありません。'dfssvc start' または 'dfscli join <url>' を実行してください)")
        if root_statuses:
            print("\n既定の root dfs:")
            for rst in root_statuses:
                state_tag = "online" if rst["online"] else "unreachable"
                reg_disp = rst["registry"] or "-"
                print(f"dfs://{rst['name']}/ -> {reg_disp} {rst['path']} [{state_tag}, unregistered]")
                detail_str = _format_remote_status_details(rst)
                if detail_str:
                    print(f"  status: {detail_str}")
                print(f"  参加するには: dfscli join dfs://{rst['name']}")
        return 0

    svc_store = ServiceStore()
    running_svcs = {n for n, s in svc_store.services.items() if s.is_running()}

    if no_check:
        statuses = {
            n: {
                "online": None,
                "l2_ok": None,
                "l2_error": "",
                "role": None,
                "root_anchor": "",
                "paths_count": None,
                "pubkey_match": None,
                "dnssec": None,
                "dnssec_record": "",
                "dnssec_error": "",
            }
            for n in names
        }
        root_statuses = []
    else:
        total_jobs = len(names) + len(builtin_roots_to_probe)
        with ThreadPoolExecutor(max_workers=min(8, max(1, total_jobs))) as pool:
            futs = {n: pool.submit(_probe_remote_status, store.remotes[n]) for n in names}
            root_futs = [pool.submit(_cm._probe_root_dfs_domain, d) for d in builtin_roots_to_probe]
            statuses = {n: futs[n].result() for n in names}
            root_statuses = [f.result() for f in root_futs]
    reachable = {n: statuses[n]["online"] for n in names}

    if getattr(args, "json", False):
        out = []
        for n in names:
            r = store.remotes[n]
            st = statuses[n]
            out.append({
                "name": n,
                "registered": True,
                "registry": r.registry,
                "path": r.path or "/",
                "read_only": bool(r.read_only),
                "online": st["online"],
                "dfssvc": n in running_svcs,
                "role": st["role"],
                "l2_ok": st["l2_ok"],
                "l2_error": st["l2_error"] or None,
                "root_anchor": st["root_anchor"] or None,
                "paths_count": st["paths_count"],
                "pubkey_match": st["pubkey_match"],
                "dnssec": st["dnssec"],
                "dnssec_record": st["dnssec_record"] or None,
                "dnssec_error": st["dnssec_error"] or None,
            })
        for rst in root_statuses:
            out.append(rst)
        print(json.dumps(out, ensure_ascii=False, indent=2))
        return 0

    if getattr(args, "prune", False):
        protected = set(svc_store.services) if not getattr(args, "all", False) else set(running_svcs)
        targets = [
            n for n in names
            if reachable[n] is False and n not in protected
        ]
        if not targets:
            skipped = [n for n in names if reachable[n] is False and n in protected]
            if skipped:
                print(
                    f"削除対象の unreachable リモートはありません（dfssvc 管理下を保護: {', '.join(skipped)}）。"
                )
            else:
                print("削除対象の unreachable リモートはありません。")
            return 0

        print("以下の unreachable リモートを削除します:")
        for n in targets:
            r = store.remotes[n]
            print(f"  - dfs://{n}/ ({r.registry} {r.path or '/'})")
        if not getattr(args, "yes", False):
            if not sys.stdin.isatty():
                raise _cm.UsageError("非対話環境で削除するには -y / --yes を付けてください")
            ans = input("削除してよろしいですか? [y/N]: ").strip().lower()
            if ans not in ("y", "yes"):
                print("中止しました")
                return 0
        for n in targets:
            store.delete(n)
        print(f"削除しました: {', '.join(targets)}")
        return 0

    first_online = None
    unreachable_count = 0
    for name in names:
        r = store.remotes[name]
        tags = []
        if reachable[name] is True:
            tags.append("online")
            if first_online is None:
                first_online = name
        elif reachable[name] is False:
            tags.append("unreachable")
            unreachable_count += 1
        tags.append("ro" if r.read_only else "rw")
        if name in running_svcs:
            tags.append("dfssvc")
        tag_str = ", ".join(tags)
        print(f"dfs://{name}/ -> {r.registry} {r.path or '/'} [{tag_str}]")
        detail_str = _format_remote_status_details(statuses[name])
        if detail_str:
            print(f"  status: {detail_str}")

    if root_statuses:
        print("\n既定の root dfs:")
        for rst in root_statuses:
            state_tag = "online" if rst["online"] else "unreachable"
            reg_disp = rst["registry"] or "-"
            print(f"dfs://{rst['name']}/ -> {reg_disp} {rst['path']} [{state_tag}, unregistered]")
            detail_str = _format_remote_status_details(rst)
            if detail_str:
                print(f"  status: {detail_str}")
            print(f"  参加するには: dfscli join dfs://{rst['name']}")

    hint_name = first_online or names[0]
    print(
        "\nScheme: dfs://<リモート名>/<パス>  (従来の <リモート名>:<パス> も利用可)\n"
        f"使い方例: dfscli ls dfs://{hint_name}/  /  dfscli copy ./file.txt dfs://{hint_name}/"
    )
    if unreachable_count:
        print("※ 到達できないリモートを削除するには: dfscli listremotes --prune")
    return 0

def cmd_config(args: argparse.Namespace) -> int:
    store = _cm.RemoteStore()
    if args.action == "create":
        dnssec_domain = getattr(args, "dnssec_domain", None)
        candidacy_urls = [
            value.strip()
            for value in (getattr(args, "candidacy_url", None) or [])
            if value.strip()
        ]
        candidacy_file = getattr(args, "candidacy_file", None)
        if dnssec_domain and (candidacy_urls or candidacy_file):
            raise _cm.UsageError("--dnssec-domain と --candidacy-url / --candidacy-file は併用できません")
        if not args.registry and not dnssec_domain and not candidacy_urls and not candidacy_file:
            raise _cm.UsageError(
                "config create には --registry、--dnssec-domain、--candidacy-url、--candidacy-file のいずれかが必要です"
            )

        discovery: Optional[Discovery] = None
        candidacy_mode = bool(candidacy_urls or candidacy_file)
        if dnssec_domain:
            try:
                discovery = _cm.discover_domain(
                    dnssec_domain,
                    record_name=getattr(args, "dnssec_name", None),
                    require_ad=not getattr(args, "dnssec_no_ad", False),
                    validate=not getattr(args, "dnssec_no_validate", False),
                )
            except DiscoveryError as e:
                raise _cm.UsageError(f"DNSSEC discovery に失敗しました: {e}") from e
            registry = discovery.primary_url
            registry_alternates = discovery.alternate_urls
            if args.registry:
                explicit = _cm.normalize_registry(args.registry, args.registry_port)
                if explicit != registry:
                    raise _cm.UsageError(
                        f"--registry ({explicit}) が DNSSEC discovery の primary "
                        f"({registry}) と一致しません"
                    )
            explicit_alts = [
                _cm.normalize_registry(value, args.registry_port)
                for value in (getattr(args, "registry_alternate", None) or [])
                if value.strip()
            ]
            if explicit_alts and explicit_alts != registry_alternates:
                raise _cm.UsageError(
                    "--registry-alternate が DNSSEC discovery の secondary 一覧と一致しません"
                )
        elif candidacy_mode:
            if not args.root_pubkey:
                raise _cm.UsageError(
                    "--candidacy-url / --candidacy-file を使うときは --root-pubkey が必須です"
                )
            expected_pub = _cm._read_root_pubkey_arg(args.root_pubkey)
            try:
                if candidacy_file:
                    env_data = json.loads(
                        Path(candidacy_file).expanduser().read_text(encoding="utf-8")
                    )
                    discovery = verify_candidacy_envelope(env_data, expected_pub)
                else:
                    discovery = fetch_candidacy(candidacy_urls, expected_pub)
            except (OSError, json.JSONDecodeError, CandidacyError) as e:
                raise _cm.UsageError(f"立候補情報の検証に失敗しました: {e}") from e
            registry = discovery.primary_url
            registry_alternates = discovery.alternate_urls
        else:
            registry = _cm.normalize_registry(args.registry, args.registry_port)
            registry_alternates = [
                _cm.normalize_registry(value, args.registry_port)
                for value in (getattr(args, "registry_alternate", None) or [])
                if value.strip()
            ]
        ost_alternates = [
            _cm.Remote.normalize_ost(value)
            for value in (getattr(args, "ost_alternate", None) or [])
            if value.strip()
        ]
        libp2p_peers = [
            value.strip()
            for value in (getattr(args, "libp2p_peer", None) or [])
            if value.strip()
        ]

        # --key が無ければ、その場で Ed25519 の鍵を作る。
        # 書き手の鍵は dfscli が初めて使うものなので、利用者に用意させない。
        key_path: Path
        created_key = False
        if args.key:
            key_path = Path(args.key).expanduser()
            if not key_path.is_file():
                raise _cm.UsageError(f"指定された書き手鍵がありません: {key_path}")
        else:
            key_dir = Path(args.key_dir).expanduser() if args.key_dir else (
                config_dir() / "keys"
            )
            key_dir.mkdir(parents=True, exist_ok=True)
            key_path = key_dir / f"{args.name}_ed25519"
            if not key_path.is_file():
                res = subprocess.run(
                    ["ssh-keygen", "-t", "ed25519", "-N", "",
                     "-C", f"dfscli-{args.name}@{socket.gethostname()}", "-f", str(key_path)],
                    capture_output=True, text=True,
                )
                if res.returncode != 0:
                    raise _cm.UsageError(f"鍵を作れませんでした: {res.stderr.strip()}")
                restrict_to_owner(key_path)
                created_key = True

        # root アンカーの公開鍵を決める（信頼の根）。
        #   --root-pubkey FILE があれば、その中身を使う（本番はこちら）。
        #   無ければ名簿から取り、指紋を表示して記録する（TOFU。初回だけ）。
        root_pubkey = ""
        root_fingerprint = ""
        root_source = "未取得"
        if discovery is not None:
            root_pubkey = discovery.root_pubkey
            root_fingerprint = _cm.ssh_key_fingerprint(root_pubkey)
            root_source = "署名付き立候補" if candidacy_mode else "DNSSEC"
            if args.root_pubkey:
                explicit_root = _cm._read_root_pubkey_arg(args.root_pubkey)
                if " ".join(explicit_root.split()) != " ".join(root_pubkey.split()):
                    raise _cm.UsageError(
                        f"--root-pubkey が {root_source} の root 公開鍵と一致しません"
                    )
        elif args.root_pubkey:
            root_pubkey = _cm._read_root_pubkey_arg(args.root_pubkey)
            root_fingerprint = _cm.ssh_key_fingerprint(root_pubkey)
            root_source = f"指定（{args.root_pubkey}）"
        else:
            registry_client = _cm.cli_mod.RemoteRegistryClient(
                [registry, *registry_alternates]
            )
            info = registry_client.root_anchor_info()
            root_pubkey = (info.get("root_pubkey") or "").strip()
            if root_pubkey:
                root_fingerprint = _cm.ssh_key_fingerprint(root_pubkey)
                root_source = "名簿から取得（初回 TOFU ピン留め）"

        ost_cert_sha256 = (getattr(args, "ost_cert_sha256", None) or "").strip().lower()
        if not ost_cert_sha256:
            try:
                ost_info = _cm.cli_mod.RemoteRegistryClient(
                    [registry, *registry_alternates]
                ).ost_info()
                selected_ost = args.ost or str(ost_info.get("endpoint") or "").strip()
                ost_cert_sha256 = _cm.matching_ost_cert_pin(selected_ost, ost_info)
            except Exception:
                ost_cert_sha256 = ""

        # --secret が無ければ端末から読む（エコーなし）。
        secret = args.secret
        secret_from_prompt = False
        if not secret and not args.no_prompt:
            secret = _cm.prompt_secret(
                f"{args.name} の tree_secret: ",
                f"{args.name} の tree_secret（確認のためもう一度）: ",
            )
            secret_from_prompt = bool(secret)

        effective_role_epoch = (
            int(discovery.epoch)
            if candidacy_mode and discovery is not None
            else int(getattr(args, "role_epoch", 1))
        )
        remote = _cm.Remote(
            name=args.name,
            registry=registry,
            registry_alternates=registry_alternates,
            key=str(key_path),
            ost=args.ost or "",
            ost_alternates=ost_alternates,
            libp2p_peers=libp2p_peers,
            libp2p_psk=getattr(args, "libp2p_psk", None) or "",
            path=_cm._normalize_path_arg(args.path),
            secret=secret or "",
            workdir=args.workdir or "",
            epoch=int(args.epoch),
            role_epoch=effective_role_epoch,
            compression=str(getattr(args, "compression", "auto") or "auto"),
            node_name=args.node_name or args.name,
            root_pubkey=root_pubkey,
            root_fingerprint=root_fingerprint,
            ost_cert_sha256=ost_cert_sha256,
            allow_tofu=bool(getattr(args, "allow_tofu", False)),
        )
        store.set(remote)
        print(f"[dfscli] リモート {remote.name!r} を保存しました: {store.path}")
        print(f"  registry    : {remote.registry}")
        if remote.registry_alternates:
            print(f"  代替名簿    : {', '.join(remote.registry_alternates)}")
        if created_key:
            print(f"  書き手の鍵  : {key_path}（作った。OpenSSH 形式の Ed25519）")
        else:
            print(f"  書き手の鍵  : {key_path}")
        print(f"  作業ディレクトリ: {remote.resolved_workdir()}")
        if remote.ost:
            print(f"  L3 OST      : {remote.ost}")
        else:
            print("  L3 OST      : （未指定。使うときに L2 のロケータから解決します）")
        if remote.ost_alternates:
            print(f"  複製 OST    : {', '.join(remote.ost_alternates)}")
        if remote.libp2p_peers:
            print(f"  libp2p peer : {', '.join(remote.libp2p_peers)}")
        if remote.path:
            print(f"  サブツリー  : {remote.path}")
        else:
            print("  サブツリー  : （未指定。使うときに L2 で書き手鍵から探します）")
        if remote.secret:
            how = "端末から読みました" if secret_from_prompt else "指定どおり"
            print(f"  tree_secret : *** （{how}）")
        else:
            print("  tree_secret : （未指定。書く前に設定してください）")
        if ost_cert_sha256:
            print(f"  OST 証明書ピン: {ost_cert_sha256}")
        if root_pubkey:
            print(f"  root アンカー: {root_fingerprint} （{root_source}）")
            print("                 これ以降この指紋だけを信頼します（違う値を返す名簿は拒否）")
        else:
            print("  root アンカー: （取得できませんでした。--root-pubkey で指定するか --allow-tofu を明示してください）")
        return 0

    if args.action == "delete":
        if store.delete(args.name):
            print(f"[dfscli] リモート {args.name!r} を削除しました")
            return 0
        raise _cm.UsageError(f"Unknown remote {args.name!r}")

    if args.action == "show":
        r = store.get(args.name)
        for key in ("name", "registry", "registry_alternates", "ost", "ost_alternates",
                    "ost_cert_sha256", "libp2p_peers", "libp2p_psk", "path", "key", "workdir",
                    "epoch", "role_epoch", "compression", "node_name", "root_fingerprint",
                    "allow_tofu"):
            value = getattr(r, key)
            if key in ("secret", "libp2p_psk"):
                value = "***"
            if key == "workdir":
                value = str(r.resolved_workdir())
            print(f"{key:{18}}: {value}")
        # root 公開鍵そのものは長いので、指紋だけ出す（--json を足す余地はある）
        if r.root_pubkey:
            algo = r.root_pubkey.split()[0] if r.root_pubkey.split() else "?"
            print(f"{'root_pubkey':{18}}: {algo} ...（指紋は上に表示）")
        else:
            print(f"{'root_pubkey':{18}}: （未取得）")
        return 0

    if args.action == "list":
        return cmd_listremotes(args)

    raise _cm.UsageError(f"Unknown config action: {args.action}")


def cmd_discover(args: argparse.Namespace) -> int:
    """DNSSEC の discovery レコードを表示する（設定は変更しない）。"""
    try:
        discovery = _cm.discover_domain(
            args.domain,
            record_name=args.dnssec_name,
            require_ad=not args.dnssec_no_ad,
            validate=not getattr(args, "dnssec_no_validate", False),
        )
    except DiscoveryError as e:
        raise _cm.UsageError(f"DNSSEC discovery に失敗しました: {e}") from e
    if args.json:
        print(json.dumps(discovery.raw, indent=2, sort_keys=True, ensure_ascii=False))
        return 0
    print(f"domain      : {discovery.domain}")
    print(f"root_anchor : {discovery.root_anchor}")
    print(f"root_pubkey : {_cm.ssh_key_fingerprint(discovery.root_pubkey)}")
    print(f"epoch       : {discovery.epoch}")
    print(f"ttl         : {discovery.ttl}")
    for row in discovery.registries:
        print(f"{row.role:10}: {row.url}")
    return 0


def cmd_candidacy(args: argparse.Namespace) -> int:
    """小規模運用向けの署名付き立候補レコードを作成・取得する。"""
    if args.action == "create":
        if not args.root_key or not args.primary:
            raise _cm.UsageError("candidacy create には --root-key と --primary が必要です")
        root_pub = _cm._read_root_pubkey_arg(args.root_pubkey)
        registries: List[Dict[str, str]] = [
            {"role": "primary", "url": _cm.normalize_registry(args.primary, args.registry_port)}
        ]
        for sec in (args.secondary or []):
            if sec.strip():
                registries.append(
                    {"role": "secondary", "url": _cm.normalize_registry(sec, args.registry_port)}
                )
        try:
            envelope = create_candidacy_envelope(
                args.root_key,
                args.root_anchor,
                root_pub,
                registries,
                epoch=int(args.epoch),
                ttl_days=int(args.ttl_days),
            )
        except (CandidacyError, ValueError) as e:
            raise _cm.UsageError(f"立候補レコードの生成に失敗しました: {e}") from e
        if args.out:
            out_path = Path(args.out).expanduser()
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(
                json.dumps(envelope, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
        for reg_url in (args.announce or []):
            if reg_url.strip():
                client = _cm.cli_mod.RemoteRegistryClient(_cm.normalize_registry(reg_url, args.registry_port))
                client.announce_candidacy(envelope)
        if args.json or not args.out:
            print(json.dumps(envelope, indent=2, sort_keys=True, ensure_ascii=False))
        return 0

    if args.action == "discover":
        root_pub = _cm._read_root_pubkey_arg(args.root_pubkey)
        urls = [
            _cm.normalize_registry(u, args.registry_port)
            for u in (args.url or [])
            if u.strip()
        ]
        try:
            discovery = fetch_candidacy(
                urls,
                root_pub,
                expected_root_anchor=args.root_anchor,
                min_epoch=args.min_epoch,
            )
        except CandidacyError as e:
            raise _cm.UsageError(f"立候補情報の取得・検証に失敗しました: {e}") from e
        if args.json:
            print(json.dumps(discovery.raw, indent=2, sort_keys=True, ensure_ascii=False))
            return 0
        print(f"root_anchor : {discovery.root_anchor}")
        print(f"root_pubkey : {_cm.ssh_key_fingerprint(discovery.root_pubkey)}")
        print(f"epoch       : {discovery.epoch}")
        print(f"ttl         : {discovery.ttl}")
        for row in discovery.registries:
            print(f"{row.role:10}: {row.url}")
        return 0

    raise _cm.UsageError(f"Unknown candidacy action: {args.action}")

def cmd_share(args: argparse.Namespace) -> int:
    """RunPod 等向けの 1 行ブートストラップコマンドを簡潔に発行する。"""
    store = _cm.RemoteStore()
    remote = store.get(args.remote)
    token = _cm._create_invite_token(args, remote)
    if getattr(args, "token_only", False):
        print(token)
        return 0
    bootstrap_url = getattr(args, "bootstrap_url", None) or _cm._default_bootstrap_url(remote)
    print(f"curl -sSL {bootstrap_url} | bash -s -- {token}")
    return 0


def cmd_invite(args: argparse.Namespace) -> int:
    """読み取り専用 / 出力委譲付きの招待トークンを作成・参加する（RunPod 等の使い捨て環境向け）。"""
    store = _cm.RemoteStore()
    if args.action == "create":
        if not args.target:
            raise _cm.UsageError("invite create にはリモート名が必要です")
        remote = store.get(args.target)
        token = _cm._create_invite_token(args, remote)
        if args.bootstrap_url:
            print(f"curl -sSL {args.bootstrap_url} | bash -s -- {token}")
        else:
            print(token)
        return 0

    if args.action == "join":
        if not args.target:
            raise _cm.UsageError("invite join には招待トークンが必要です")
        try:
            info = decode_invite(args.target)
        except InviteError as e:
            raise _cm.UsageError(f"招待トークンが不正です: {e}") from e

        registries = list(info["registries"])
        role_epoch = int(info["role_epoch"])
        if info.get("use_candidacy"):
            try:
                disc = fetch_candidacy(
                    registries,
                    info["root_pubkey"],
                    expected_root_anchor=None,
                    min_epoch=role_epoch,
                )
                registries = [disc.primary_url, *disc.alternate_urls]
                role_epoch = disc.epoch
            except CandidacyError as e:
                print(
                    f"[dfscli] warning: candidacy refresh skipped ({e})",
                    file=sys.stderr,
                )

        remote_name = (args.name or info["name"]).strip()
        workdir = str(Path(args.workdir).expanduser()) if args.workdir else ""
        invite_ost_pin = str(info.get("ost_cert_sha256") or "").strip().lower()
        if not invite_ost_pin and info.get("ost"):
            try:
                ost_info = _cm.cli_mod.RemoteRegistryClient(registries).ost_info()
                invite_ost_pin = _cm.matching_ost_cert_pin(info["ost"], ost_info)
            except Exception:
                invite_ost_pin = ""
        remote = _cm.Remote(
            name=remote_name,
            registry=registries[0],
            registry_alternates=registries[1:],
            key="",
            ost=info["ost"],
            ost_alternates=info["ost_alternates"],
            path=info["path"],
            secret=info["tree_secret"],
            workdir=workdir,
            role_epoch=role_epoch,
            node_name=remote_name,
            root_pubkey=info["root_pubkey"],
            root_fingerprint=_cm.ssh_key_fingerprint(info["root_pubkey"]),
            ost_cert_sha256=invite_ost_pin,
            read_only=True,
        )
        store.set(remote)
        print(f"[dfscli] 読み取り専用リモート {remote.name!r} を登録しました: {store.path}")

        write_info = info.get("write")
        if isinstance(write_info, dict):
            write_name = str(write_info.get("name") or "")
            if not _cm.NAME_RE.match(write_name):
                raise _cm.UsageError(
                    f"招待トークン内の write.name が不正です: {write_name!r}"
                )
            key_dir = (config_dir() / "keys").resolve()
            _cm.ensure_private_dir(key_dir)
            eph_key_path = (key_dir / f"{write_name}_ed25519").resolve()
            eph_pub_path = (key_dir / f"{write_name}_ed25519.pub").resolve()
            if (
                not eph_key_path.is_relative_to(key_dir)
                or not eph_pub_path.is_relative_to(key_dir)
            ):
                raise _cm.UsageError(
                    f"招待トークン内の write.name が鍵ディレクトリ外を指しています: {write_name!r}"
                )
            if eph_key_path.exists() or eph_pub_path.exists():
                raise _cm.UsageError(
                    f"既存の鍵ファイルが既に存在するため上書きを拒否しました: {eph_key_path}"
                )
            eph_key_path.write_text(write_info["priv_key"], encoding="utf-8")
            restrict_to_owner(eph_key_path)
            eph_pub_path.write_text(write_info["pub_key"] + "\n", encoding="utf-8")
            write_workdir = (
                str(Path(args.workdir).expanduser() / write_name)
                if args.workdir
                else ""
            )
            out_remote = _cm.Remote(
                name=write_name,
                registry=registries[0],
                registry_alternates=registries[1:],
                key=str(eph_key_path),
                ost=info["ost"],
                ost_alternates=info["ost_alternates"],
                path=write_info["path"],
                secret=info["tree_secret"],
                workdir=write_workdir,
                epoch=int(write_info["epoch"]),
                role_epoch=role_epoch,
                node_name=write_name,
                root_pubkey=info["root_pubkey"],
                root_fingerprint=_cm.ssh_key_fingerprint(info["root_pubkey"]),
                ost_cert_sha256=invite_ost_pin,
                read_only=False,
            )
            store.set(out_remote)
            print(
                f"[dfscli] 出力用リモート {out_remote.name!r} ({out_remote.path}, "
                f"epoch={out_remote.epoch}) を登録しました"
            )

        if args.sync or args.watch:
            node = _cm.open_remote(remote, create=True)
            dest = Path(args.dest).expanduser() if args.dest else remote.resolved_workdir() / "out"
            path_filter = _cm._path_filter(argparse.Namespace(include=[], exclude=[]))
            version, count = _cm._pull_once(
                node, remote, "", dest, path_filter, force=False
            )
            print(f"[dfscli] pull OK <- v{version} | {count} ファイル -> {dest}")
            if args.watch:
                poll = max(1, int(args.poll or info["poll_seconds"]))
                last_version = version
                try:
                    while True:
                        time.sleep(poll)
                        try:
                            latest = node.remote_version()
                        except Exception as e:  # noqa: BLE001
                            print(f"[dfscli] watch poll failed: {e}", file=sys.stderr)
                            continue
                        if latest > last_version:
                            version, count = _cm._pull_once(
                                node, remote, "", dest, path_filter, force=False
                            )
                            last_version = version
                            print(f"[dfscli] pull OK <- v{version} | {count} ファイル -> {dest}")
                except KeyboardInterrupt:
                    print("\n[dfscli] watch を終了します", file=sys.stderr)
        return 0

    raise _cm.UsageError(f"Unknown invite action: {args.action}")


def _detect_external_ip(timeout: float = 0.8) -> str:
    """外部 IP（取得できなければローカルの送出元 IP）を返す。"""
    import urllib.request

    try:
        with urllib.request.urlopen("https://api.ipify.org", timeout=timeout) as resp:
            ip_txt = resp.read().decode("utf-8", errors="ignore").strip()
            if ip_txt:
                return ip_txt
    except Exception:  # noqa: BLE001
        pass
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return str(s.getsockname()[0])
    except OSError:
        return "127.0.0.1"


def default_subtree_name(
    external_ip: Optional[str] = None,
    hostname: Optional[str] = None,
) -> str:
    """外部 IP とホスト名から決定的な URL-safe Base64 部分木名を生成する。"""
    import base64

    ext_ip = (external_ip if external_ip is not None else _cm._detect_external_ip()).strip()
    host = (hostname if hostname is not None else socket.gethostname()).strip()
    digest = hashlib.sha256(f"{ext_ip}\n{host}".encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest[:12]).decode("ascii").rstrip("=")


def cmd_join(args: argparse.Namespace) -> int:
    """別のドメイン / root ハブ / 招待 URI に後から参加する。"""
    target = str(args.target or "").strip()
    if not target:
        raise _cm.UsageError("参加先のドメイン・URL または招待 URI を指定してください")
    if target.startswith("dfs-invite://"):
        clean_target = target[len("dfs-invite://"):].lstrip("/")
        inv_args = argparse.Namespace(
            action="join",
            target=clean_target,
            name=args.name,
            workdir=getattr(args, "workdir", None),
            sync=getattr(args, "sync", False),
            dest=getattr(args, "dest", None),
            watch=False,
            poll=30,
            candidacy=True,
        )
        return cmd_invite(inv_args)

    if target.startswith("dfs://"):
        stripped = target[len("dfs://"):].lstrip("/")
        if stripped.startswith("dfs-ro-v1:") or stripped.startswith("dfs-rw-v1:"):
            inv_args = argparse.Namespace(
                action="join",
                target=stripped,
                name=args.name,
                workdir=getattr(args, "workdir", None),
                sync=getattr(args, "sync", False),
                dest=getattr(args, "dest", None),
                watch=False,
                poll=30,
                candidacy=True,
            )
            return cmd_invite(inv_args)
        target = stripped.split("/", 1)[0].rstrip(":")

    from urllib.parse import urlsplit
    from dfs.dnssec import DEFAULT_RECORD_PREFIX, has_txt_record
    from dfs.relay import discover_ice_candidates

    discovered = None
    if "://" not in target:
        if "." in target and ":" not in target and not target.startswith("["):
            rec_name = f"{DEFAULT_RECORD_PREFIX}.{target}"
            if has_txt_record(rec_name):
                try:
                    discovered = _cm.discover_domain(target, record_name=rec_name)
                except DiscoveryError as e:
                    raise _cm.UsageError(
                        f"{rec_name} に TXT レコードが存在するため DNSSEC 検証が必須ですが失敗しました: {e}"
                    ) from e
        if discovered is not None:
            base_url = discovered.primary_url
        else:
            base_url = f"http://{target}" if (":" in target and not target.startswith("[")) else f"https://{target}"
    else:
        base_url = target
    base_url = base_url.rstrip("/")
    parsed = urlsplit(base_url)
    host_label = parsed.hostname or "remote"

    # 0) L2 名簿への疎通確認
    urls = [base_url, *(list(discovered.alternate_urls) if discovered is not None else [])]
    reg_client = _cm.cli_mod.RemoteRegistryClient(urls)
    try:
        l2_info = reg_client.list_paths()
    except Exception as e:  # noqa: BLE001
        raise _cm.UsageError(f"L2 名簿 ({base_url}) への疎通確認に失敗しました: {e}") from e
    if discovered is not None:
        server_pub = str(l2_info.get("root_pubkey") or "").strip()
        if server_pub and discovered.root_pubkey and server_pub != discovered.root_pubkey:
            raise _cm.UsageError(
                f"L2 名簿 ({base_url}) の root_pubkey が DNSSEC 記録と一致しません"
            )

    # 1) /_ice/candidates から直接ピア候補を取得
    cands = discover_ice_candidates(base_url, timeout=2.0)
    direct_eps = [
        str(c["endpoint"])
        for c in cands
        if c.get("type") in ("host", "srflx") and c.get("endpoint")
    ]

    # 2) ローカルの dfssvc 設定があれば join 先を保存
    svc_name = getattr(args, "svc", None) or "local"
    svc_dir = Path.home() / "dfssvc" / svc_name
    cfg_file = svc_dir / "dfssvc.json"
    if svc_dir.is_dir():
        cfg: Dict[str, Any] = {}
        if cfg_file.is_file():
            try:
                loaded = json.loads(cfg_file.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    cfg = loaded
            except (OSError, ValueError, TypeError):
                cfg = {}
        cfg["join"] = base_url
        if not cfg.get("relay_node"):
            import socket as _sock

            cfg["relay_node"] = svc_name if svc_name != "local" else _sock.gethostname().split(".")[0]
        cfg_file.write_text(json.dumps(cfg, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"[dfscli] dfssvc ({svc_name}) の参加先を {base_url} に設定しました: {cfg_file}")

    # 3) --path / --secret または DNSSEC 自動発見があれば _cm.RemoteStore にリモートを登録
    if args.path or args.secret or discovered is not None:
        store = _cm.RemoteStore()
        remote_name = (args.name or (discovered.domain if discovered is not None else host_label)).strip()
        existing_remote = store.remotes.get(remote_name)
        key_value = str(args.key or "")
        if not key_value and existing_remote is not None and existing_remote.key:
            key_value = existing_remote.key
        if not key_value:
            from dfs import svc as svc_mod

            svc_rec = svc_mod.ServiceStore().services.get(remote_name)
            if svc_rec is not None and svc_rec.writer_key and Path(svc_rec.writer_key).expanduser().is_file():
                key_value = svc_rec.writer_key
            elif remote_name == svc_name:
                cand_writer = svc_dir / "keys" / "writer"
                if cand_writer.is_file():
                    key_value = str(cand_writer)
        secret_value = str(args.secret or "")
        if not secret_value and existing_remote is not None and existing_remote.secret:
            secret_value = existing_remote.secret
        primary_ost = direct_eps[0] if direct_eps else ""
        alt_osts = direct_eps[1:] if len(direct_eps) > 1 else []
        base_anchor = discovered.root_anchor if discovered is not None else f"/{host_label}"
        if args.path:
            remote_path = str(args.path)
        elif key_value:
            anchor_clean = base_anchor.rstrip("/")
            subtree_label = default_subtree_name()
            if anchor_clean.endswith(f"/{subtree_label}"):
                remote_path = anchor_clean or f"/{subtree_label}"
            else:
                remote_path = f"{anchor_clean}/{subtree_label}"
        else:
            remote_path = base_anchor
        join_ost_pin = existing_remote.ost_cert_sha256 if existing_remote is not None else ""
        if not join_ost_pin:
            try:
                ost_info = _cm.cli_mod.RemoteRegistryClient([base_url]).ost_info()
                selected_ost = primary_ost or str(ost_info.get("endpoint") or "").strip()
                join_ost_pin = _cm.matching_ost_cert_pin(selected_ost, ost_info)
            except Exception:
                join_ost_pin = ""

        explicit_root_arg = getattr(args, "root_pubkey", None)
        explicit_root = _cm._read_root_pubkey_arg(explicit_root_arg) if explicit_root_arg else ""
        join_root_pub = ""
        join_root_source = "未取得"
        if discovered is not None:
            join_root_pub = discovered.root_pubkey
            join_root_source = "DNSSEC"
            if explicit_root and " ".join(explicit_root.split()) != " ".join(join_root_pub.split()):
                raise _cm.UsageError(
                    "--root-pubkey が DNSSEC の root 公開鍵と一致しません"
                )
        elif explicit_root:
            server_root = str(l2_info.get("root_pubkey") or "").strip()
            if server_root and " ".join(explicit_root.split()) != " ".join(server_root.split()):
                raise _cm.UsageError(
                    "--root-pubkey が L2 名簿の root 公開鍵と一致しません"
                )
            join_root_pub = explicit_root
            join_root_source = f"指定（{explicit_root_arg}）"
        elif existing_remote is not None and existing_remote.root_pubkey:
            join_root_pub = existing_remote.root_pubkey
            join_root_source = "既存リモート設定を引き継ぎ"
        else:
            join_root_pub = str(l2_info.get("root_pubkey") or "").strip()
            if join_root_pub:
                join_root_source = "名簿から取得（初回 TOFU ピン留め）"
        join_root_fp = _cm.ssh_key_fingerprint(join_root_pub) if join_root_pub else ""
        join_allow_tofu = bool(getattr(args, "allow_tofu", False)) or (
            bool(existing_remote.allow_tofu) if existing_remote is not None else False
        )

        remote = _cm.Remote(
            name=remote_name,
            registry=base_url,
            registry_alternates=list(discovered.alternate_urls) if discovered is not None else [],
            key=key_value,
            ost=primary_ost,
            ost_alternates=alt_osts,
            path=remote_path,
            secret=secret_value,
            role_epoch=int(discovered.epoch) if discovered is not None else 1,
            node_name=remote_name,
            root_pubkey=join_root_pub,
            root_fingerprint=join_root_fp,
            ost_cert_sha256=join_ost_pin,
            allow_tofu=join_allow_tofu,
            read_only=not bool(key_value),
        )
        store.set(remote)
        if existing_remote is not None and (
            existing_remote.path != remote.path
            or (
                remote.root_pubkey
                and existing_remote.root_pubkey
                and existing_remote.root_pubkey != remote.root_pubkey
            )
        ):
            _cm._reset_workdir_pin(remote.resolved_workdir().expanduser())
        print(f"[dfscli] リモート {remote.name!r} を登録しました: {store.path}")
        if join_root_pub:
            print(f"  root アンカー: {join_root_fp} （{join_root_source}）")
            if join_root_source.startswith("名簿から取得"):
                print("                 名簿由来の初回 TOFU として記録しました（--root-pubkey で事前固定できます）")
            print("                 これ以降この指紋だけを信頼します（違う値を返す名簿は拒否）")
        else:
            print("  root アンカー: （取得できませんでした。--root-pubkey で指定するか --allow-tofu を明示してください）")
        if key_value:
            try:
                writer_pub = _cm.public_key_of(Path(key_value).expanduser())
            except _cm.UsageError:
                writer_pub = ""
            if writer_pub:
                rows = l2_info.get("paths")
                already = isinstance(rows, list) and any(
                    isinstance(r, dict)
                    and r.get("path") == remote.path
                    and str(r.get("writer") or "").strip() == writer_pub
                    for r in rows
                )
                auto_fn = getattr(reg_client, "auto_delegate", None)
                if not already and callable(auto_fn):
                    try:
                        auto_fn(remote.path, writer_pub)
                        print(f"[dfscli] L2 自動委譲を登録しました: {remote.path}")
                    except Exception as e:  # noqa: BLE001
                        print(
                            f"[dfscli] warning: L2 自動委譲に失敗しました ({e})。"
                            "必要に応じて手動で dfscli delegate を実行してください",
                            file=sys.stderr,
                        )

    print(f"[dfscli] join 対象: {base_url}")
    anchor_info = str(l2_info.get("root_anchor") or "").strip() or "/"
    print(f"[dfscli] L2 疎通確認 OK: {base_url} (anchor={anchor_info})")
    if direct_eps:
        print(f"[dfscli] 発見した直接 OST 候補 ({len(direct_eps)} 件): {', '.join(direct_eps)}")
    if svc_dir.is_dir():
        from dfs import svc as svc_mod

        svc_store = svc_mod.ServiceStore()
        running_svc = svc_store.services.get(svc_name)
        if running_svc is not None and (
            running_svc.is_running() or svc_mod._recorded_server_is_alive(running_svc)
        ):
            print(f"[dfscli] 稼働中の dfssvc ({svc_name}) を再起動して参加先を反映します...")
            rc_svc = svc_mod.main(["start", "--name", svc_name, "--force"])
            if rc_svc != 0:
                print(
                    f"[dfscli] warning: dfssvc の自動再起動に失敗しました (code={rc_svc})。"
                    f"手動で 'dfssvc start --name {svc_name} --force' を実行してください",
                    file=sys.stderr,
                )
        else:
            print(f"[dfscli] 反映するには 'dfssvc start --name {svc_name} --force' を実行してください")
    return 0


def cmd_quit(args: argparse.Namespace) -> int:
    """参加中のドメインから安全に離脱し、ローカル単独モードへ戻す。"""
    svc_name = getattr(args, "svc", None) or "local"
    svc_dir = Path.home() / "dfssvc" / svc_name
    cfg_file = svc_dir / "dfssvc.json"
    prev_join = ""
    cleared_svc = False

    if cfg_file.is_file():
        try:
            cfg = json.loads(cfg_file.read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError):
            cfg = {}
        if isinstance(cfg, dict):
            prev_join = str(cfg.get("join") or "")
            if prev_join or cfg.get("relay_node") or cfg.get("relay_token"):
                cfg["join"] = ""
                cfg["relay_node"] = ""
                cfg["relay_token"] = ""
                cfg_file.write_text(
                    json.dumps(cfg, ensure_ascii=False, indent=2) + "\n",
                    encoding="utf-8",
                )
                cleared_svc = True
                print(f"[dfscli] dfssvc ({svc_name}) の参加設定 ({prev_join or 'relay'}) を解除しました")

    store = _cm.RemoteStore()
    targets: List[str] = []
    if getattr(args, "name", None):
        targets.append(str(args.name).strip())
    elif getattr(args, "all", False) and prev_join:
        norm_prev = prev_join.rstrip("/")
        for rname in store.names():
            r = store.get(rname)
            if r.registry.rstrip("/") == norm_prev:
                targets.append(rname)

    removed_remotes: List[str] = []
    for rname in targets:
        if rname not in store.names():
            continue
        r = store.get(rname)
        if r.workdir:
            cache_file = Path(r.workdir).expanduser() / ".clayfs" / "transport_cache.json"
            if cache_file.is_file():
                try:
                    cache_file.unlink()
                except OSError:
                    pass
        if store.delete(rname):
            removed_remotes.append(rname)
            print(f"[dfscli] リモート {rname!r} と接続キャッシュを削除しました")

    if not cleared_svc and not removed_remotes:
        print("[dfscli] 離脱対象のドメイン設定・リモートは見つかりませんでした")
    elif cleared_svc:
        print(f"[dfscli] 反映するには 'dfssvc start --name {svc_name} --force' を実行してください")
    return 0

def cmd_delegate(args: argparse.Namespace) -> int:
    _cm.cli_mod.cmd_delegate(args)
    return 0


# ==========================================
# 引数の組み立て
# ==========================================
