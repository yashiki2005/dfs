"""Archive bundle / BitTorrent subcommands (``dfscli archive``)."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, Optional, Tuple


def _archive_registry_context(
    store: Any,
    remote: Any,
    version: Optional[int],
) -> Tuple[str, Dict[str, Any], Dict[str, Any]]:
    """ローカル設定を起点に、L2公開descriptorと対応L4 headを検証して返す。"""
    from dfs import cli_main as _cm
    from dfs import cli as cli_mod

    registry = cli_mod.RemoteRegistryClient(remote.registry_urls())
    path = _cm.resolve_path(remote, registry)
    if not remote.root_pubkey:
        if not remote.allow_tofu:
            raise _cm.UsageError(
                f"Remote {remote.name!r} has no root_pubkey and allow_tofu=False; "
                "pass --root-pubkey or --allow-tofu when creating the remote"
            )
        info = registry.root_anchor_info()
        root_pubkey = str(info.get("root_pubkey", "") or "").strip()
        if not root_pubkey:
            raise _cm.UsageError(
                f"Registry {remote.registry} did not provide a root public key; "
                "pass --root-pubkey when creating the remote"
            )
        remote.root_pubkey = root_pubkey
        remote.root_fingerprint = _cm.ssh_key_fingerprint(root_pubkey)
        store.set(remote)

    entries = registry.archives(path, version=version)
    if not entries:
        label = f"v{version}" if version is not None else "latest"
        raise _cm.UsageError(f"No published archive descriptor for {path!r} ({label})")

    pubkey = _cm.public_key_of(Path(remote.key).expanduser()) if remote.key else ""
    verifier = _cm.L4LogClient(
        path,
        remote.key,
        pubkey,
        pin_file=None,
        root_pubkey=remote.root_pubkey,
    )
    candidates = sorted(
        (
            envelope
            for envelope in entries
            if isinstance(envelope, dict)
            and isinstance(envelope.get("payload"), dict)
            and isinstance(envelope["payload"].get("version"), int)
            and (
                version is None
                or int(envelope["payload"]["version"]) == int(version)
            )
        ),
        key=lambda envelope: int(envelope["payload"]["version"]),
        reverse=True,
    )
    if not candidates:
        raise _cm.UsageError("Registry returned only malformed archive descriptors")

    last_error: Optional[BaseException] = None
    for selected in candidates:
        selected_version = int(selected["payload"]["version"])
        try:
            head, delegation, _locator = verifier.resolve_verified(
                registry, version=selected_version
            )
            leaf = _cm.verify_delegation_chain(
                root_anchor_path=str(delegation.get("root_anchor") or ""),
                root_anchor_pubkey=remote.root_pubkey,
                chain=list(delegation.get("chain") or []),
                now=int(head["payload"]["timestamp"]),
                requested_path=path,
            )
            _cm.verify_archive_descriptor(
                selected,
                path,
                str(leaf["writer"]),
                head_log=head,
            )
            return path, selected, head
        except _cm.ServiceUnavailableError:
            raise
        except Exception as e:  # noqa: BLE001 - 名簿の候補ごとに検証して不正候補を読み飛ばす
            last_error = e
    raise _cm.UsageError(
        f"すべてのpublished archive descriptorを検証できません: {last_error}"
    )


def _resolve_archive_trust_args(args: argparse.Namespace, action_label: str) -> Tuple[Optional[str], Optional[str]]:
    from .. import cli_core as _cm

    exp_pub = getattr(args, "root_pubkey", None)
    exp_fp = getattr(args, "root_fingerprint", None)
    allow_embedded = bool(getattr(args, "allow_embedded_root", False))
    if exp_pub:
        pub_p = Path(exp_pub).expanduser()
        if pub_p.is_file():
            exp_pub = pub_p.read_text(encoding="utf-8").strip()
    if not exp_pub and not exp_fp and not allow_embedded:
        raise _cm.UsageError(
            f"archive {action_label} には --root-pubkey または --root-fingerprint が必要です"
            "（自己整合性のみ確認する場合は --allow-embedded-root を指定してください）"
        )
    return exp_pub, exp_fp


def cmd_archive(args: argparse.Namespace) -> int:
    """版単位の archive bundle / torrent を作成・公開・取得・復元する。"""
    from dfs import cli_main as _cm
    from dfs import cli as cli_mod

    if args.action == "create":
        store = _cm.RemoteStore()
        name, _sub = _cm.split_remote_spec(args.source, args.remote_name)
        remote = store.get(name)
        node = _cm.open_remote(remote, create=False)
        out = (
            Path(args.out).expanduser()
            if args.out
            else Path.cwd() / f"dfs-archive-{remote.name}-{int(time.time())}"
        )
        from dfs import archive as _arch_mod, cli_core as _cc

        find_par2 = (
            _cc.find_par2_binary
            if _cm.find_par2_binary is _arch_mod.find_par2_binary
            else _cm.find_par2_binary
        )
        recovery_arg = getattr(args, "recovery", None)
        missing_par2_notice = False
        if recovery_arg is None:
            if find_par2():
                recovery_percent = 5
            else:
                recovery_percent = 0
                missing_par2_notice = True
        else:
            recovery_percent = int(recovery_arg)
            if recovery_percent < 0 or recovery_percent > 100:
                raise _cm.UsageError("--recovery は 0〜100 の整数で指定してください")
            if recovery_percent > 0 and not find_par2():
                raise _cm.UsageError(
                    "par2 が見つかりません（macOS: brew install par2 / Ubuntu: sudo apt install par2）"
                )
        try:
            result = _cm.create_archive(
                node,
                out,
                announce=args.announce,
                version=args.version,
                keep_dir=bool(getattr(args, "keep_dir", False)),
                recovery_percent=recovery_percent,
                archive_format=str(getattr(args, "format", "zstd:chunked") or "zstd:chunked"),
            )
        except _cm.ArchiveError as e:
            raise _cm.UsageError(f"archive create に失敗しました: {e}") from e
        if missing_par2_notice:
            print(
                "[dfscli] ヒント: par2 が入っていれば 5% のリカバリレコード付き"
                "（*.tar.zst.par2）にできます（例: brew install par2 / apt install par2）",
                file=sys.stderr,
            )
        if result.bundle.is_dir():
            print(f"archive     : {result.bundle}")
        if result.tarball is not None:
            print(f"tarball     : {result.tarball}")
        if result.par2_files:
            print(
                f"par2        : {result.par2_files[0]} "
                f"({len(result.par2_files)} files, {recovery_percent}%)"
            )
        if result.readme is not None:
            print(f"readme      : {result.readme}")
        print(f"torrent     : {result.torrent}")
        print(f"descriptor  : {result.descriptor}")
        print(f"infohash    : {result.infohash}")
        print(f"version     : v{result.version}")
        print(f"chunks      : {result.chunk_count}")
        print(
            f"magnet      : magnet:?xt=urn:btih:{result.infohash}"
            f"&dn={result.bundle.name}"
        )
        if args.publish:
            registry = cli_mod.RemoteRegistryClient(remote.registry_urls())
            registry.publish_archive(
                result.descriptor_envelope,
                role_epoch=int(remote.role_epoch),
            )
            print(
                f"published   : {remote.registry} "
                f"{remote.path or node.sub_path} v{result.version}"
            )
        return 0

    if args.action == "catalog":
        try:
            rows = _cm.catalog(Path(args.source).expanduser())
        except _cm.ArchiveError as e:
            raise _cm.UsageError(f"archive catalog に失敗しました: {e}") from e
        for row in rows:
            print(
                f"{row.get('path', '?')} v{row.get('version', '?')} "
                f"{row.get('infohash', '?')} {row.get('bundle', '')}"
            )
        return 0

    if args.action == "publish":
        if not args.remote_name:
            raise _cm.UsageError("archive publish には --remote NAME が必要です")
        store = _cm.RemoteStore()
        remote = store.get(args.remote_name)
        bundle = Path(args.source).expanduser()
        base_str = str(bundle)
        for ext in (".tar.zst", ".tar.gz", ".tgz", ".tar"):
            if base_str.endswith(ext):
                descriptor_path = Path(base_str[: -len(ext)] + ".archive.json")
                break
        else:
            descriptor_path = bundle.with_suffix(".archive.json")
        try:
            descriptor = json.loads(descriptor_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            raise _cm.UsageError(
                f"archive descriptor を読めません: {descriptor_path}: {e}"
            ) from e
        envelope = (
            descriptor.get("descriptor_envelope")
            if isinstance(descriptor, dict)
            else None
        )
        if not isinstance(envelope, dict):
            raise _cm.UsageError(
                "この bundle には署名済みdescriptorがありません。作成し直してください"
            )
        registry = cli_mod.RemoteRegistryClient(remote.registry_urls())
        verified = registry.publish_archive(
            envelope, role_epoch=int(remote.role_epoch)
        )
        print(
            f"published   : {remote.registry} "
            f"{verified['path']} v{verified['version']}"
        )
        return 0

    bundle = Path(args.source).expanduser()
    if args.action == "verify":
        exp_pub, exp_fp = _resolve_archive_trust_args(args, "verify")
        try:
            meta = _cm.verify_bundle(
                bundle,
                expected_root_pubkey=exp_pub,
                expected_root_fingerprint=exp_fp,
            )
        except _cm.ArchiveError as e:
            raise _cm.UsageError(f"archive verify に失敗しました: {e}") from e
        print(f"archive     : {bundle}")
        print(f"version     : v{meta['version']}")
        print(f"chunks      : {len(meta['chunks'])}")
        print(f"root_fp     : {meta.get('root_fingerprint') or '(unknown)'}")
        print("signatures  : OK")
        return 0

    if args.action == "extract":
        if not args.dest:
            raise _cm.UsageError("archive extract には出力先が必要です")
        exp_pub, exp_fp = _resolve_archive_trust_args(args, "extract")
        secret = args.secret
        if not secret and not args.no_prompt:
            secret = _cm.prompt_secret("tree_secret: ", "tree_secret（確認）: ")
        if not secret:
            raise _cm.UsageError("archive extract には --secret が必要です")
        try:
            out = _cm.extract_bundle(
                bundle,
                Path(args.dest).expanduser(),
                secret,
                expected_root_pubkey=exp_pub,
                expected_root_fingerprint=exp_fp,
            )
        except _cm.ArchiveError as e:
            raise _cm.UsageError(f"archive extract に失敗しました: {e}") from e
        print(f"extracted   : {out}")
        return 0

    if args.action == "fetch":
        store = _cm.RemoteStore()
        name, _sub = _cm.split_remote_spec(args.source, args.remote_name)
        remote = store.get(name)
        try:
            path, descriptor, _head = _archive_registry_context(
                store, remote, args.version
            )
        except _cm.ArchiveError as e:
            raise _cm.UsageError(
                f"archive descriptor の検証に失敗しました: {e}"
            ) from e
        payload = descriptor["payload"]
        version = int(payload["version"])
        out = (
            Path(args.out).expanduser()
            if args.out
            else Path.cwd() / f"dfs-fetch-{remote.name}-v{version}"
        )
        if int(args.torrent_timeout) <= 0:
            raise _cm.UsageError("--torrent-timeout は正の秒数にしてください")
        magnet = _cm.magnet_for_descriptor(payload)
        print(
            f"[dfscli] archive fetch: {path} v{version} "
            f"infohash={payload['infohash'][:12]}..."
        )
        try:
            _cm.download_torrent(
                magnet,
                out,
                torrent_client=args.torrent_client,
                timeout=int(args.torrent_timeout),
            )
            bundle = _cm.locate_downloaded_bundle(out, descriptor)
            meta = _cm.verify_bundle(
                bundle,
                expected_root_pubkey=remote.root_pubkey or None,
            )
        except _cm.ArchiveError as e:
            raise _cm.UsageError(f"archive fetch に失敗しました: {e}") from e
        print(f"archive     : {bundle}")
        print(f"verified    : v{meta['version']} ({len(meta['chunks'])} chunks)")
        if args.dest:
            secret = args.secret or remote.secret
            if not secret and not args.no_prompt:
                secret = _cm.prompt_secret("tree_secret: ", "tree_secret（確認）: ")
            if not secret:
                raise _cm.UsageError("archive fetch --dest には tree_secret が必要です")
            try:
                restored = _cm.extract_bundle(
                    bundle,
                    Path(args.dest).expanduser(),
                    secret,
                    expected_root_pubkey=remote.root_pubkey or None,
                )
            except _cm.ArchiveError as e:
                raise _cm.UsageError(
                    f"archive fetch の復号に失敗しました: {e}"
                ) from e
            print(f"extracted   : {restored}")
        return 0

    raise _cm.UsageError(f"unknown archive action: {args.action}")
