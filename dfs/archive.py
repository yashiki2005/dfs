#!/usr/bin/env python3
"""版単位の読み取り専用 archive bundle と BitTorrent torrents。

BitTorrent は「現在の OST を置き換えるもの」ではなく、版のチャンクと署名済み
メタデータをまとめて長期保存・配布するための層として使う。torrent の内容は
DFS の wire_id（SHA-256）で再検証する。
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Sequence, Tuple

from .crypto import (
    NS_L4_LOG,
    ContentAddressedCrypto,
    canonical_json,
    normalize_path,
    sha256_hex,
    ssh_verify,
)
from .l1_delegation import verify_delegation_chain
from .l2_registry import verify_locator_envelope
from .l4_log import MerkleTreeBuilder

ARCHIVE_SCHEMA = "dfs-archive-v1"
DEFAULT_PIECE_LENGTH = 256 * 1024
CHUNK_GROUP = 128


class ArchiveError(ValueError):
    """archive bundle の作成・検証・復元エラー。"""


def bencode(value: Any) -> bytes:
    """最小限の bencode エンコーダ（torrent の info 用）。"""
    if isinstance(value, int):
        return b"i" + str(value).encode("ascii") + b"e"
    if isinstance(value, str):
        value = value.encode("utf-8")
    if isinstance(value, bytes):
        return str(len(value)).encode("ascii") + b":" + value
    if isinstance(value, (list, tuple)):
        return b"l" + b"".join(bencode(item) for item in value) + b"e"
    if isinstance(value, dict):
        items = []
        for key, item in value.items():
            key_bytes = key.encode("utf-8") if isinstance(key, str) else key
            items.append((key_bytes, item))
        items.sort(key=lambda pair: pair[0])
        return b"d" + b"".join(
            bencode(key) + bencode(item) for key, item in items
        ) + b"e"
    raise TypeError(f"Cannot bencode {type(value).__name__}")


def _safe_name(value: str) -> str:
    text = value.strip("/").replace("/", "-")
    text = "".join(ch if ch.isalnum() or ch in ".-_" else "-" for ch in text)
    return text or "root"


def _chunk_paths(bundle: Path, wire_ids: Sequence[str]) -> List[Path]:
    return [bundle / "chunks" / wid for wid in wire_ids]


def _write_torrent(
    bundle: Path,
    torrent_path: Path,
    name: str,
    announce: Optional[str],
) -> str:
    files: List[Path] = [bundle / "meta.json"]
    files.extend(sorted((bundle / "chunks").glob("*"), key=lambda p: p.name))
    piece_length = DEFAULT_PIECE_LENGTH
    pieces = bytearray()
    pending = bytearray()
    file_rows = []
    for path in files:
        rel = path.relative_to(bundle)
        data = path.read_bytes()
        file_rows.append({"length": len(data), "path": list(rel.parts)})
        pending.extend(data)
        while len(pending) >= piece_length:
            pieces.extend(hashlib.sha1(pending[:piece_length]).digest())
            del pending[:piece_length]
    if pending:
        pieces.extend(hashlib.sha1(bytes(pending)).digest())

    info = {
        "files": file_rows,
        "name": name,
        "piece length": piece_length,
        "pieces": bytes(pieces),
    }
    torrent: Dict[str, Any] = {"info": info}
    if announce:
        torrent["announce"] = announce
    raw = bencode(torrent)
    torrent_path.write_bytes(raw)
    return hashlib.sha1(bencode(info)).hexdigest()


def _fetch_chunks(node: Any, wire_ids: Sequence[str]) -> Dict[str, bytes]:
    result: Dict[str, bytes] = {}
    with node.read_ost.session():
        for start in range(0, len(wire_ids), CHUNK_GROUP):
            group = list(wire_ids[start : start + CHUNK_GROUP])
            result.update(node.read_ost.batch_get(group))
    return result


@dataclass(frozen=True)
class ArchiveResult:
    bundle: Path
    torrent: Path
    descriptor: Path
    infohash: str
    version: int
    chunk_count: int


def create_archive(
    node: Any,
    out_dir: Path | str,
    *,
    announce: Optional[str] = None,
    version: Optional[int] = None,
) -> ArchiveResult:
    """指定版（省略時は先頭版）を、署名済みメタデータ + 全チャンク + torrent として保存する。"""
    bundle = Path(out_dir).expanduser()
    if bundle.exists() and any(bundle.iterdir()):
        raise ArchiveError(f"Archive output is not empty: {bundle}")
    try:
        head, del_env, loc_env = node.l4.resolve_verified(
            node.registry, version=version
        )
    except Exception as e:  # noqa: BLE001
        raise ArchiveError(f"Cannot resolve archive version: {e}") from e
    node.refresh_read_ost()
    if not del_env or not del_env.get("chain"):
        raise ArchiveError("No verified delegation chain for the current version")
    if not node.l4.root_pubkey:
        raise ArchiveError("root_pubkey is required to create a self-verifying archive")

    p = head["payload"]
    root_pid, root_wid = p["root_plain_id"], p["root_wire_id"]
    entries = node.read_builder.list_tree(
        root_pid, root_wid, root_store=getattr(node, "root_store", None)
    )
    plain_by_wire: Dict[str, str] = {root_wid: root_pid}
    for entry in entries:
        wid = str(entry.get("wire_id", ""))
        if wid:
            plain_by_wire[wid] = str(entry.get("plain_id", ""))
    wire_ids = sorted(wid for wid in plain_by_wire if wid)
    blobs = _fetch_chunks(node, wire_ids)

    bundle.mkdir(parents=True, exist_ok=True)
    chunks_dir = bundle / "chunks"
    chunks_dir.mkdir(parents=True, exist_ok=True)
    chunk_rows = []
    for wid in wire_ids:
        blob = blobs.get(wid)
        if blob is None:
            raise ArchiveError(f"Missing chunk from OST: {wid}")
        if sha256_hex(blob) != wid:
            raise ArchiveError(f"Chunk hash mismatch: {wid}")
        (chunks_dir / wid).write_bytes(blob)
        chunk_rows.append(
            {"plain_id": plain_by_wire.get(wid, ""), "size": len(blob), "wire_id": wid}
        )

    meta = {
        "schema": ARCHIVE_SCHEMA,
        "path": node.sub_path,
        "version": int(p["version"]),
        "root_plain_id": root_pid,
        "root_wire_id": root_wid,
        "root_anchor": del_env.get("root_anchor", ""),
        "root_pubkey": node.l4.root_pubkey or "",
        "delegation": del_env,
        "locator": loc_env,
        "head_log": head,
        "chunks": sorted(chunk_rows, key=lambda row: row["wire_id"]),
    }
    meta_bytes = json.dumps(
        meta, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8") + b"\n"
    (bundle / "meta.json").write_bytes(meta_bytes)

    torrent = bundle.with_suffix(".torrent")
    name = (
        f"dfs-{_safe_name(node.sub_path)}-v{int(p['version'])}-"
        f"{sha256_hex(meta_bytes)[:12]}"
    )
    infohash = _write_torrent(bundle, torrent, name, announce)
    descriptor = bundle.with_suffix(".archive.json")
    descriptor.write_text(
        json.dumps(
            {
                "schema": "dfs-archive-descriptor-v1",
                "bundle": str(bundle),
                "created_at": int(time.time()),
                "head_hash": head.get("entry_hash", ""),
                "infohash": infohash,
                "path": node.sub_path,
                "root_wire_id": root_wid,
                "torrent": str(torrent),
                "version": int(p["version"]),
            },
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        ) + "\n",
        encoding="utf-8",
    )
    return ArchiveResult(
        bundle=bundle,
        torrent=torrent,
        descriptor=descriptor,
        infohash=infohash,
        version=int(p["version"]),
        chunk_count=len(wire_ids),
    )


def catalog(directory: Path | str) -> List[Dict[str, Any]]:
    """``create_archive`` が作った descriptor を一覧する。"""
    root = Path(directory).expanduser()
    if not root.exists():
        raise ArchiveError(f"Archive catalog directory does not exist: {root}")
    rows: List[Dict[str, Any]] = []
    for item in sorted(root.glob("*.archive.json")):
        try:
            data = json.loads(item.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(data, dict):
            data["descriptor"] = str(item)
            rows.append(data)
    rows.sort(key=lambda row: (str(row.get("path", "")), int(row.get("version", 0))))
    return rows


def _load_meta(bundle: Path) -> Dict[str, Any]:
    meta_path = bundle / "meta.json"
    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        raise ArchiveError(f"Cannot read {meta_path}: {e}") from e
    if not isinstance(meta, dict) or meta.get("schema") != ARCHIVE_SCHEMA:
        raise ArchiveError("Invalid archive schema")
    return meta


def verify_bundle(bundle: Path | str) -> Dict[str, Any]:
    """bundle のチャンクと、含まれる L1/L2/L4 署名を検証する。"""
    root = Path(bundle).expanduser()
    meta = _load_meta(root)
    try:
        path = normalize_path(str(meta.get("path", "")))
    except ValueError as e:
        raise ArchiveError(f"Invalid archive path: {e}") from e
    root_anchor = str(meta.get("root_anchor", ""))
    root_pubkey = str(meta.get("root_pubkey", "")).strip()
    if not root_anchor:
        raise ArchiveError("Archive has no root_anchor")
    delegation = meta.get("delegation")
    head = meta.get("head_log")
    locator = meta.get("locator")
    if not root_pubkey:
        raise ArchiveError("Archive has no root_pubkey; cannot verify trust")
    if not isinstance(delegation, dict) or not isinstance(head, dict):
        raise ArchiveError("Archive is missing delegation or head_log")
    chain = delegation.get("chain") or []
    if not chain:
        raise ArchiveError("Archive delegation has no chain")
    head_payload = head.get("payload", {})
    try:
        historical_now = int(head_payload["timestamp"])
    except (KeyError, TypeError, ValueError) as e:
        raise ArchiveError("Archive head has no valid timestamp") from e
    try:
        leaf = verify_delegation_chain(
            root_anchor_path=root_anchor,
            root_anchor_pubkey=root_pubkey,
            chain=chain,
            now=historical_now,
            requested_path=path,
        )
    except Exception as e:  # noqa: BLE001 - L1/L2 の例外型をまとめて扱う
        raise ArchiveError(f"Archive delegation verification failed: {e}") from e
    raw = canonical_json(head_payload)
    if sha256_hex(raw) != head.get("entry_hash"):
        raise ArchiveError("Archive head entry_hash mismatch")
    if not ssh_verify(
        leaf["writer"], path, NS_L4_LOG, raw, str(head.get("signature", ""))
    ):
        raise ArchiveError("Archive head signature is invalid")
    if (
        str(meta.get("root_plain_id", "")) != str(head_payload.get("root_plain_id", ""))
        or str(meta.get("root_wire_id", "")) != str(head_payload.get("root_wire_id", ""))
    ):
        raise ArchiveError("Archive root ids do not match the signed head")
    if locator is not None:
        try:
            loc_p = verify_locator_envelope(
                locator, path, leaf["writer"], historical_now
            )
        except Exception as e:  # noqa: BLE001
            raise ArchiveError(f"Archive locator verification failed: {e}") from e
        if (
            int(loc_p["head_version"]) != int(head_payload["version"])
            or loc_p["head_hash"] != head["entry_hash"]
        ):
            raise ArchiveError("Archive locator does not match head")

    chunks = meta.get("chunks")
    if not isinstance(chunks, list):
        raise ArchiveError("Archive chunks list is invalid")
    seen = set()
    for row in chunks:
        if not isinstance(row, dict):
            raise ArchiveError("Invalid archive chunk row")
        wid = str(row.get("wire_id", ""))
        if not wid or wid in seen:
            raise ArchiveError(f"Invalid or duplicate archive chunk: {wid!r}")
        seen.add(wid)
        chunk_path = root / "chunks" / wid
        try:
            blob = chunk_path.read_bytes()
        except OSError as e:
            raise ArchiveError(f"Missing archive chunk {wid}: {e}") from e
        if len(blob) != int(row.get("size", -1)):
            raise ArchiveError(f"Archive chunk size mismatch: {wid}")
        if sha256_hex(blob) != wid:
            raise ArchiveError(f"Archive chunk hash mismatch: {wid}")
    return meta


class _BundleOST:
    """archive bundle を読み取り専用 OST として見せるクライアント。"""

    def __init__(self, bundle: Path):
        self.bundle = bundle
        self.host = "archive"
        self.port = 0
        self.bytes_sent = 0
        self.bytes_received = 0
        self.blob_bytes_sent = 0
        self.round_trips = 0
        self.tls_handshakes = 0
        self.put_count = 0
        self.get_count = 0

    def reset_metrics(self) -> None:
        self.bytes_sent = 0
        self.bytes_received = 0
        self.blob_bytes_sent = 0
        self.round_trips = 0
        self.tls_handshakes = 0
        self.put_count = 0
        self.get_count = 0

    @contextmanager
    def session(self) -> Iterator["_BundleOST"]:
        yield self

    def batch_has(self, wire_ids: Sequence[str]) -> Dict[str, bool]:
        return {wid: (self.bundle / "chunks" / wid).is_file() for wid in wire_ids}

    def batch_get(self, wire_ids: Sequence[str]) -> Dict[str, bytes]:
        result = {}
        for wid in wire_ids:
            result[wid] = (self.bundle / "chunks" / wid).read_bytes()
            self.bytes_received += len(result[wid])
            self.get_count += 1
        return result

    def get(self, wire_id: str) -> bytes:
        return self.batch_get([wire_id])[wire_id]

    def batch_put_if_absent(self, chunks: Dict[str, bytes], assume_absent: bool = False) -> int:
        raise ArchiveError("Archive bundle is read-only")

    def put_if_absent(self, wire_id: str, blob: bytes) -> bool:
        raise ArchiveError("Archive bundle is read-only")


def extract_bundle(bundle: Path | str, dest: Path | str, tree_secret: str) -> Path:
    """archive bundle を復号してローカルディレクトリへ展開する。"""
    meta = verify_bundle(bundle)
    root = Path(bundle).expanduser()
    out = Path(dest).expanduser()
    local_ost = _BundleOST(root)
    builder = MerkleTreeBuilder(ContentAddressedCrypto(tree_secret), local_ost)
    builder.download_directory(
        str(meta["root_plain_id"]), str(meta["root_wire_id"]), out
    )
    return out
