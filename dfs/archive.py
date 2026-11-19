#!/usr/bin/env python3
"""版単位の読み取り専用 archive bundle と BitTorrent torrents。

BitTorrent は「現在の OST を置き換えるもの」ではなく、版のチャンクと署名済み
メタデータをまとめて長期保存・配布するための層として使う。torrent の内容は
DFS の wire_id（SHA-256）で再検証する。
"""

from __future__ import annotations

import hashlib
import json
import shutil
import struct
import subprocess
import tarfile
import tempfile
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Sequence, Tuple

from .crypto import (
    KDF_LEGACY_SHA256,
    NS_ARCHIVE,
    NS_L4_LOG,
    ContentAddressedCrypto,
    CryptoError,
    SignatureVerificationError,
    canonical_json,
    normalize_kdf_version,
    normalize_path,
    sha256_hex,
    ssh_sign,
    ssh_verify,
)
from .l1_delegation import verify_delegation_chain
from .l2_registry import verify_locator_envelope
from .l4_log import MerkleTreeBuilder

ARCHIVE_SCHEMA = "dfs-archive-v1"
DEFAULT_PIECE_LENGTH = 256 * 1024
CHUNK_GROUP = 128
ARCHIVE_DESCRIPTOR_SCHEMA = "dfs-archive-descriptor-v1"


class ArchiveError(ValueError):
    """archive bundle の作成・検証・復元エラー。"""


def _valid_infohash(value: str) -> bool:
    return (
        len(value) == 40
        and value == value.lower()
        and all(ch in "0123456789abcdef" for ch in value)
    )


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
    descriptor_envelope: Dict[str, Any]
    infohash: str
    version: int
    chunk_count: int
    tarball: Optional[Path] = None
    par2_files: Tuple[Path, ...] = ()
    readme: Optional[Path] = None


def _build_archive_readme(
    *,
    bundle_name: str,
    sub_path: str,
    version: int,
    chunk_count: int,
    tarball_name: str,
    archive_format: str,
    par2_names: Sequence[str],
    descriptor_name: str,
    torrent_name: str,
    readme_name: str,
) -> str:
    """アーカイブの利用・検証・復元手順をまとめた README テキストを生成する。"""
    par2_section = (
        f"  - {par2_names[0]} (+ {len(par2_names) - 1} volume(s)): PAR2 修復データ\n"
        if par2_names
        else "  - (PAR2 修復データなし / not generated)\n"
    )
    par2_verify_cmd = (
        f"  par2 verify {par2_names[0]}\n"
        f"  # 破損時は修復:\n"
        f"  par2 repair {par2_names[0]}\n"
        if par2_names
        else "  # (PAR2 なし)\n"
    )
    unpack_cmd = (
        f"  tar --zstd -xf {tarball_name}\n"
        f"  # または (if tar lacks --zstd):\n"
        f"  zstd -d {tarball_name} -o {bundle_name}.tar && tar -xf {bundle_name}.tar"
        if archive_format != "tar.gz"
        else f"  tar -xzf {tarball_name}"
    )
    return (
        f"DFS Archive Bundle: {bundle_name}\n"
        f"{'=' * (20 + len(bundle_name))}\n\n"
        f"Subtree : {sub_path}\n"
        f"Version : v{version}\n"
        f"Chunks  : {chunk_count}\n"
        f"Format  : {archive_format}\n\n"
        f"1. 同梱ファイル / Included Files\n"
        f"--------------------------------\n"
        f"  - {tarball_name} : アーカイブ本体 (meta.json + chunks/*)\n"
        f"{par2_section}"
        f"  - {readme_name} : この説明書\n"
        f"  - {descriptor_name} : 署名付きアーカイブ記述子 (catalog/publish 用)\n"
        f"  - {torrent_name} : BitTorrent メタデータ\n\n"
        f"2. 破損チェック・修復 / Verify & Repair (PAR2)\n"
        f"----------------------------------------------\n"
        f"{par2_verify_cmd}\n"
        f"3. DFS リモートへ復元 / Restore into DFS Remote\n"
        f"-----------------------------------------------\n"
        f"アーカイブ内のチャンクは元の tree_secret で暗号化されています。\n"
        f"復元には元のツリーの tree_secret（または同じ秘密鍵を設定したリモート）が必要です。\n\n"
        f"  dfscli import {tarball_name} <remote>:/ --source-secret <tree_secret>\n\n"
        f"4. ローカルで展開・検証 / Local Verify & Extract\n"
        f"------------------------------------------------\n"
        f"tarball を展開して中身の整合性検証やファイル抽出を行う場合:\n\n"
        f"{unpack_cmd}\n"
        f"  dfscli archive verify {bundle_name} --secret <tree_secret>\n"
        f"  dfscli archive extract {bundle_name} ./restored --secret <tree_secret>\n"
    )


def find_par2_binary() -> Optional[str]:
    """利用可能な par2 CLI バイナリを返す。"""
    return shutil.which("par2") or shutil.which("par2create")


def _par2_matching_files(par2_index: Path, target_name: str) -> List[Path]:
    stem = f"{target_name}."
    return sorted(
        p
        for p in par2_index.parent.iterdir()
        if p.is_file() and p.name.startswith(stem) and p.name.endswith(".par2")
    )


def create_par2_recovery(
    target_file: Path,
    *,
    redundancy: int = 5,
    par2_bin: Optional[str] = None,
) -> Tuple[Path, ...]:
    """対象ファイルに対する PAR2 リカバリファイル群を生成する。"""
    if redundancy < 1 or redundancy > 100:
        raise ArchiveError("PAR2 redundancy must be between 1 and 100")
    exe = par2_bin or find_par2_binary()
    if not exe:
        raise ArchiveError(
            "par2 command not found (install with `brew install par2` or `apt install par2`)"
        )
    target = Path(target_file).expanduser().resolve()
    if not target.is_file():
        raise ArchiveError(f"PAR2 target file does not exist: {target}")
    par2_index = target.with_name(f"{target.name}.par2")
    for old in _par2_matching_files(par2_index, target.name):
        old.unlink()
    cmd = [exe, "c", "-q", f"-r{redundancy}", "-n1", "--", par2_index.name, target.name]
    try:
        res = subprocess.run(
            cmd,
            cwd=str(target.parent),
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as e:
        raise ArchiveError(f"Cannot run par2: {e}") from e
    if res.returncode != 0:
        detail = (res.stderr or res.stdout).strip()
        raise ArchiveError(f"par2 create failed (exit {res.returncode}): {detail}")
    vol_prefix = f"{target.name}.vol"
    vol_files = sorted(
        p
        for p in target.parent.iterdir()
        if p.is_file() and p.name.startswith(vol_prefix) and p.name.endswith(".par2")
    )
    if vol_files:
        with par2_index.open("ab") as out_f:
            for vol in vol_files:
                with vol.open("rb") as in_f:
                    shutil.copyfileobj(in_f, out_f, length=1024 * 1024)
                vol.unlink()
    return (par2_index,) if par2_index.is_file() else ()


def verify_with_par2(
    par2_index: Path,
    *,
    par2_bin: Optional[str] = None,
) -> None:
    """PAR2 リカバリファイルで対象ファイルを検証する。"""
    exe = par2_bin or find_par2_binary()
    if not exe:
        raise ArchiveError("par2 command not found")
    idx = Path(par2_index).expanduser().resolve()
    if not idx.is_file():
        raise ArchiveError(f"PAR2 index file not found: {idx}")
    res = subprocess.run(
        [exe, "v", "-q", "--", idx.name],
        cwd=str(idx.parent),
        capture_output=True,
        text=True,
        check=False,
    )
    if res.returncode != 0:
        detail = (res.stderr or res.stdout).strip()
        raise ArchiveError(f"par2 verify failed (exit {res.returncode}): {detail}")


def repair_with_par2(
    target_file: Path,
    par2_index: Path,
    work_dir: Path,
    *,
    par2_bin: Optional[str] = None,
) -> Path:
    """作業ディレクトリへコピーした上で PAR2 による修復を試みる。"""
    exe = par2_bin or find_par2_binary()
    if not exe:
        raise ArchiveError("par2 command not found")
    target = Path(target_file).expanduser().resolve()
    idx = Path(par2_index).expanduser().resolve()
    if not target.is_file() or not idx.is_file():
        raise ArchiveError("PAR2 target or index file is missing")
    work_dir.mkdir(parents=True, exist_ok=True)
    work_target = work_dir / target.name
    shutil.copy2(target, work_target)
    for par_file in _par2_matching_files(idx, target.name):
        shutil.copy2(par_file, work_dir / par_file.name)
    res = subprocess.run(
        [exe, "r", "-q", "--", idx.name],
        cwd=str(work_dir),
        capture_output=True,
        text=True,
        check=False,
    )
    if res.returncode != 0:
        detail = (res.stderr or res.stdout).strip()
        raise ArchiveError(f"par2 repair failed (exit {res.returncode}): {detail}")
    return work_target


def magnet_for_descriptor(payload: Dict[str, Any]) -> str:
    """署名済みdescriptorから、外部BTクライアントへ渡すmagnet linkを作る。"""
    infohash = str(payload.get("infohash", ""))
    if not _valid_infohash(infohash):
        raise ArchiveError(f"Invalid archive infohash: {infohash!r}")
    name = str(payload.get("bundle_name", "dfs-archive"))
    magnet = f"magnet:?xt=urn:btih:{infohash}&dn={name}"
    announce = str(payload.get("announce", "") or "")
    if announce:
        from urllib.parse import quote

        magnet += f"&tr={quote(announce, safe='')}"
    return magnet


def create_archive_descriptor_envelope(
    writer_priv_key: Path | str,
    path: str,
    *,
    version: int,
    infohash: str,
    head_hash: str,
    root_wire_id: str,
    bundle_name: str,
    created_at: Optional[int] = None,
    announce: Optional[str] = None,
) -> Dict[str, Any]:
    """L2へ公開する、書き手署名付きarchive descriptorを作る。

    infohashはDHT上のpeer探索にだけ使う。どの版が正しいかはhead_hash、
    root_wire_id、L1/L4署名で決める。
    """
    norm_path = normalize_path(path)
    if not _valid_infohash(infohash):
        raise ArchiveError(f"Invalid archive infohash: {infohash!r}")
    payload = {
        "announce": str(announce or ""),
        "bundle_name": str(bundle_name),
        "created_at": int(time.time() if created_at is None else created_at),
        "head_hash": str(head_hash),
        "infohash": infohash,
        "path": norm_path,
        "root_wire_id": str(root_wire_id),
        "schema": ARCHIVE_DESCRIPTOR_SCHEMA,
        "version": int(version),
    }
    raw = canonical_json(payload)
    try:
        signature = ssh_sign(writer_priv_key, NS_ARCHIVE, raw)
    except SignatureVerificationError as e:
        raise ArchiveError(str(e)) from e
    return {"payload": payload, "signature": signature}


def verify_archive_descriptor(
    envelope: Dict[str, Any],
    expected_path: str,
    writer_pubkey: str,
    *,
    head_log: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """descriptorの署名と、対象L4 headへの束縛を検証する。"""
    if not isinstance(envelope, dict):
        raise ArchiveError("Malformed archive descriptor")
    payload = envelope.get("payload")
    signature = envelope.get("signature")
    if not isinstance(payload, dict) or not isinstance(signature, str):
        raise ArchiveError("Malformed archive descriptor")
    if payload.get("schema") != ARCHIVE_DESCRIPTOR_SCHEMA:
        raise ArchiveError("Unsupported archive descriptor schema")
    norm_path = normalize_path(expected_path)
    if payload.get("path") != norm_path:
        raise ArchiveError(
            f"Archive descriptor path mismatch: expected {norm_path!r}, "
            f"got {payload.get('path')!r}"
        )
    if not _valid_infohash(str(payload.get("infohash", ""))):
        raise ArchiveError("Archive descriptor has an invalid infohash")
    try:
        version = int(payload["version"])
        created_at = int(payload["created_at"])
    except (KeyError, TypeError, ValueError) as e:
        raise ArchiveError("Archive descriptor has invalid numeric fields") from e
    if version < 1 or created_at < 0:
        raise ArchiveError("Archive descriptor has invalid version or timestamp")
    raw = canonical_json(payload)
    if not ssh_verify(writer_pubkey, norm_path, NS_ARCHIVE, raw, signature):
        raise ArchiveError("Invalid archive descriptor signature")

    if head_log is not None:
        head_payload = head_log.get("payload", {})
        if str(payload["head_hash"]) != str(head_log.get("entry_hash", "")):
            raise ArchiveError("Archive descriptor does not match the L4 entry hash")
        if version != int(head_payload.get("version", -1)):
            raise ArchiveError("Archive descriptor version does not match the L4 head")
        if str(payload["root_wire_id"]) != str(
            head_payload.get("root_wire_id", "")
        ):
            raise ArchiveError("Archive descriptor root_wire_id does not match the L4 head")
    return payload


def _write_single_file_torrent(
    target_file: Path,
    torrent_path: Path,
    announce: Optional[str],
) -> str:
    piece_length = DEFAULT_PIECE_LENGTH
    pieces = bytearray()
    with target_file.open("rb") as fh:
        while True:
            chunk = fh.read(piece_length)
            if not chunk:
                break
            pieces.extend(hashlib.sha1(chunk).digest())
    info = {
        "length": target_file.stat().st_size,
        "name": target_file.name,
        "piece length": piece_length,
        "pieces": bytes(pieces),
    }
    torrent: Dict[str, Any] = {"info": info}
    if announce:
        torrent["announce"] = announce
    torrent_path.write_bytes(bencode(torrent))
    return hashlib.sha1(bencode(info)).hexdigest()


def _write_files_torrent(
    target_files: Sequence[Path],
    torrent_path: Path,
    name: str,
    announce: Optional[str],
) -> str:
    if len(target_files) == 1:
        return _write_single_file_torrent(target_files[0], torrent_path, announce)
    piece_length = DEFAULT_PIECE_LENGTH
    pieces = bytearray()
    pending = bytearray()
    file_rows = []
    for path in target_files:
        file_rows.append({"length": path.stat().st_size, "path": [path.name]})
        with path.open("rb") as fh:
            while True:
                chunk = fh.read(piece_length)
                if not chunk:
                    break
                pending.extend(chunk)
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
    torrent_path.write_bytes(bencode(torrent))
    return hashlib.sha1(bencode(info)).hexdigest()


ZSTD_SKIPPABLE_TOC_MAGIC = 0x184D2A50
ZSTD_SKIPPABLE_FOOTER_MAGIC = 0x184D2A5F


def _require_zstd() -> Any:
    try:
        import zstandard as zstd
    except ImportError as e:  # pragma: no cover
        raise ArchiveError(
            "zstandard is required for zstd:chunked archives (pip install zstandard)"
        ) from e
    return zstd


def write_zstd_chunked_tar(bundle: Path, out_path: Path) -> Dict[str, Any]:
    """``bundle`` ディレクトリを zstd:chunked 形式（独立 Zstd フレーム + TOC Skippable Frame）の tar.zst へ書き出す。"""
    zstd = _require_zstd()
    bundle = Path(bundle)
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    c_meta = zstd.ZstdCompressor(level=3)
    c_chunk = zstd.ZstdCompressor(level=1)
    toc_entries: List[Dict[str, Any]] = []
    uncompressed_offset = 0

    items: List[Path] = [bundle]
    for p in sorted(bundle.rglob("*"), key=lambda x: str(x.relative_to(bundle))):
        items.append(p)

    with out_path.open("wb") as fout:
        for item in items:
            rel = item.relative_to(bundle.parent).as_posix()
            st = item.stat()
            ti = tarfile.TarInfo(rel)
            ti.mtime = int(st.st_mtime)
            if item.is_dir():
                ti.type = tarfile.DIRTYPE
                ti.mode = 0o755
                ti.size = 0
                raw_entry = ti.tobuf(tarfile.USTAR_FORMAT)
                compressed = c_meta.compress(raw_entry)
                frame_off = fout.tell()
                fout.write(compressed)
                toc_entries.append({
                    "name": rel,
                    "type": "dir",
                    "size": 0,
                    "offset": frame_off,
                    "compressed_size": len(compressed),
                    "uncompressed_offset": uncompressed_offset,
                    "payload_offset_in_frame": len(raw_entry),
                })
                uncompressed_offset += len(raw_entry)
            elif item.is_file():
                file_size = st.st_size
                ti.type = tarfile.REGTYPE
                ti.mode = 0o644
                ti.size = file_size
                hdr = ti.tobuf(tarfile.USTAR_FORMAT)
                pad_len = (-file_size) % 512
                raw_entry_len = len(hdr) + file_size + pad_len

                comp = c_meta if item.name == "meta.json" else c_chunk
                frame_off = fout.tell()
                compressor_obj = comp.compressobj(size=raw_entry_len)
                compressed_len = 0

                # 1. ヘッダーを圧縮して出力
                out_chunk = compressor_obj.compress(hdr)
                if out_chunk:
                    fout.write(out_chunk)
                    compressed_len += len(out_chunk)

                # 2. ファイル本体をバッファ単位でストリーミング圧縮
                with item.open("rb") as fin:
                    while True:
                        buf = fin.read(64 * 1024)
                        if not buf:
                            break
                        out_chunk = compressor_obj.compress(buf)
                        if out_chunk:
                            fout.write(out_chunk)
                            compressed_len += len(out_chunk)

                # 3. パディング (512 バイト境界アラインメント)
                if pad_len > 0:
                    out_chunk = compressor_obj.compress(b"\x00" * pad_len)
                    if out_chunk:
                        fout.write(out_chunk)
                        compressed_len += len(out_chunk)

                # 4. Zstd フレームの終端フラッシュ
                out_chunk = compressor_obj.flush(zstd.COMPRESSOBJ_FLUSH_FINISH)
                if out_chunk:
                    fout.write(out_chunk)
                    compressed_len += len(out_chunk)

                toc_entries.append({
                    "name": rel,
                    "type": "file",
                    "size": file_size,
                    "offset": frame_off,
                    "compressed_size": compressed_len,
                    "uncompressed_offset": uncompressed_offset,
                    "payload_offset_in_frame": len(hdr),
                })
                uncompressed_offset += raw_entry_len

        # Standard tar EOF 1024 zero bytes in its own frame
        fout.write(c_meta.compress(b"\x00" * 1024))

        toc_payload = {
            "version": 1,
            "format": "zstd:chunked",
            "entries": toc_entries,
        }
        toc_bytes = json.dumps(
            toc_payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        toc_offset = fout.tell()
        fout.write(struct.pack("<II", ZSTD_SKIPPABLE_TOC_MAGIC, len(toc_bytes)))
        fout.write(toc_bytes)
        fout.write(struct.pack("<IIQ", ZSTD_SKIPPABLE_FOOTER_MAGIC, 8, toc_offset))

    return toc_payload


def read_zstd_chunked_toc(archive_path: Path | str) -> Dict[str, Any]:
    """``zstd:chunked`` アーカイブ末尾の Skippable Frame から TOC を O(1) で読み取る。"""
    path = Path(archive_path)
    size = path.stat().st_size
    if size < 24:
        raise ArchiveError(f"Not a zstd:chunked archive (too small): {path}")
    with path.open("rb") as fh:
        fh.seek(size - 16)
        footer = fh.read(16)
        magic, flen, toc_offset = struct.unpack("<IIQ", footer)
        if magic != ZSTD_SKIPPABLE_FOOTER_MAGIC or flen != 8 or toc_offset >= size - 16:
            raise ArchiveError(f"Missing zstd:chunked TOC footer: {path}")
        fh.seek(toc_offset)
        hdr = fh.read(8)
        if len(hdr) != 8:
            raise ArchiveError(f"Truncated zstd:chunked TOC header: {path}")
        toc_magic, toc_len = struct.unpack("<II", hdr)
        if toc_magic != ZSTD_SKIPPABLE_TOC_MAGIC or toc_offset + 8 + toc_len != size - 16:
            raise ArchiveError(f"Invalid zstd:chunked TOC frame: {path}")
        raw_toc = fh.read(toc_len)
    try:
        toc = json.loads(raw_toc.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise ArchiveError(f"Invalid zstd:chunked TOC JSON: {e}") from e
    if not isinstance(toc, dict) or toc.get("format") != "zstd:chunked":
        raise ArchiveError(f"Invalid zstd:chunked TOC payload: {path}")
    return toc


def extract_zstd_chunked_member(archive_path: Path | str, member_name: str) -> bytes:
    """TOC を使って ``zstd:chunked`` アーカイブから単一メンバーだけをシーク復号して取り出す。"""
    zstd = _require_zstd()
    path = Path(archive_path)
    toc = read_zstd_chunked_toc(path)
    norm_target = member_name.strip().lstrip("./")
    if not norm_target:
        raise ArchiveError("member_name must not be empty")

    entries = [e for e in (toc.get("entries") or []) if isinstance(e, dict)]
    matched_entry: Optional[Dict[str, Any]] = None

    # 1. 完全一致 (例: bundle_name/meta.json または bundle_name 相対)
    for entry in entries:
        ename = str(entry.get("name") or "").strip().lstrip("./")
        if ename == norm_target:
            matched_entry = entry
            break

    # 2. トップレベルディレクトリ（バンドル名）を剥がしたパスとの完全一致
    #    例: ename が "dfs-archive/meta.json" で norm_target が "meta.json"
    #        ename が "dfs-archive/chunks/abc" で norm_target が "chunks/abc"
    if matched_entry is None:
        exact_subpath_matches = []
        for entry in entries:
            ename = str(entry.get("name") or "").strip().lstrip("./")
            parts = ename.split("/", 1)
            if len(parts) == 2 and parts[1] == norm_target:
                exact_subpath_matches.append(entry)
        if len(exact_subpath_matches) == 1:
            matched_entry = exact_subpath_matches[0]
        elif len(exact_subpath_matches) > 1:
            raise ArchiveError(f"Ambiguous member name in archive: {member_name}")

    # 3. フォールバック: パス末尾との完全一致 (ただし一意であること)
    if matched_entry is None:
        suffix_matches = []
        for entry in entries:
            ename = str(entry.get("name") or "").strip().lstrip("./")
            if ename.endswith(f"/{norm_target}"):
                suffix_matches.append(entry)
        if len(suffix_matches) == 1:
            matched_entry = suffix_matches[0]
        elif len(suffix_matches) > 1:
            raise ArchiveError(f"Ambiguous member name in archive (multiple matches): {member_name}")

    if matched_entry is None:
        raise ArchiveError(f"Member not found in zstd:chunked archive: {member_name}")

    if matched_entry.get("type") != "file":
        raise ArchiveError(f"Member is not a file: {member_name}")

    off = int(matched_entry["offset"])
    clen = int(matched_entry["compressed_size"])
    poff = int(matched_entry["payload_offset_in_frame"])
    psize = int(matched_entry["size"])
    if off < 0 or clen <= 0 or poff < 0 or psize < 0:
        raise ArchiveError(f"Invalid zstd:chunked TOC offsets for {member_name}")
    file_size = path.stat().st_size
    if off + clen > file_size:
        raise ArchiveError(f"zstd:chunked TOC entry out of bounds for {member_name}")
    with path.open("rb") as fh:
        fh.seek(off)
        compressed = fh.read(clen)
    max_frame_bytes = max(poff + psize, 64 * 1024 * 1024)
    raw_frame = zstd.ZstdDecompressor().decompress(compressed, max_output_size=max_frame_bytes)
    if len(raw_frame) < poff + psize:
        raise ArchiveError(f"Truncated zstd:chunked frame for {member_name}")
    return raw_frame[poff : poff + psize]


def create_archive(
    node: Any,
    out_dir: Path | str,
    *,
    announce: Optional[str] = None,
    version: Optional[int] = None,
    keep_dir: bool = True,
    recovery_percent: int = 0,
    archive_format: str = "zstd:chunked",
) -> ArchiveResult:
    """指定版（省略時は先頭版）を、署名済みメタデータ + 全チャンク + torrent + zstd:chunked (.tar.zst) として保存する。"""
    raw_out = Path(out_dir).expanduser()
    fmt = str(archive_format or "zstd:chunked").strip().lower()
    if raw_out.name.endswith(".tar.gz"):
        fmt = "tar.gz"
        tarball = raw_out
        bundle = raw_out.with_name(raw_out.name[:-7] or "dfs-archive")
    elif raw_out.name.endswith(".tgz"):
        fmt = "tar.gz"
        tarball = raw_out
        bundle = raw_out.with_name(raw_out.name[:-4] or "dfs-archive")
    elif raw_out.name.endswith(".tar.zst"):
        fmt = "zstd:chunked"
        tarball = raw_out
        bundle = raw_out.with_name(raw_out.name[:-8] or "dfs-archive")
    elif raw_out.name.endswith(".tzst"):
        fmt = "zstd:chunked"
        tarball = raw_out
        bundle = raw_out.with_name(raw_out.name[:-5] or "dfs-archive")
    else:
        bundle = raw_out
        ext = ".tar.gz" if fmt == "tar.gz" else ".tar.zst"
        tarball = bundle.parent / f"{bundle.name}{ext}"
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
        root_pid,
        root_wid,
        root_store=getattr(node, "root_store", None) or getattr(node.builder, "root_store", None),
    )
    plain_by_wire: Dict[str, str] = {root_wid: root_pid}
    for entry in entries:
        for chunk in entry.get("chunks") or [entry]:
            wid = str(chunk.get("wire_id", ""))
            if wid:
                plain_by_wire[wid] = str(chunk.get("plain_id", ""))
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
        "kdf": node.crypto.kdf_version,
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
    if fmt == "tar.gz":
        with tarfile.open(tarball, "w:gz") as tf:
            tf.add(bundle, arcname=bundle.name)
    else:
        write_zstd_chunked_tar(bundle, tarball)
    par2_files: Tuple[Path, ...] = ()
    if recovery_percent > 0:
        par2_files = create_par2_recovery(tarball, redundancy=recovery_percent)
    descriptor = bundle.with_suffix(".archive.json")
    readme_file = bundle.with_name(f"{bundle.name}.README.txt")
    readme_text = _build_archive_readme(
        bundle_name=bundle.name,
        sub_path=node.sub_path,
        version=int(p["version"]),
        chunk_count=len(wire_ids),
        tarball_name=tarball.name,
        archive_format=fmt,
        par2_names=[pf.name for pf in par2_files],
        descriptor_name=descriptor.name,
        torrent_name=torrent.name,
        readme_name=readme_file.name,
    )
    readme_file.write_text(readme_text, encoding="utf-8")
    if keep_dir:
        (bundle / "README.txt").write_text(readme_text, encoding="utf-8")
        infohash = _write_torrent(bundle, torrent, name, announce)
    else:
        shutil.rmtree(bundle)
        torrent_targets = [tarball, *par2_files, readme_file]
        infohash = _write_files_torrent(torrent_targets, torrent, bundle.name, announce)
    descriptor_envelope = create_archive_descriptor_envelope(
        node.l4.priv_key_path,
        node.sub_path,
        version=int(p["version"]),
        infohash=infohash,
        head_hash=str(head.get("entry_hash", "")),
        root_wire_id=root_wid,
        bundle_name=name if keep_dir else tarball.name,
        created_at=int(time.time()),
        announce=announce,
    )
    descriptor.write_text(
        json.dumps(
            {
                "schema": "dfs-archive-descriptor-v1",
                "bundle": str(bundle if keep_dir else tarball),
                "created_at": int(time.time()),
                "descriptor_envelope": descriptor_envelope,
                "head_hash": head.get("entry_hash", ""),
                "infohash": infohash,
                "path": node.sub_path,
                "readme": str(readme_file),
                "root_wire_id": root_wid,
                "tarball": str(tarball),
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
        bundle=bundle if keep_dir else tarball,
        torrent=torrent,
        descriptor=descriptor,
        descriptor_envelope=descriptor_envelope,
        infohash=infohash,
        version=int(p["version"]),
        chunk_count=len(wire_ids),
        tarball=tarball,
        par2_files=par2_files,
        readme=readme_file,
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
        if (
            len(wid) != 64
            or any(ch not in "0123456789abcdef" for ch in wid)
            or wid in seen
        ):
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


def _resolve_torrent_client(explicit: Optional[str] = None) -> str:
    if explicit:
        found = shutil.which(explicit)
        if not found:
            raise ArchiveError(f"Torrent client not found: {explicit}")
        return found
    for candidate in ("aria2c", "transmission-cli"):
        found = shutil.which(candidate)
        if found:
            return found
    raise ArchiveError(
        "No supported BitTorrent CLI was found. Install aria2c or transmission-cli, "
        "or pass --torrent-client."
    )


def download_torrent(
    magnet: str,
    download_dir: Path | str,
    *,
    torrent_client: Optional[str] = None,
    timeout: int = 7200,
) -> Path:
    """外部BT CLIのtracker/DHTを使ってbundleを取得する。

    DFS自身はDHTやピア交換を実装しない。取得先の決定と実データ転送だけを
    aria2c / transmission-cliへ委ね、後段でDFS署名を再検証する。
    """
    out = Path(download_dir).expanduser()
    out.mkdir(parents=True, exist_ok=True)
    executable = _resolve_torrent_client(torrent_client)
    name = Path(executable).name.lower()
    if name.startswith("aria2c"):
        cmd = [
            executable,
            "--dir", str(out),
            "--seed-time=0",
            "--summary-interval=0",
            "--enable-dht=true",
            magnet,
        ]
    elif "transmission-cli" in name:
        cmd = [executable, "--download-dir", str(out), magnet]
    else:
        raise ArchiveError(
            f"Unsupported torrent client {executable!r}; use aria2c or transmission-cli"
        )
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as e:
        raise ArchiveError(
            f"Torrent download timed out after {timeout}s: {magnet}"
        ) from e
    except OSError as e:
        raise ArchiveError(f"Cannot start torrent client {executable!r}: {e}") from e
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise ArchiveError(
            f"Torrent download failed with exit code {result.returncode}: {detail}"
        )
    return out


def locate_downloaded_bundle(
    download_dir: Path | str,
    descriptor: Dict[str, Any],
) -> Path:
    """ダウンロード先から、署名済みdescriptorに対応するbundleを探す。"""
    root = Path(download_dir).expanduser()
    payload = descriptor.get("payload", {})
    expected_path = str(payload.get("path", ""))
    expected_version = int(payload.get("version", -1))
    expected_head = str(payload.get("head_hash", ""))
    candidates: List[Path] = []
    for meta_path in sorted(root.rglob("meta.json")):
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(meta, dict) or meta.get("schema") != ARCHIVE_SCHEMA:
            continue
        head = meta.get("head_log", {})
        if (
            str(meta.get("path", "")) == expected_path
            and int(meta.get("version", -1)) == expected_version
            and str(head.get("entry_hash", "")) == expected_head
        ):
            candidates.append(meta_path.parent)
    if not candidates:
        raise ArchiveError(
            "Downloaded torrent does not contain the selected DFS archive bundle"
        )
    if len(candidates) > 1:
        raise ArchiveError(
            f"Downloaded torrent contains multiple matching bundles: {candidates}"
        )
    return candidates[0]


def extract_bundle(bundle: Path | str, dest: Path | str, tree_secret: str) -> Path:
    """archive bundle を復号してローカルディレクトリへ展開する。"""
    meta = verify_bundle(bundle)
    root = Path(bundle).expanduser()
    out = Path(dest).expanduser()
    local_ost = _BundleOST(root)
    try:
        kdf_version = normalize_kdf_version(
            meta.get("kdf"),
            default=KDF_LEGACY_SHA256,
        )
    except CryptoError as e:
        raise ArchiveError(f"Unsupported archive KDF: {e}") from e
    builder = MerkleTreeBuilder(
        ContentAddressedCrypto(tree_secret, kdf_version=kdf_version),
        local_ost,
    )
    try:
        builder.download_directory(
            str(meta["root_plain_id"]), str(meta["root_wire_id"]), out
        )
    finally:
        builder.close()
    return out
