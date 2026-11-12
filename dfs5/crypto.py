#!/usr/bin/env python3
"""
dfs5/crypto.py
L1 / L2 / L3 / L4 共通の正規化・署名検証・内容アドレス決定論的暗号化 (Convergent AEAD) モジュール。
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import struct
import subprocess
import tempfile
import unicodedata
from pathlib import Path
from typing import Any, Dict, Tuple

SIGN_TIMEOUT_SECONDS: float = 30.0

EMPTY_SHA256: str = hashlib.sha256(b"").hexdigest()

NS_L1_DELEGATION: str = "dfs5-delegation-v1"
NS_L2_LOCATOR: str = "dfs5-l2-locator-v1"
NS_L4_LOG: str = "dfs5-l4-log-v1"


class CryptoError(Exception):
    """dfs5 暗号・署名・整合性エラーの基底クラス"""


class SignatureVerificationError(CryptoError):
    """Ed25519 署名の生成または検証失敗"""


class ChunkIntegrityError(CryptoError):
    """L3 チャンクの破損・改ざん・ハッシュ不一致 (evil A2 検出)"""


class CompressionError(CryptoError):
    """圧縮コーデックの利用・圧縮データの展開失敗"""


def normalize_name(name: str) -> str:
    """ファイル名・パス要素を UTF-8 NFC に正規化し、不正な要素を拒否する。"""
    if not name or "/" in name or "\x00" in name or name in (".", ".."):
        raise ValueError(f"Invalid path entry name: {name!r}")
    return unicodedata.normalize("NFC", name)


def normalize_path(path: str) -> str:
    """パス全体を検証・UTF-8 NFC 正規化する（先頭 '/' 必須、末尾 '/' なし）。"""
    if not path or not path.startswith("/"):
        raise ValueError(f"Path must start with '/': {path!r}")
    if path == "/":
        raise ValueError("Root '/' alone is not a valid subtree path")
    if "//" in path or path.endswith("/"):
        raise ValueError(f"Path must not contain empty segments or trailing slash: {path!r}")
    parts = [normalize_name(p) for p in path.split("/")[1:]]
    return "/" + "/".join(parts)


def canonical_json(obj: Dict[str, Any]) -> bytes:
    """jq -cnS 互換の正規化 JSON バイト列（辞書順ソート・空白なし・末尾LF）を返す。"""
    text = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
    return text.encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def ssh_key_fingerprint(pubkey_line: str) -> str:
    """OpenSSH 公開鍵の指紋を ``SHA256:<base64>`` の形で返す（ssh-keygen -lf と同じ）。

    人間が目で比べるための短い表現。``ssh-ed25519 AAAA... comment`` の 2 番目を
    デコードしてハッシュする。解釈できない行では空文字を返す（判断は呼び出し側）。
    """
    parts = (pubkey_line or "").split()
    if len(parts) < 2:
        return ""
    try:
        blob = base64.b64decode(parts[1], validate=True)
    except Exception:
        return ""
    digest = hashlib.sha256(blob).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def _ssh_keygen_sign(priv_key_path: Path, namespace: str, payload: bytes) -> str:
    """ssh-keygen -Y sign によるフォールバック署名。必ずタイムアウトする。"""
    with tempfile.TemporaryDirectory(prefix="dfs5_sign_") as tmpdir:
        msg_file = Path(tmpdir) / "payload"
        msg_file.write_bytes(payload)
        try:
            res = subprocess.run(
                ["ssh-keygen", "-Y", "sign", "-f", str(priv_key_path), "-n", namespace, str(msg_file)],
                capture_output=True,
                text=True,
                timeout=SIGN_TIMEOUT_SECONDS,
                stdin=subprocess.DEVNULL,
            )
        except subprocess.TimeoutExpired as e:
            raise SignatureVerificationError(
                f"ssh-keygen -Y sign timed out after {SIGN_TIMEOUT_SECONDS:.0f}s "
                f"(key={priv_key_path}); provide an unencrypted key or install 'cryptography'"
            ) from e
        except OSError as e:
            raise SignatureVerificationError(f"ssh-keygen -Y sign could not start: {e}") from e
        if res.returncode != 0:
            raise SignatureVerificationError(f"ssh-keygen -Y sign failed: {res.stderr.strip()}")
        sig_file = Path(f"{msg_file}.sig")
        if not sig_file.is_file():
            raise SignatureVerificationError("ssh-keygen -Y sign produced no signature file")
        return sig_file.read_text(encoding="utf-8")


def _ssh_string(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


def _read_ssh_string(data: bytes, offset: int) -> Tuple[bytes, int]:
    if offset < 0 or offset + 4 > len(data):
        raise ValueError("truncated SSH string")
    length = struct.unpack(">I", data[offset:offset + 4])[0]
    start = offset + 4
    end = start + length
    if end > len(data):
        raise ValueError("truncated SSH string")
    return data[start:end], end


def _read_ed25519_public_key(pubkey_str: str) -> bytes:
    parts = (pubkey_str or "").split()
    if len(parts) < 2 or parts[0] != "ssh-ed25519":
        raise ValueError("not an Ed25519 SSH public key")
    blob = base64.b64decode(parts[1], validate=True)
    key_type, offset = _read_ssh_string(blob, 0)
    key_bytes, offset = _read_ssh_string(blob, offset)
    if key_type != b"ssh-ed25519" or len(key_bytes) != 32 or offset != len(blob):
        raise ValueError("invalid Ed25519 SSH public key")
    return key_bytes


def _read_sshsig_signature(signature: str, namespace: str) -> Tuple[bytes, bytes]:
    """SSHSIG armored 署名から公開鍵と Ed25519 署名を取り出す。"""
    lines = [
        line.strip()
        for line in (signature or "").splitlines()
        if line.strip() and not line.strip().startswith("-----")
    ]
    if not lines:
        raise ValueError("empty SSHSIG signature")
    raw = base64.b64decode("".join(lines), validate=True)
    if len(raw) < 10 or raw[:6] != b"SSHSIG":
        raise ValueError("invalid SSHSIG magic")
    version = struct.unpack(">I", raw[6:10])[0]
    if version != 1:
        raise ValueError("unsupported SSHSIG version")
    offset = 10
    pubkey_blob, offset = _read_ssh_string(raw, offset)
    signed_namespace, offset = _read_ssh_string(raw, offset)
    reserved, offset = _read_ssh_string(raw, offset)
    hash_alg, offset = _read_ssh_string(raw, offset)
    signature_blob, offset = _read_ssh_string(raw, offset)
    if offset != len(raw):
        raise ValueError("trailing bytes in SSHSIG signature")
    if signed_namespace.decode("utf-8") != namespace:
        raise ValueError("SSHSIG namespace mismatch")
    if reserved != b"" or hash_alg != b"sha512":
        raise ValueError("unsupported SSHSIG options")

    key_type, key_offset = _read_ssh_string(pubkey_blob, 0)
    key_bytes, key_offset = _read_ssh_string(pubkey_blob, key_offset)
    if key_type != b"ssh-ed25519" or len(key_bytes) != 32 or key_offset != len(pubkey_blob):
        raise ValueError("invalid SSHSIG public key")
    sig_type, sig_offset = _read_ssh_string(signature_blob, 0)
    sig_bytes, sig_offset = _read_ssh_string(signature_blob, sig_offset)
    if sig_type != b"ssh-ed25519" or len(sig_bytes) != 64 or sig_offset != len(signature_blob):
        raise ValueError("invalid SSHSIG Ed25519 signature")
    return key_bytes, sig_bytes


def _ssh_verify_ed25519(
    pubkey_str: str,
    namespace: str,
    payload: bytes,
    signature: str,
) -> bool | None:
    """Ed25519 の SSHSIG を in-process 検証する。

    未対応形式・解析不能なら ``None`` を返し、呼び出し側が ``ssh-keygen`` に
    フォールバックする。署名が構文的に正しい Ed25519 SSHSIG で検証失敗した場合は
    ``False`` を返す。
    """
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        expected_key = _read_ed25519_public_key(pubkey_str)
        signed_key, sig_bytes = _read_sshsig_signature(signature, namespace)
        if not hmac.compare_digest(expected_key, signed_key):
            return False
        public_key = Ed25519PublicKey.from_public_bytes(expected_key)
        try:
            public_key.verify(sig_bytes, _sshsig_signed_data(payload, namespace))
        except InvalidSignature:
            return False
        return True
    except ImportError:
        return None
    except (ValueError, TypeError, binascii.Error):
        return None


def sshenc_encode(payload: bytes, namespace: str, signature: bytes, pubkey_blob: bytes) -> str:
    """OpenSSH SSHSIG の armored 形式を組み立てる（ssh-keygen -Y verify と互換）。"""
    sig_blob = _ssh_string(b"ssh-ed25519") + _ssh_string(signature)
    sig_struct = (
        b"SSHSIG"
        + struct.pack(">I", 1)
        + _ssh_string(pubkey_blob)
        + _ssh_string(namespace.encode("utf-8"))
        + _ssh_string(b"")
        + _ssh_string(b"sha512")
        + _ssh_string(sig_blob)
    )
    b64 = base64.b64encode(sig_struct).decode("ascii")
    lines = [b64[i:i + 70] for i in range(0, len(b64), 70)]
    return (
        "-----BEGIN SSH SIGNATURE-----\n"
        + "\n".join(lines)
        + "\n-----END SSH SIGNATURE-----\n"
    )


def _sshsig_signed_data(payload: bytes, namespace: str) -> bytes:
    """SSHSIG が署名する対象（MAGIC, namespace, reserved, hash_alg, H(message)）。"""
    return (
        b"SSHSIG"
        + _ssh_string(namespace.encode("utf-8"))
        + _ssh_string(b"")
        + _ssh_string(b"sha512")
        + _ssh_string(hashlib.sha512(payload).digest())
    )


def ssh_sign(priv_key_path: Path | str, namespace: str, payload: bytes) -> str:
    """OpenSSH 秘密鍵で分離署名を作る。

    まず ``cryptography`` で復号を試みる（外部プロセスを起動しない）。
    パスフレーズ付きなど復号できない鍵だけ ``ssh-keygen -Y sign`` に委ねる。
    """
    priv_path = Path(priv_key_path).expanduser().resolve()
    if not priv_path.is_file():
        raise SignatureVerificationError(f"Private key not found: {priv_path}")

    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519

        key_bytes = priv_path.read_bytes()
        try:
            private_key = serialization.load_ssh_private_key(key_bytes, password=None)
        except Exception:
            private_key = serialization.load_pem_private_key(key_bytes, password=None)
        if not isinstance(private_key, ed25519.Ed25519PrivateKey):
            raise SignatureVerificationError("Only Ed25519 private keys are supported in-process")
        from cryptography.hazmat.primitives import serialization as _ser

        pub_raw = private_key.public_key().public_bytes(_ser.Encoding.Raw, _ser.PublicFormat.Raw)
        pubkey_blob = _ssh_string(b"ssh-ed25519") + _ssh_string(pub_raw)
        signature = private_key.sign(_sshsig_signed_data(payload, namespace))
        return sshenc_encode(payload, namespace, signature, pubkey_blob)
    except SignatureVerificationError:
        raise
    except ImportError:
        pass
    except Exception:
        # パスフレーズ付き鍵や未対応形式は ssh-keygen に任せる（タイムアウト付き）
        pass

    return _ssh_keygen_sign(priv_path, namespace, payload)


def ssh_verify(
    pubkey_str: str,
    identity: str,
    namespace: str,
    payload: bytes,
    signature: str,
) -> bool:
    """Ed25519 SSHSIG を in-process で検証する。

    ``cryptography`` が無い場合や未対応の鍵形式だけ ``ssh-keygen -Y verify`` に
    フォールバックする。
    """
    clean_pub = pubkey_str.strip()
    if not clean_pub or "\n" in clean_pub:
        return False

    in_process = _ssh_verify_ed25519(clean_pub, namespace, payload, signature)
    if in_process is not None:
        return in_process

    with tempfile.TemporaryDirectory(prefix="dfs5_verify_") as tmpdir:
        tmp_path = Path(tmpdir)
        allowed_signers = tmp_path / "allowed_signers"
        sig_file = tmp_path / "payload.sig"

        allowed_signers.write_text(f"{identity} {clean_pub}\n", encoding="utf-8")
        sig_file.write_text(signature, encoding="utf-8")

        res = subprocess.run(
            [
                "ssh-keygen",
                "-Y",
                "verify",
                "-f",
                str(allowed_signers),
                "-I",
                identity,
                "-n",
                namespace,
                "-s",
                str(sig_file),
            ],
            input=payload,
            capture_output=True,
            timeout=SIGN_TIMEOUT_SECONDS,
        )
        return res.returncode == 0


def require_ssh_verify(
    pubkey_str: str,
    identity: str,
    namespace: str,
    payload: bytes,
    signature: str,
) -> None:
    if not ssh_verify(pubkey_str, identity, namespace, payload, signature):
        raise SignatureVerificationError(
            f"Signature verification failed for identity={identity!r}, namespace={namespace!r}"
        )


class ContentAddressedCrypto:
    """内容アドレス付きチャンク暗号。

    設計方針（単一書き手を前提とする）:
      - 重複排除は、暗号化の前に平文の内容アドレス ``plain_id`` で判定する。
        判定主体は書き手自身（署名済み履歴／ローカル索引）であり、OST ではない。
      - したがって暗号化は決定的である必要がない。Nonce は毎回 ``os.urandom`` で作り、
        暗号は標準 AEAD (ChaCha20-Poly1305) を使う。自作暗号は持たない。
      - ``plain_id`` の導出鍵（内容アドレス鍵）は、暗号化鍵のローテーションとは分離する。
        内容アドレス鍵を変えると過去のチャンクと重複排除できなくなるため、長期固定とする。
      - 暗号化鍵は ``tree_secret`` から導出する（epoch で回してよい）。
    """

    MAGIC_HEADER = b"DFS5B2"
    MAGIC_HEADER_V3 = b"DFS5B3"
    CODEC_NONE = 0
    CODEC_ZSTD = 1
    ZSTD_LEVEL = 10
    COMPRESSION_THRESHOLD = 0.95
    COMPRESSION_SAMPLE_BYTES = 64 * 1024
    NONCE_LEN = 12
    TAG_LEN = 16  # ChaCha20-Poly1305 のタグ長

    def __init__(self, tree_secret: bytes | str, address_secret: bytes | str | None = None):
        if isinstance(tree_secret, str):
            tree_secret = hashlib.sha256(tree_secret.encode("utf-8")).digest()
        self.tree_secret: bytes = tree_secret
        # 内容アドレス鍵は暗号化鍵と分離する。未指定なら tree_secret から決定的に導出する。
        if address_secret is None:
            self.address_secret: bytes = hmac.new(
                b"dfs5-address-key-v1", tree_secret, hashlib.sha256
            ).digest()
        elif isinstance(address_secret, str):
            self.address_secret = hashlib.sha256(address_secret.encode("utf-8")).digest()
        else:
            self.address_secret = address_secret

    def _enc_key(self, plain_id_bytes: bytes) -> bytes:
        return hmac.new(self.tree_secret, b"dfs5-chunk-key-v1:" + plain_id_bytes, hashlib.sha256).digest()

    def compute_plain_id(self, plaintext: bytes) -> bytes:
        """平文の内容アドレス。暗号化鍵のローテーションに依存しない。"""
        return hmac.new(self.address_secret, b"dfs5-plain-id-v1:" + plaintext, hashlib.sha256).digest()

    @staticmethod
    def _normalize_compression(compression: str | None) -> str:
        value = str(compression or "none").strip().lower()
        if value in ("", "none", "off", "false", "0"):
            return "none"
        if value in ("zstd", "zstandard", "zstd:10"):
            return "zstd"
        raise CompressionError(f"Unsupported compression codec: {compression!r}")

    @classmethod
    def _compress_if_beneficial(cls, plaintext: bytes) -> bytes | None:
        """サンプルで明らかな非圧縮を除外し、最終圧縮率で採否を決める。"""
        if len(plaintext) < 4096:
            return None
        try:
            import zstandard as zstd
        except ImportError as e:
            raise CompressionError(
                "zstd compression requires zstandard (pip install 'dfs5[compression]')"
            ) from e
        sample_size = cls.COMPRESSION_SAMPLE_BYTES
        if len(plaintext) <= sample_size * 3:
            sample = plaintext
        else:
            middle = len(plaintext) // 2
            sample = (
                plaintext[:sample_size]
                + plaintext[middle:middle + sample_size]
                + plaintext[-sample_size:]
            )
        compressor = zstd.ZstdCompressor(level=cls.ZSTD_LEVEL)
        sampled = compressor.compress(sample)
        if len(sampled) / len(sample) >= cls.COMPRESSION_THRESHOLD:
            return None
        compressed = compressor.compress(plaintext)
        if len(compressed) >= len(plaintext):
            return None
        if len(compressed) / len(plaintext) >= cls.COMPRESSION_THRESHOLD:
            return None
        return compressed

    @classmethod
    def chunk_codec(cls, blob: bytes) -> str:
        if blob.startswith(cls.MAGIC_HEADER_V3) and len(blob) > len(cls.MAGIC_HEADER_V3):
            codec = blob[len(cls.MAGIC_HEADER_V3)]
            if codec == cls.CODEC_ZSTD:
                return "zstd"
        return "none"

    def pack_chunk(
        self,
        plaintext: bytes,
        nonce: bytes | None = None,
        compression: str | None = "none",
    ) -> Tuple[str, str, bytes]:
        """平文を暗号化し、(plain_id, wire_id, blob) を返す。

        ``nonce`` を省略すると毎回 ``os.urandom`` で生成する（決定的暗号にしない）。
        同じ平文でも呼ぶたびに ``wire_id`` は変わりうるが、重複排除は ``plain_id`` で
        行うため影響しない。圧縮する場合は平文を圧縮してから暗号化し、B3 ヘッダーに
        codec と元サイズを保存する。
        """
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

        plain_id_bytes = self.compute_plain_id(plaintext)
        plain_id_hex = plain_id_bytes.hex()
        codec = self._normalize_compression(compression)
        payload = self._compress_if_beneficial(plaintext) if codec == "zstd" else None
        if payload is None:
            codec = "none"
            payload = plaintext
        if nonce is None:
            nonce = os.urandom(self.NONCE_LEN)
        if len(nonce) != self.NONCE_LEN:
            raise ValueError(f"Nonce must be {self.NONCE_LEN} bytes, got {len(nonce)}")

        key = self._enc_key(plain_id_bytes)
        if codec == "zstd":
            codec_byte = bytes([self.CODEC_ZSTD])
            header = self.MAGIC_HEADER_V3 + codec_byte + plain_id_bytes + struct.pack(">Q", len(plaintext))
        else:
            header = self.MAGIC_HEADER + plain_id_bytes
            codec_byte = b""
        ciphertext = ChaCha20Poly1305(key).encrypt(nonce, payload, header)
        blob = header + nonce + ciphertext
        wire_id_hex = sha256_hex(blob)
        return plain_id_hex, wire_id_hex, blob

    def unpack_chunk(self, expected_plain_id: str, expected_wire_id: str, blob: bytes) -> bytes:
        """blob を検証・復号する。A2（改ざん）は wire_id と AEAD タグの二段で検出する。"""
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

        actual_wire_id = sha256_hex(blob)
        if actual_wire_id != expected_wire_id:
            raise ChunkIntegrityError(
                f"Wire SHA-256 mismatch (A2): expected {expected_wire_id[:12]}..., got {actual_wire_id[:12]}..."
            )
        try:
            plain_id_bytes = bytes.fromhex(expected_plain_id)
        except ValueError as e:
            raise ChunkIntegrityError(f"Invalid plain_id hex: {expected_plain_id}") from e

        if blob.startswith(self.MAGIC_HEADER_V3):
            m_len = len(self.MAGIC_HEADER_V3)
            if len(blob) < m_len + 1 + 32 + 8 + self.NONCE_LEN + self.TAG_LEN:
                raise ChunkIntegrityError("Invalid or truncated DFS5B3 chunk header")
            codec = blob[m_len]
            embedded_plain_id = blob[m_len + 1 : m_len + 33]
            plain_size = struct.unpack(">Q", blob[m_len + 33 : m_len + 41])[0]
            head_len = m_len + 1 + 32 + 8 + self.NONCE_LEN
            aad = blob[: m_len + 1 + 32 + 8]
            if not hmac.compare_digest(embedded_plain_id, plain_id_bytes):
                raise ChunkIntegrityError("Embedded plain_id does not match the manifest (A2)")
            nonce = blob[m_len + 41 : head_len]
            ciphertext = blob[head_len:]
        else:
            m_len = len(self.MAGIC_HEADER)
            head_len = m_len + 32 + self.NONCE_LEN
            if len(blob) < head_len + self.TAG_LEN or not blob.startswith(self.MAGIC_HEADER):
                raise ChunkIntegrityError("Invalid or truncated DFS5 chunk header")
            codec = self.CODEC_NONE
            embedded_plain_id = blob[m_len : m_len + 32]
            plain_size = 0
            if not hmac.compare_digest(embedded_plain_id, plain_id_bytes):
                raise ChunkIntegrityError("Embedded plain_id does not match the manifest (A2)")
            nonce = blob[m_len + 32 : head_len]
            ciphertext = blob[head_len:]
            aad = self.MAGIC_HEADER + plain_id_bytes

        if len(blob) < head_len + self.TAG_LEN:
            raise ChunkIntegrityError("Invalid or truncated DFS5 chunk header")

        key = self._enc_key(plain_id_bytes)
        try:
            payload = ChaCha20Poly1305(key).decrypt(nonce, ciphertext, aad)
        except Exception as e:
            raise ChunkIntegrityError(f"AEAD authentication failed (A2 or wrong key): {e}") from e

        if codec == self.CODEC_ZSTD:
            try:
                import zstandard as zstd

                plaintext = zstd.ZstdDecompressor().decompress(
                    payload, max_output_size=plain_size
                )
            except Exception as e:
                raise CompressionError(f"zstd decompression failed: {e}") from e
        elif codec == self.CODEC_NONE:
            plaintext = payload
        else:
            raise CompressionError(f"Unsupported chunk codec: {codec}")

        actual_plain_id = self.compute_plain_id(plaintext).hex()
        if actual_plain_id != expected_plain_id:
            raise ChunkIntegrityError(
                f"Plaintext content address mismatch: expected {expected_plain_id[:12]}..., got {actual_plain_id[:12]}..."
            )
        return plaintext
