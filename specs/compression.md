# Enabling Plaintext Compression by Default (`auto` Policy)

> **English** | [日本語](compression.ja.md)

## Rationale

Previously, `dfs` defaulted to the `"none"` compression policy, enabling compression only when users explicitly specified `--compression zstd` or the `user.dfs.compression` xattr. However, for the following reasons, **the default was changed to `"auto"` (effectively ON), and `zstandard>=0.22` was promoted to a required dependency (`dependencies`)**.

1. **Disadvantage in bandwidth-constrained and metered environments**
   - In remote GPU environments such as RunPod and vast.ai, ingress and egress are billed, and on narrow-bandwidth or high-latency links, transfer volume directly translates into sync time and cost.
   - Having easily compressible data such as logs, code, JSONL, and config files travel back and forth to the L3 OST uncompressed simply because compression wasn't explicitly configured is a major disadvantage as a default behavior.

2. **Why pre-encryption (plaintext) compression is used instead of L3 stream compression**
   - Chunk payloads flowing over the L3 OST are **already encrypted** by Convergent AEAD (ChaCha20-Poly1305) in [dfs/crypto.py](../dfs/crypto.py).
   - Because ciphertext has maximum entropy (a pseudorandom byte stream), compressing the transport stream with HTTP `gzip`/`zstd` etc. barely reduces size and only increases CPU load on both sender and receiver.
   - Compressing plaintext before encryption (Compress-then-Encrypt) reduces both L3 transfer volume and server-side storage usage, and decompression is handled automatically on the receiving side by inspecting the `DFSB3` header, preventing configuration mismatches.
   - (Note: For plaintext responses such as L2 JSON-RPC replies or `bootstrap_ro.sh`, `encode zstd gzip` on the reverse proxy is sufficient.)

3. **Sampling check prevents negative impact on incompressible data**
   - `_compress_if_beneficial` already skips chunks under `4096` bytes, performs sampled compression checks at the start, middle, and end, and checks the final compression ratio against a threshold (`COMPRESSION_THRESHOLD`).
   - Incompressible files such as model weights (`.safetensors`, etc.), images, and archives automatically switch to uncompressed (`CODEC_NONE`), so enabling it by default does not increase transfer volume or cause excessive CPU usage.

---

## Specification (`auto` / `zstd` / `none`)

- **`auto` (default)**:
  - If `zstandard` is available, runs `_compress_if_beneficial` as `zstd`, storing and transferring only chunks that shrink past the threshold with `DFSB3` + `CODEC_ZSTD`.
  - When writing from a minimal environment without `zstandard`, it safely falls back to uncompressed (`none`) instead of raising an error.
- **`zstd`**:
  - Runs `_compress_if_beneficial`. Raises `CompressionError` if `zstandard` is not installed.
- **`none`**:
  - Performs no compression. To completely disable compression for a specific directory only, set the `user.dfs.compression` xattr to `none` or pass `--compression none`.

---

## Related Files

- Dependency definition: [pyproject.toml](../pyproject.toml) (added `zstandard>=0.22` to `dependencies`)
- Encryption & compression decision: [dfs/crypto.py](../dfs/crypto.py) (`ContentAddressedCrypto.pack_chunk` / `_compress_if_beneficial`)
- Policy definition & xattr: [dfs/compression.py](../dfs/compression.py) (`VALID_POLICIES = {"auto", "none", "zstd"}`)
- Default value references: [dfs/l4_log.py](../dfs/l4_log.py), [dfs/l5_fs.py](../dfs/l5_fs.py), [dfs/remotes.py](../dfs/remotes.py), [dfs/cli.py](../dfs/cli.py), [dfs/cli_main.py](../dfs/cli_main.py)
