# 平文圧縮の既定有効化 (`auto` ポリシー)

> [English](compression.md) | **日本語**

## 方針決定の経緯

従来 `dfs` の既定の圧縮ポリシーは `"none"` であり、利用者が `--compression zstd` や `user.dfs.compression` xattr を明示的に指定した場合にのみ圧縮が有効になっていた。しかし、以下の理由から **既定値を `"auto"`（実質 ON）へ変更し、`zstandard>=0.22` を必須依存 (`dependencies`) へ昇格した**。

1. **通信制限環境・従量課金環境での不利**
   - RunPod や vast.ai などのリモート GPU 環境では ingress / egress に課金が発生し、また狭帯域・高遅延回線では転送量がそのまま同期時間・コストに直結する。
   - 圧縮設定を明示し忘れただけでログ・コード・JSONL・設定ファイル等の圧縮しやすいデータがすべて無圧縮で L3 OST を往復するのは、デフォルト挙動として不利が大きい。

2. **L3 ストリーム圧縮ではなく「暗号化前（平文）圧縮」を採用する理由**
   - L3 OST を流れるチャンク本体は [dfs/crypto.py](../dfs/crypto.py) の Convergent AEAD（ChaCha20-Poly1305）によって **すでに暗号化済み** である。
   - 暗号文はエントロピーが最大（擬似ランダム列）であるため、HTTP の `gzip`/`zstd` 等でトランスポートストリームを圧縮してもサイズはほとんど縮まず、送受信双方の CPU 負荷だけが増える。
   - 暗号化の前に平文を圧縮（Compress-then-Encrypt）しておけば、L3 転送量・サーバ側ストレージ容量の両方を削減でき、展開も受信側が `DFSB3` ヘッダを見て自動で行うため設定の引き継ぎミスが起きない。
   - （補足: L2 の JSON-RPC 応答や `bootstrap_ro.sh` 等の平文テキストについては、リバースプロキシ側の `encode zstd gzip` で十分対応できる。）

3. **サンプリング判定により非圧縮データへの悪影響がない**
   - `_compress_if_beneficial` はすでに `4096` バイト未満のスキップ、先頭・中盤・後半のサンプリング圧縮判定、および最終圧縮率の閾値判定（`COMPRESSION_THRESHOLD`）を備えている。
   - モデル重み（`.safetensors` 等）や画像・アーカイブ等の縮まないファイルでは自動で無圧縮（`CODEC_NONE`）へ切り替わるため、既定で有効にしても転送量の増加や過剰な CPU 消費を招かない。

---

## 仕様 (`auto` / `zstd` / `none`)

- **`auto`（既定値）**:
  - `zstandard` が利用可能であれば `zstd` として `_compress_if_beneficial` を実行し、閾値以上に縮むチャンクのみ `DFSB3` + `CODEC_ZSTD` で格納・転送する。
  - `zstandard` が無い最小環境から書き込む場合でもエラーにせず、安全に無圧縮（`none`）へフォールバックする。
- **`zstd`**:
  - `_compress_if_beneficial` を実行する。`zstandard` が未導入の場合は `CompressionError` を送出する。
- **`none`**:
  - 圧縮を行わない。特定のディレクトリだけ圧縮を完全に止めたい場合は、`user.dfs.compression` xattr に `none` を設定するか `--compression none` を指定する。

---

## 関連ファイル

- 依存定義: [pyproject.toml](../pyproject.toml)（`zstandard>=0.22` を `dependencies` に追加）
- 暗号化・圧縮判定: [dfs/crypto.py](../dfs/crypto.py)（`ContentAddressedCrypto.pack_chunk` / `_compress_if_beneficial`）
- ポリシー定義・xattr: [dfs/compression.py](../dfs/compression.py)（`VALID_POLICIES = {"auto", "none", "zstd"}`）
- 既定値参照: [dfs/l4_log.py](../dfs/l4_log.py)、[dfs/l5_fs.py](../dfs/l5_fs.py)、[dfs/remotes.py](../dfs/remotes.py)、[dfs/cli.py](../dfs/cli.py)、[dfs/cli_main.py](../dfs/cli_main.py)
