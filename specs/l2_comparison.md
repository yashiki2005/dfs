# L2 所在地解決 方式比較と仕様（`specs/l2_comparison.md`）

## 0. 目的と位置づけ

本文書は `dfs5` の段階 3（L2: 所在地解決 — 名前から住所へ）における検証結果と確定仕様を記録する。
`DESIGN.md` §10 の問い 3「ロケータをどこに置くか」および §9「まず名簿で作り、後から DHT を足せる形にする」の妥当性を数値で検証し、以下を確定する。

1. **方式に依存しない共通の署名付きロケータ形式**（`dfs5-l2-locator-v1`）を定義し、L2 の通信路や保管ノード自体を信頼しなくてよい構造にする。
2. **(a) 名簿（Directory）**、**(b) DHT（Kademlia 型）**、**(c) DNS（TXT レコード流用）** の 3 方式を同一条件で比較計測する。
3. 高遅延条件（RTT 200ms）で往復 2 回以内に収まるかを判定し、**3 回以上かかる方式（DHT）に対する 2 段キャッシュ設計**を確定する。

---

## 1. 共通データ形式：署名付きロケータ（Signed Locator）

L2 がどのバックエンド（名簿 / DHT / DNS）で実装されていても、やり取りされるデータ構造は単一の正規化 JSON ペイロードと OpenSSH Ed25519 分離署名のペアに統一する。

### 1.1 ペイロード（署名対象）

キーを辞書順にソートし、余白を含まない 1 行の UTF-8 JSON（`jq -cnS` および `dfs5.crypto.canonical_json()` 形式、末尾 LF 1 バイトを含む）とする。

```json
{
  "delegation_epoch": 1,
  "endpoints": [
    "tls://192.168.1.50:9443",
    "tls://[2001:db8::1]:9443"
  ],
  "expires_at": 1763086400,
  "head_hash": "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
  "head_version": 2,
  "path": "/[example.com/alice](https://example.com/alice)",
  "ttl": 300
}