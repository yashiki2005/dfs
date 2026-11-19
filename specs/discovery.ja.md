# 小規模運用向けの署名付き立候補モデル (Signed Candidacy Discovery)

> [English](discovery.md) | **日本語**

## 方針決定の経緯

`dfs` の registry discovery には以下の 3 つの選択肢を検討した。

1. **無条件の立候補（最初に起動したサーバが root / primary）**
   - なりすましやネットワーク分断時の split-brain を防げないため不採用。
2. **過半数クォーラムによる立候補（Raft 等の多数決合意）**
   - 小規模構成（2〜3 台）では 1 台停止で過半数を失う等、運用負荷・複雑さが見合わないため不採用。
3. **DNSSEC による discovery**
   - 公開ドメイン管理・ゾーン署名・外部リゾルバ依存が必須となり、未公開・閉域・小規模の分散ファイルシステムでは実運用として重すぎる。

以上を踏まえ、**小規模・未公開運用では「署名付き立候補モデル（`dfs-candidacy-v1`）」を採用する**。
将来的に**中規模を超える運用**（公開ドメイン配下での不特定クライアント配布、多拠点の外部リゾルバ経由 discovery 等）へ移行する場合は、[specs/dnssec.md](dnssec.md) の DNSSEC discovery へ移行する。

---

## 仕組み

1. **信頼の根の共有（初回のみ帯域外）**
   - クライアントには招待・設定時に `root_pubkey`（と候補 registry URL 群）を渡す。
2. **立候補（告知）と検証**
   - 管理者は `root` の秘密鍵で `dfs-candidacy-v1` エンベロープに署名し、各 registry の `/v1/candidacy/announce` へ登録（またはファイル配布）する。
   - クライアントは候補 registry 群の `/v1/candidacy` へ問い合わせ、手元の `root_pubkey` で署名と有効期限を検証した上で、**有効かつ最大の `epoch`（`role_epoch`）** を持つ立候補を採用する。
3. **primary 切り替え**
   - `primary` を切り替える際は `epoch` を `+1` して再署名するだけで、古い `epoch` の立候補はロールバックとして拒否される。

---

## エンベロープ形式 (`dfs-candidacy-v1`)

SSH 署名 namespace は `dfs-candidacy-v1`、identity は `root_anchor` とする。

```json
{
  "payload": {
    "epoch": 2,
    "expires_at": 1738281600,
    "issued_at": 1735689600,
    "registries": [
      {"role": "primary", "url": "http://192.0.2.60:9440"},
      {"role": "secondary", "url": "http://192.0.2.61:9440"}
    ],
    "root_anchor": "/example.com",
    "root_pubkey": "ssh-ed25519 AAAA...",
    "schema": "dfs-candidacy-v1"
  },
  "signature": "-----BEGIN SSH SIGNATURE-----\n..."
}
```

### 検証規則
- `schema == "dfs-candidacy-v1"`
- `root_anchor` が正規化済み（`normalize_path` と一致）
- `root_pubkey` がクライアントの手元の信頼済み `root_pubkey` と一致
- `issued_at <= now < expires_at`
- `epoch >= 1` かつローカル既知の `min_epoch` 以上
- `registries` に重複 URL がなく、`primary` がちょうど 1 つ（`http://` または `https://`）
- `ssh_verify(expected_root_pubkey, root_anchor, "dfs-candidacy-v1", canonical_json(payload), signature)` が真

---

## CLI / HTTP API

- `POST /v1/candidacy`: 登録済みの署名付き立候補エンベロープを返す。
- `POST /v1/candidacy/announce`: `{"envelope": ...}` を検証・保存する。
- `dfscli candidacy create`: 立候補エンベロープを生成・署名し、`--out` や `--announce` で配布する。
- `dfscli candidacy discover`: 候補 URL 群から `/v1/candidacy` を取得・検証し、最大 `epoch` の結果を表示する。
- `dfscli config create <name> --candidacy-url <url>... --root-pubkey <pub>`: 立候補モデルからリモート定義を作成する。
