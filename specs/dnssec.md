# DNSSEC による L1 root / registry discovery

## 結論

DNSSEC は **root アンカー公開鍵と registry 一覧の配布**に使う。動的な head、CAS、
primary 昇格の判断には使わない。

「最初に起動したサーバが domain root になる」方式は採用しない。
primary / secondary は DNSSEC レコードに明示された役割、または運用者の静的設定で
決める。最初に起動したことは権威の根拠にならない。

DNSSEC レコードが落ちても、クライアントは最後に検証済みの設定をキャッシュして
読み取りを継続できる。ただし、レコードの更新・失効には TTL があるため、
registry の即時フェイルオーバーを DNS に依存させない。

## レコード

`_dfs.<domain>` の TXT レコードに JSON を 1 つ置く。

```json
{
  "schema": "dfs-discovery-v1",
  "domain": "example.com",
  "root_anchor": "/example.com",
  "root_pubkey": "ssh-ed25519 AAAA...",
  "registries": [
    {"url": "https://l2-a.example.com:9440", "role": "primary"},
    {"url": "https://l2-b.example.com:9440", "role": "secondary"}
  ],
  "epoch": 1,
  "ttl": 300
}
```

### フィールド

| フィールド | 意味 |
|---|---|
| `schema` | `dfs-discovery-v1` 固定 |
| `domain` | このレコードが管理するドメイン |
| `root_anchor` | L1 root のパス（例: `/example.com`） |
| `root_pubkey` | L1 root の OpenSSH 公開鍵 |
| `registries` | `primary` 1 つと `secondary` 0 個以上 |
| `epoch` | レコードの世代。単調増加させる |
| `ttl` | クライアントが採用を検討する目安の TTL |

`primary` はちょうど 1 つでなければならない。複数 primary、primary なしは拒否する。
URL は `http(s)://host:port` 形式で、重複を拒否する。

## 検証

1. EDNS0 の DO ビットを付けて `_dfs.<domain>` TXT を引く
2. TXT の RRSIG から署名ゾーンを特定する
3. IANA の root trust anchor（KSK-2017 / KSK-2024 の DS）を根として、
   署名ゾーンまでの DNSKEY / DS チェーンをクライアント側で検証する
4. TXT RRset の RRSIG を検証する
5. TXT の JSON をスキーマ・型・必須項目について検証する
6. `root_pubkey` を `root_anchor` の信頼の根として記録する
7. 以後の L1 委譲チェーンは、既存の root アンカー検証で検証する

AD（Authenticated Data）ビットは既定の検証では使わない。`validate=False` を
明示した旧互換経路だけが、検証済みリゾルバの AD ビットを信頼する。
この旧経路は `--dnssec-no-validate --dnssec-no-ad` で選ぶ。診断用であり、
通常運用では使わない。

## DNSSEC と L2/L3 の役割

- DNSSEC: root 公開鍵、registry の初期一覧、primary/secondary の役割
- L2 registry: 委譲チェーン、ロケータ、L4 head の CAS / 複製
- L3 OST: 暗号化チャンク。主 OST と読み取りレプリカ OST

DNSSEC レコードは静的な discovery 情報であり、L4 head を載せない。
head の更新は L2 の署名付きログで行う。

DNSSEC は **必須ではない**。閉域・WireGuard・LAN の初期運用や小規模運用では、
[specs/discovery.md](discovery.md) の「署名付き立候補モデル (`dfs-candidacy-v1`)」
または `dfscli config create --registry ... --root-pubkey ...` を使う。
中規模を超える運用になりそうな場合に DNSSEC へ移行する。
DNSSEC を使う場合も、その役割は初期 root/registry discovery に限定する。

## 障害時の前提

「registry は落ちない」とは仮定しない。

| 障害 | 期待する挙動 |
|---|---|
| DNSSEC / DNS 停止 | 最後に検証済みの root 鍵と registry 一覧を使う |
| primary registry 停止 | 読み取りは secondary にフォールバック。書き込みは失敗 |
| secondary registry 停止 | primary で読み書きを継続 |
| primary の復帰 | `role_epoch` による fencing で、昇格後の writer からの書き込みだけを受理する |
| DNSSEC 鍵漏洩 | ドメイン権威の侵害として扱い、root 鍵と registry 一覧をローテーションする |

最初に起動したサーバを root にする方式は、同時起動・分断・復帰時に split-brain を
起こすため採用しない。

## CLI

```bash
# discovery の内容を確認
dfscli discover example.com

# DNSSEC から root 鍵・primary/secondary を取得してリモートを登録
dfscli config create scw \
  --dnssec-domain example.com \
  --key ~/.ssh/alice \
  --secret <tree_secret>

# dfssvc が管理するサービスの TXT JSON を生成
dfssvc dnssec scw --domain example.com
```

`--registry` / `--registry-alternate` を併記した場合は、DNSSEC の内容と一致しなければ
エラーにする。`--root-pubkey` を併記した場合も、DNSSEC の root 公開鍵と一致しなければ
拒否する。

## 制約

- root trust anchor はコードに埋め込んでいる。IANA の KSK ロールオーバー時には
  `ROOT_TRUST_ANCHOR_DS` を更新する必要がある
- primary 昇格時の fencing は `role_epoch` で行う。旧 primary は、昇格後の
  `role_epoch` を持つ writer からの書き込みを拒否する。ただし旧 epoch の writer は
  引き続き旧 primary に書き込めるため、writer 設定の更新を同時に行う必要がある
- TXT レコードのサイズ・TTL・伝播遅延を考慮し、多数の registry を 1 レコードに
  詰め込まない
- DNSSEC は primary の生存監視や自動昇格を行わない
- DNSSEC レコードの更新は、TSIG / 動的更新 / ゾーン管理の権限で保護する

## 回帰試験

- `tests/test_dnssec.py`: JSON のスキーマ、primary 1 つ、URL、root 鍵、epoch の検証
- `tests/test_dnssec.py`: CLI の `--dnssec-domain` が Remote に root 鍵と
  primary/secondary を反映すること
