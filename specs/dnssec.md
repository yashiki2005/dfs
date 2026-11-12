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

`_dfs5.<domain>` の TXT レコードに JSON を 1 つ置く。

```json
{
  "schema": "dfs5-discovery-v1",
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
| `schema` | `dfs5-discovery-v1` 固定 |
| `domain` | このレコードが管理するドメイン |
| `root_anchor` | L1 root のパス（例: `/example.com`） |
| `root_pubkey` | L1 root の OpenSSH 公開鍵 |
| `registries` | `primary` 1 つと `secondary` 0 個以上 |
| `epoch` | レコードの世代。単調増加させる |
| `ttl` | クライアントが採用を検討する目安の TTL |

`primary` はちょうど 1 つでなければならない。複数 primary、primary なしは拒否する。
URL は `http(s)://host:port` 形式で、重複を拒否する。

## 検証

1. DNSSEC 対応リゾルバで `_dfs5.<domain>` TXT を引く
2. レスポンスの AD（Authenticated Data）ビットを確認する
3. TXT の JSON をスキーマ・型・必須項目について検証する
4. `root_pubkey` を `root_anchor` の信頼の根として記録する
5. 以後の L1 委譲チェーンは、既存の root アンカー検証で検証する

現段階の実装は **検証済みリゾルバの AD ビットを信頼する**方式である。
クライアント自身が DNSKEY/DS チェーンを再検証する方式ではない。
ローカルで AD を付けられない検証環境向けに `--dnssec-no-ad` を用意するが、
本番では使わない。

## DNSSEC と L2/L3 の役割

- DNSSEC: root 公開鍵、registry の初期一覧、primary/secondary の役割
- L2 registry: 委譲チェーン、ロケータ、L4 head の CAS / 複製
- L3 OST: 暗号化チャンク。主 OST と読み取りレプリカ OST

DNSSEC レコードは静的な discovery 情報であり、L4 head を載せない。
head の更新は L2 の署名付きログで行う。

## 障害時の前提

「registry は落ちない」とは仮定しない。

| 障害 | 期待する挙動 |
|---|---|
| DNSSEC / DNS 停止 | 最後に検証済みの root 鍵と registry 一覧を使う |
| primary registry 停止 | 読み取りは secondary にフォールバック。書き込みは失敗 |
| secondary registry 停止 | primary で読み書きを継続 |
| primary の復帰 | 古い primary の書き込みを拒否できるよう epoch / fencing が必要（未実装） |
| DNSSEC 鍵漏洩 | ドメイン権威の侵害として扱い、root 鍵と registry 一覧をローテーションする |

最初に起動したサーバを root にする方式は、同時起動・分断・復帰時に split-brain を
起こすため採用しない。

## CLI

```bash
# discovery の内容を確認
dfs5cli discover example.com

# DNSSEC から root 鍵・primary/secondary を取得してリモートを登録
dfs5cli config create scw \
  --dnssec-domain example.com \
  --key ~/.ssh/alice \
  --secret <tree_secret>
```

`--registry` / `--registry-alternate` を併記した場合は、DNSSEC の内容と一致しなければ
エラーにする。`--root-pubkey` を併記した場合も、DNSSEC の root 公開鍵と一致しなければ
拒否する。

## 制約

- AD ビットを信頼する MVP であり、完全なクライアント側 DNSSEC 検証は未実装
- primary 昇格時の epoch / fencing は未実装。現在の epoch は discovery レコードの
  世代を検証・表示するための値で、古い primary の書き込み拒否にはまだ使っていない
- TXT レコードのサイズ・TTL・伝播遅延を考慮し、多数の registry を 1 レコードに
  詰め込まない
- DNSSEC は primary の生存監視や自動昇格を行わない
- DNSSEC レコードの更新は、TSIG / 動的更新 / ゾーン管理の権限で保護する

## 回帰試験

- `tests/test_dnssec.py`: JSON のスキーマ、primary 1 つ、URL、root 鍵、epoch の検証
- `tests/test_dnssec.py`: CLI の `--dnssec-domain` が Remote に root 鍵と
  primary/secondary を反映すること
