# 単一書き手 `dfssvc` の分散配置と root 中継リレー (`dfs-relay-v1`)

## 方針決定の経緯

`dfs` では **1 つの書き込み境界ごとに単一の書き手と自前の `dfssvc`（L2 名簿 + L3 OST）を持つ** モデルを採っている。これにより各ホストが自身のデータ・スナップショット・チャンク保存先を自律的に管理できるが、実際の配置では以下のネットワーク制約が生じる。

1. **自宅 Mac 等の書き手ホストは NAT の背後にいる**
   - アウトバウンドの IPv4/IPv6（特に HTTPS 443/tcp）は通るが、外部から自宅ホストへのインバウンド接続は受けられない。
2. **RunPod / vast.ai 等の計算ホストは `scp` やインバウンド待受が制限される**
   - こちらも外部から直接繋ぐことはできず、アウトバウンドの HTTP/HTTPS 接続のみが安定して通る。
3. **データの実体は各ホストの `dfssvc` に残したい**
   - root ホスト（`dfs.yashiki.top`）に全ホストの全データを複製・集約するのではなく、各ホストの `dfssvc` が実データと状態の正本を持ち、`dfs.yashiki.top` は **暗号化済み L3 チャンクと署名済み L2/L4 メタデータを透過中継するだけ** に留めたい。
   - すべてのチャンクは書き手端末側で AEAD 暗号化（`tree_secret`）されているため、root リレーが中継トラフィックの内容を復号・改ざんすることはできない。

以上を踏まえ、**パブリック IPv4/IPv6 を持つ root `dfssvc`（`dfs.yashiki.top`）に HTTP/1.1 リバースリレーハブ（`RelayHub`）を持たせ、NAT/FW 裏の各 `dfssvc` がアウトバウンドで接続して公開パス `/relay/<node_id>/...` を生やす構造** を採用する。

---

## 仕組み

```text
[自宅 Mac dfssvc (NAT裏)]                         [root: dfs.yashiki.top (RelayHub)]                         [RunPod クライアント]
   127.0.0.1:19440                                       https://dfs.yashiki.top
         ▲                                                         │                                                 │
         └── RelayAgent ──(アウトバウンド POST /_relay/pull)───────┤                                                 │
                          (アウトバウンド POST /_relay/reply)      ◀── POST /relay/mac1/v1/resolve ─────────────────┤
                                                                   ◀── POST /relay/mac1/v1/ost/batch_get ───────────┤
```

1. **エージェント側のアウトバウンド接続 (`RelayAgent`)**
   - NAT 裏の `dfssvc` は `--relay https://dfs.yashiki.top --relay-node mac1` で起動する。
   - 複数ワーカー（既定 4 本）が `POST /_relay/pull?node=mac1` をロングポーリング（最大 25 秒）で張り続ける。
   - リクエストが届いたらローカルの `dfssvc`（`127.0.0.1:<registry_port>`）へ転送し、応答を `POST /_relay/reply?node=mac1&id=<req_id>` で返す。
2. **ハブ側の中継 (`/relay/<node_id>/...`) と Direct-first 優先制御**
   - root リレー `dfs.yashiki.top` に全トラフィックを流すと過負荷になるため、**直接通信できる場合は対象ホストの `dfssvc` と直接通信し、直接通信できない場合のみリレーにフォールバックする（Direct-first, Relay-as-fallback）**。
   - `dfssvc` は `/v1/ost` で直接の `endpoint` を先頭に維持したまま、`alternates` / `relay_endpoint` に `https://dfs.yashiki.top/relay/<node_id>` を広告する。
   - クライアント（`RemoteRegistryClient`・`FailoverOSTClient`・`DFSNode`・`dfscli share`）は先頭の直接 URL をまず試し、同一 LAN や到達可能な環境では `dfs.yashiki.top` を一切経由しない。NAT/FW で直接接続に失敗した環境（RunPod 等）だけが `/relay/<node_id>` へ自動的にフォールバックする。
3. **バイナリフレーム形式**
   - `/_relay/pull` の応答と `/_relay/reply` のリクエストは、Base64 膨張を避けるため以下のバイナリフレームを使う。
   - `[4-byte big-endian JSON header length] + [UTF-8 JSON header] + [raw body bytes]`
4. **認証 (`X-DFS-Relay-Token`)**
   - ハブ側で `--relay-token <secret>`（または環境変数 `DFS_RELAY_TOKEN`）を設定した場合、`/_relay/pull` と `/_relay/reply` は `X-DFS-Relay-Token` ヘッダの定数時間比較で検証される。

---

## 中〜大規模運用（DNSSEC + パブリックホストによる分散リレー）

- **なぜ任意の本番パブリックホストをリレーにできるのか**:
  - `dfs` の L3 チャンクは書き手端末側で AEAD 暗号化されており、L2/L4 メタデータも Ed25519 で署名されている。そのためリレーノードは**平文を復号することも署名付きログ・委譲を偽造することもできない**（ゼロトラスト中継）。
- **DNSSEC による安全なリレー群の配布**:
  - 小規模運用では単一ハブ（`dfs.yashiki.top`）+ `--relay-token` で十分だが、中〜大規模運用では **パブリック IPv4/IPv6 を持ち NAT 不要でインバウンド・アウトバウンド両方向が通る任意のホスト** で `dfssvc --enable-relay` を動かし、DNSSEC 署名付きレコードでそのドメイン配下のリレー群として配布できる。
- **複数リレーへの冗長接続**:
  - NAT 裏の `dfssvc` は `--relay` を複数回指定して複数のパブリックリレーへ同時にアウトバウンド接続できる。クライアント側は **Direct-first → Relay 1 → Relay 2 ...** の順で試行するため、特定のハブ（`dfs.yashiki.top`）への過負荷と単一障害点を同時に避けられる。
