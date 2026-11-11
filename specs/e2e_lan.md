# Mac と Pi5 の実機統合（`specs/e2e_lan.md`）

## 0. 目的と位置づけ

`PLAN.md` 段階 5（2 台で 1 つのツリーを共有する）の実機結果を記録する。

- ハーネス: `bench/e2e_lan.py`
- 生データ: `bench/results/20261111-200812-e2e-lan.json`
- 実行日: 2026-11-11
- 接続: `ssh -i ~/.ssh/pi-mock-test yy@192.168.0.7`

---

## 1. 構成

```text
[Mac]                                         [Pi5 (Ubuntu 24.04, aarch64, 4 core, 16GB)]
clayfs (L5)                                     dfs5 serve
  └ tree/  ── push ──▶ L3 ChunkStore (TLS 9443) ──┐
  .clayfs/snapshots/                             │
        ▲                                        │
        └──── pull ◀── L4 追記ログ ◀── L2 名簿 (HTTP 9440)
```

| 項目 | 値 |
|---|---|
| Mac | macOS 27.3 arm64、Python 3.12 |
| Pi5 | Ubuntu 24.04（Linux 7.0）、Python 3.14.4、`cryptography` 入り、pytest なし |
| LAN RTT（ping 10 回） | **平均 2.25ms**（min 0.57 / max 6.04） |
| L2 | `http://192.168.0.7:9440`（Symbolic Registry, HTTP） |
| L3 | `tls://192.168.0.7:9443`（TLS 1.3） |
| 部屋の既存サービス | mini_lustre が 9001/9002 を使用中。**別ポートで試験し、止めていない** |

---

## 2. 手順

1. `ssh-keygen` で root / alice の Ed25519 鍵を作る。
2. Pi5 に root の公開鍵を置き、`dfs5 serve` を起動する（状態は `~/dfs5_e2e/server_state`）。
3. Mac から `dfs5 delegate` で `/example.com` → `/example.com/alice/notes` を委譲し、Pi5 の L2 に登録する。
4. Mac と Pi5 で `dfs5 init` し、同じ `tree_secret` を使う。
5. Mac で `push` → Pi5 で `pull` → 内容を SHA-256 で照合する。
6. Pi5 で `push` → Mac で `pull`（逆方向）。
7. 両方が同じ親版のまま同時に `push` し、片方が `ConflictError` で拒否されることを確認する。
8. 衝突コピーが作られていないことを確認する。

---

## 3. 結果

| 手順 | 結果 | 所要時間（ハーネス計測） | 備考 |
|---|---|---|---|
| L2 疎通（HTTP） | 成功 | 32.5 ms | `resolve` が委譲と先頭版を 1 往復で返す |
| L3 疎通（TLS） | 成功 | 75.9 ms | TLS 1.3（初回のハンドシェイク込み） |
| Mac push v1 | 成功 | 66.4 ms | 送信 1,624 B |
| Pi5 pull v1 | 成功 | 39.9 ms | 受信 978 B、内容一致 |
| Pi5 push v2 | 成功 | 60.4 ms | 送信 1,641 B |
| Mac pull v2 | 成功 | 94.0 ms | 受信 995 B、内容一致 |
| Mac push v3 | 成功 | 67.7 ms | 送信 1,661 B |
| **Pi5 の同時 push** | **拒否** | — | `ConflictError`（CAS 不一致） |
| 内容一致（SHA-256） | 成功 | — | 両端末 2 ファイルの digest が一致 |
| 衝突コピー | **0 件** | — | `*conflict*` は無い |

ハーネス実行時の集計（v4）:

```text
OK   L2 疎通（HTTP）          32.5 ms
OK   L3 疎通（TLS）           75.9 ms
OK   Mac push              165.3 ms（内部計測 70.5 ms、送信 1,661 B）
OK   Pi5 pull              643.5 ms（内部計測 38.8 ms、受信 1,015 B、ssh 起動を含む）
OK   内容一致（SHA-256）       2 ファイル
OK   同時書き込みを CAS で拒否
OK   衝突コピー 0 件
```

---

## 4. 何が確かめられたか

- **L2 の署名付きロケータが LAN 越しに動く。** 名簿は 1 往復で委譲と先頭版を返す。
- **L3 の TLS/TCP が LAN 越しに動く。** TLS 1.3、独自プロトコル。
- **L4 の単一書き手が実機で効く。** 同じ親版からの同時 push は、後着が `ConflictError` になる。
- **三方向マージが起きない。** 衝突コピーが 1 つも作られなかった。
- **双方向の同期が成立する。** Mac ↔ Pi5 の両方向で内容が一致した。
- **既存サービスを止めずに試験できる。** mini_lustre が 9001/9002 を使っている状態で、9440/9443 で動いた。

---

## 5. 測れていないこと

- **WAN 条件。** LAN の RTT は約 2ms。`PLAN.md` の想定（高遅延 200ms）は未検証。
  ハーネスは `tc qdisc` やプロキシでの注入に対応していない。
- **多数ノード。** 2 台のみ。3 台以上での委譲境界や名簿の競合は未検証。
- **Pi5 での pytest。** 入れていないため、テストは Mac 側でのみ実行した。
  Pi5 では CLI と暗号・署名を直接動かして確認した。
- **長時間運用。** 数分の試験のみ。連続 push/pull の劣化は未計測。
- **ストライピング。** 実機では 1 OST で動かした。2 OST はローカルで検証済み
  （`TestL3Striping`）だが、LAN 越しの 2 OST は未実施。

---

## 6. 再現方法

```bash
# Pi5 側
ssh -i ~/.ssh/pi-mock-test yy@192.168.0.7
cd ~/src/dfs5
python3 -m dfs5.cli serve --bind 0.0.0.0 \
  --registry-port 9440 --ost-port 9443 \
  --root-anchor /example.com \
  --root-pubkey ~/dfs5_e2e/root.pub \
  --state-dir ~/dfs5_e2e/server_state

# Mac 側
python bench/e2e_lan.py
```

生データは `bench/results/` に残る。環境や日時を含むため、比較するときは同じハーネスで取り直す。
