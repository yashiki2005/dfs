# ローカルにサーバを立てる（`dfssvc`）

## 0. 目的と位置づけ

`dfs serve` は状態ディレクトリ・root 公開鍵・L2/L3 のポートをすべて自分で用意する。
層を確かめるにはそれでよいが、「ローカルで 1 つ立てて試す」には手数が多い。
`dfssvc` はその入口で、次を肩代わりする。

1. **連続した空きポートを 2 つ探し**、1 つ目を L2（名簿）、2 つ目を L3（OST）に割り当てる。
2. root の鍵（L1 権威の Ed25519）と、**書き手の鍵**（L4 のログに署名する人）が無ければ作る。
3. 状態ディレクトリを用意し、`dfs serve` を起動する。OST チャンクだけを
   別ディスクへ置く場合は `--ost-dir` を使う。
4. 立ち上がりを待って確認し、**書き手への委譲を登録する**。
5. 接続に必要な値を記録する（`~/.config/dfs/services.json`）。
6. `stop` / `list` / `status` / `env` / `dnssec` / `logs` で後始末と確認ができる。

- 実装: `dfs/svc.py`
- エントリポイント: `./dfssvc`
- 試験: `tests/test_svc_cli.py`

---

## 1. 理由: L2 と L3 を隣り合わせにする

L2 と L3 は別のポートで待ち受ける。連続した空きを 2 つ取ると、`--registry-port N` /
`--ost-port N+1` のように覚えやすく、衝突の確認も 1 回で済む。

### 1.1 空きポートの判定（macOS の落とし穴）

**`SO_REUSEADDR` を立てた bind だけで「空き」と判断してはいけない。** macOS では
他のプロセスが `0.0.0.0:19440` で待ち受けていても、`127.0.0.1:19440` への bind は
通ってしまう（別のアドレスとして扱われるため）。

そこで `is_port_free` は 2 段で確かめる。

1. **接続を試す**（timeout 0.4 秒）。応答があれば「誰かがいる」＝使用中。
   L3 は TLS のサーバなのでハンドシェイクの前で切れるが、connect が成功した時点で
   そのポートには誰かがいると判断してよい。
2. **`SO_REUSEADDR` を付けずに bind する**。`TIME_WAIT` の残骸にも当たる。

最初はこの 2 段目を `SO_REUSEADDR` 付きで実装してしまい、launchd のサーバ（`0.0.0.0:19440`）が
あるのに `127.0.0.1:19440` を「空き」と誤判定した。上の 2 段で直っている。

さらに、記録済みのサービスが使っているポートは探索の候補から外す（同じ番号を 2 度
取らないように）。

---

## 2. コマンド

```text
dfssvc start [--name NAME] [--host HOST] [--port N] [--advertise HOST]
              [--state-dir DIR] [--ost-dir DIR] [--root-key FILE] [--root-anchor PATH]
              [--wait SECONDS] [--foreground] [--force]
dfssvc list
dfssvc status [NAME]
dfssvc stop   [NAME] [--forget]
dfssvc env    [NAME] [--workdir DIR]
dfssvc dnssec [NAME] [--domain DOMAIN] [--primary-url URL]
                     [--secondary-url URL] [--ttl SECONDS] [--epoch N]
dfssvc logs   [NAME] [-n LINES]
```

`--json` を付けると、`start` / `list` / `status` の結果を機械可読で出す。

### 2.1 引数

| 引数 | 既定 | 意味 |
|---|---|---|
| `--name` | `local` | サービスの名前。状態と記録の鍵になる |
| `--host` | `127.0.0.1` | bind するアドレス。外から使うなら `0.0.0.0` |
| `--advertise` | `--host` から推定 | L2 が L3 の場所として広告するホスト |
| `--port` | `19440` | この番号から連続した空きを探す |
| `--state-dir` | `~/dfssvc/<name>/server` | サーバの状態（チャンクと名簿） |
| `--ost-dir` | `<state-dir>/ost_chunks` | L3 OST チャンクの保存先。外付け SSD などに分離できる |
| `--root-key` | `~/dfssvc/<name>/keys/root` | L1 権威の Ed25519 鍵（無ければ作る） |
| `--root-anchor` | `/example.com` | 根のパス |
| `--writer-key` | `~/dfssvc/<name>/keys/writer` | 書き手の Ed25519 鍵（無ければ作る） |
| `--path` | `<root-anchor>/<name>` | 委譲するサブツリー。`dfscli` は鍵から引く |
| `--no-delegate` | — | 委譲を登録しない（サーバだけ立てる） |
| `--wait` | `30` | 起動を待つ秒数 |
| `--foreground` | — | 前面で動かす（Ctrl-C で停止） |
| `--force` | — | 稼働中の同名サービスを停止してから記録を作り直す |

### 2.2 記録

`~/.config/dfs/services.json`（600）に置く。`start` で書き、`stop` で PID を 0 にし、
`--forget` で消す。

```json
{
  "schema": "dfs-services-v1",
  "services": {
    "dev": {
      "name": "dev",
      "registry_port": 19441,
      "ost_port": 19442,
      "bind": "127.0.0.1",
      "advertise": "127.0.0.1",
      "state_dir": "~/dfssvc/dev/server",
      "root_key": "~/dfssvc/dev/keys/root",
      "writer_key": "~/dfssvc/dev/keys/writer",
      "sub_path": "/example.com/dev",
      "role": "primary",
      "role_epoch": 1,
      "ost_dir": "/Volumes/ExtSSD/dfs/ost/dev",
      "pid": 12345
    }
  }
}
```

`registry_url` と `ost_endpoint` は記録に書かず、読むときに組み立てる（重複を避け、
書き換えで食い違わないように）。

`ost_dir` を指定した場合、L2 の状態（`registry_state.json`）と TLS 証明書は
`--state-dir` に残り、L3 の暗号化チャンクだけが `--ost-dir` に置かれる。

```bash
dfssvc start --name dev --ost-dir /Volumes/ExtSSD/dfs/ost/dev
```

### 2.3 委譲まで自動で登録する

`dfs serve` を上げただけでは、リモートは空である（`/v1/paths` が空）。そのため
`dfscli` はサブツリーを解決できない。`dfssvc start` はここまで面倒を見る。

- 書き手の Ed25519 鍵を `~/dfssvc/<name>/keys/writer` に用意する。
- 根から見て途中の階層にも委譲を張る（L1 は多段を要求する）。`/example.com/team/notes` なら
  `/example.com/team` を経て末端へ至る。中間は root の書き手で作る。
- 末端は書き手の鍵へ委譲する。
- 同じ書き手・同じパスの委譲が既にあれば登録しない（再起動で作り直さない）。

有効期間は、**末端（書き手への委譲）を 365 日、中間を 366 日**にする。L1 は
`child.expires_at <= parent.expires_at` を要求する（Invariant 3）。親子は別のプロセスで
署名するため、同じ日数だと実行時刻が 1 秒ずれただけで子が親を超えて落ちる（試験で実際に
起きた）。中間を 1 日長くして、必ず親 > 子になるようにしている。ずれは高々数秒なので、
日単位の粗さで足りる。

`--no-delegate` を付けると、サーバだけ立てて委譲は自分で組む。

### 2.4 DNSSEC TXT を出力する

`dnssec` は、サービス記録の root 公開鍵・root アンカー・registry URL から
`_dfs.<domain>` TXT に置く JSON を生成する。

```bash
dfssvc dnssec dev
```

既定のドメインは `root_anchor` の先頭要素（`/example.com/dev` なら
`example.com`）で、registry URL はそのサービスの L2 URL。公開 DNSSEC では
必要に応じて上書きする。

```bash
dfssvc dnssec dev \
  --domain yashiki.top \
  --primary-url https://l2.yashiki.top \
  --secondary-url https://l2-b.yashiki.top \
  --ttl 300 \
  --epoch 2
```

標準出力は TXT にそのまま入れる 1 行 JSON で、レコード名は標準エラーに出す。
`--json` を付けると整形 JSON になる（`dfssvc --json dnssec dev`）。
生成値は discovery パーサで再検証し、primary がちょうど 1 つであること、
URL と TTL が有効であることを確認する。

---

## 3. 使い方

### 3.1 立てて、つないで、書く

```bash
cd ~/src/dfs

# 1. サーバを立てる（連続した空きポートを選び、鍵と委譲まで用意する）
./dfssvc start --name dev

# 2. dfscli につなぐ。L3 もサブツリーも L2 が知っているので --ost も --path も不要
./dfscli config create dev \
    --registry http://127.0.0.1:19441 \
    --key ~/dfssvc/dev/keys/writer \
    --secret dev-secret

# 3. 使う
mkdir -p /tmp/sample
echo "hello" > /tmp/sample/hello.txt
./dfscli copy /tmp/sample dev:
./dfscli ls   dev:
./dfscli cat  dev:hello.txt
```

`./dfssvc env dev` を実行すると、4 の行（`--secret` を除く）をそのまま出せる。

```
$ ./dfssvc env dev
# dev に接続する（L3 は L2 が広告するので --ost は不要）
dfscli config create dev --registry http://127.0.0.1:19441 --key ~/dfssvc/dev/keys/writer --secret <tree_secret>

# 参考: このサーバの L3 は tls://127.0.0.1:19442
#        書き手の鍵 : ~/dfssvc/dev/keys/writer（--key にそのまま使える）
#        サブツリー : /example.com/dev（L2 が鍵から引くので --path は不要）
#        L1 の root : ~/dfssvc/dev/keys/root（--signing-key に使う）
```

### 3.2 確認と後始末

```bash
./dfssvc list             # 記録済みのサービスと稼働状況
./dfssvc status dev       # 詳細と L2 の応答確認
./dfssvc logs dev -n 20   # ログの末尾
./dfssvc stop dev         # 止める（記録は残す）
./dfssvc stop dev --forget  # 止めて記録からも消す
```

`stop` は `SIGTERM` を送り、10 秒待って落ちなければ `SIGKILL` にする。

---

## 4. 試験

`tests/test_svc_cli.py` に 14 件。

| 試験 | 確かめること |
|---|---|
| `test_consecutive_ports_are_adjacent` | 返る 2 つのポートが隣り合っている |
| `test_busy_port_is_skipped` | 実際に待ち受けたポートを使われていると判定する |
| `test_start_port_that_is_busy_is_avoided` | 使用中の番号から始めても、その番号を避ける |
| `test_out_of_range_start_is_rejected` | 65535 から 2 つ取ろうとしたら弾く |
| `test_store_roundtrip_with_600` | 記録の往復と 600、派生値を書かないこと |
| `test_start_then_stop` | 起動 → 稼働中 → L2 が応答 → stop で落ちる |
| `test_same_name_without_force_is_refused` | 同じ名前を `--force` 無しで上書きしない |
| `test_two_services_get_different_ports` | 2 つ目は別の連続ペアを取る |
| `test_start_registers_delegation` | start が書き手の鍵と委譲まで用意する |
| `test_ls_works_before_any_write` | 何も書いていないリモートでも `ls` が通る |
| `test_no_delegate_leaves_registry_empty` | `--no-delegate` なら委譲を作らない |
| `test_explicit_path_is_used` | `--path` の末端と中間の両方に委譲が張られる |
| `test_dnssec_outputs_txt_json` | `dnssec` が TXT 用 JSON とレコード名を出す |
| `test_dnssec_json_and_secondary_primary_requirement` | 整形 JSON、secondary の primary 必須、secondary URL の自動追加 |

試験は `HOME` を一時ディレクトリに差し替え、その中に状態と記録を閉じる。
`tearDown` で記録に残ったサービスを全部止める（`addCleanup` は一時ディレクトリの
後始末より後に走ることがあり、順序に頼るとプロセスが残る）。

---

## 5. 注意

- **認証は無い。** `--host 0.0.0.0` で立てるなら WireGuard / LAN の中に限ること。
  完全性は L4 の署名で担保する。
- **`tree_secret` は `dfssvc` が作らない。** サーバに置かない共有秘密なので、
  `dfscli config create --secret` で自分で渡す。
- **`stop` は記録を残す。** 同じ名前で立て直すと `--force` が要る。`--force` は
  旧プロセスを停止し、同じ状態ディレクトリを同時に使うプロセスを残さない。消すなら `--forget`。
- **root 鍵は使い回す。** 同じ `--name` で立て直すと、以前の委譲がそのまま使える。
  作り直したいときは `--root-key` を別の場所にする。
- **`dfscli` の参照系は作業ディレクトリを自動で作る。** `ls` / `cat` / `size` / `check` などは
  リモートの版を読むだけだが、接続情報（解決した ost と sub_path）と HeadPin を置く場所が
  要る。`touch` を先に打たせず、その場で作る。

## 6. 落とし穴の記録

- **参照系に `touch` を要求していた。** 最初、`open_remote(create=False)` で実装したため、
  `dfscli ls` が「not initialized、先に touch を打て」と返していた。読み取り専用なのに
  初期化を求めるのは筋が悪いので、参照系も `create=True` にした。
- **`dfssvc start` が委譲を登録していなかった。** サーバは立てば動くが、リモートが空なので
  `ls` に出せるものが無く、`dfscli` はサブツリーを解決できない。start に含めた。
- **`SO_REUSEADDR` の bind で空きを誤判定していた。** §1.1 の 2 段判定に直した。
- **多段委譲の有効期間が同じで、時刻のずれで落ちていた。** 中間と末端を別プロセスで
  署名するため、1 秒ずれるだけで子の `expires_at` が親を超え、Invariant 3 に落ちる。
  中間を 1 日長くして直した（§2.3）。
- **委譲の登録に失敗すると、起動済みのサーバが孤児として残っていた。** `start` は
  サーバを起動してから委譲を登録する。登録で例外が出ると、記録にも載らないプロセスが
  ポートを掴んだまま残る（試験で実際に起きた）。失敗したら必ず止めてから抜けるように
  した（SIGTERM → 10 秒 → SIGKILL）。
