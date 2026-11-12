# Registry の primary / secondary と手動昇格

## 目的

読み取りは複数 registry / OST / libp2p へフォールバックできる。書き込みは単一の
primary registry に集約する。primary が停止した場合に備え、secondary を
**明示的に** primary へ昇格できるようにする。

これは自動選挙や合意形成ではない。旧 primary を停止・隔離したうえで運用者が
昇格する方式である。

## role と fencing epoch

registry state は次の 2 つを持つ。

- `role`: `primary` または `secondary`
- `role_epoch`: 昇格の世代（単調増加）

primary だけが `/v1/delegate` と `/v1/announce` を受け付ける。secondary は
`/v1/replicate` を受け付けるが、書き込みは拒否する。

writer は `remotes.json` の `role_epoch` を `announce` に載せる。registry 側の
`role_epoch` と一致しなければ `ConflictError` になる。旧 primary が `role_epoch=1`、
昇格後の secondary が `role_epoch=2` の場合、旧 primary への `role_epoch=2` の
書き込みは拒否される。

## 昇格手順

1. secondary の複製が primary に追いついていることを確認する
   - 両方の `resolve` で同じ head version / entry_hash が返ること
   - `history` で必要な版が存在すること
2. 旧 primary を停止する
3. secondary の state を昇格する

```bash
dfs promote --state-dir ~/.dfs_server --role-epoch 2
```

4. secondary を primary として再起動する

```bash
dfs serve ... --role primary --role-epoch 2
```

5. writer の `remotes.json` を更新する
   - `registry` を secondary の URL にする
   - 旧 primary を `registry_alternates` に残す（読み取り専用）
   - `role_epoch` を 2 にする

```bash
dfscli config create NAME \
  --registry http://secondary:9440 \
  --registry-alternate http://old-primary:9440 \
  --role-epoch 2 ...
```

6. DNSSEC discovery を使っている場合は、primary/secondary の URL と `epoch` を
   更新する

## 重要な制約

- 自動選挙・quorum・lease は持たない
- 旧 primary は必ず停止してから昇格する
- 旧 primary を再起動して両方を primary にしない
- 古い `role_epoch` を持つ writer は旧 primary に書き込めるため、writer 設定も
  同時に更新する
- 強固な split-brain 防止が必要なら、lease / fencing token / 合意形成を追加する

`role_epoch` は「明示的に昇格したこと」を示す fencing 値であり、単独では
ネットワーク分断を解決しない。

## 回帰試験

- `tests/test_availability.py`: secondary の write 拒否
- `tests/test_availability.py`: role_epoch 不一致の拒否
- `tests/test_availability.py`: state の promote と epoch 永続化
