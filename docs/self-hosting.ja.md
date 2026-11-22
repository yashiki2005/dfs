# 自己 root ドメイン & リレーハブ構築ガイド

> [English](self-hosting.md) | **日本語**

自分の VPS 等で **dfs** の公開リレーハブ（NAT 越え中継）や自己 root ドメイン（L2 名簿 + L3 保管庫 + DNSSEC）を立ち上げるための手順書です。

---

## 1. 構成パターンの選択

用途に応じて 2 通りの公開方法があります。

| パターン | 公開する機能 | サーバーのディスク消費 | 必要な開放ポート |
|---|---|---|---|
| **A. リレーハブ専任** | NAT 越えリレー中継のみ（`/_relay/*`, `/relay/*`, `/_p2p/*`） | **ほぼ 0**（インメモリ中継のみ） | `80`, `443` (TCP) |
| **B. 自己 root ドメイン** | L2 名簿 + L1 委譲 + L3 OST + リレーハブ | 利用データ量に比例 | `80`, `443` (TCP) + 任意で L3 OST ポート |

---

## 2. 前提条件（DNS とファイアウォール）

1. **DNS レコード**: サーバーのグローバル IP（IPv4 `A` / IPv6 `AAAA`）へ向けるホスト名を用意します（例: `l2.example.com`）。
2. **ファイアウォール**: Caddy が Let's Encrypt で TLS 証明書を取得・終端するため、TCP `80` / `443` を開放します。
   * リレー経由（HTTPS/WSS）のみで運用する場合、dfs 本体のポート（例: `9440`）を外に開ける必要はありません。

---

## 3. `dfs` のインストール

```bash
git clone https://github.com/yashiki2005/dfs.git ~/dfs
cd ~/dfs
python3 -m venv ~/dfs-venv
~/dfs-venv/bin/pip install -r requirements.txt
```

※ `dfssvc` スクリプトは `$HOME/dfs-venv/bin/python` を自動的に優先して使用します。

---

## 4. `systemd` サービスの設定・起動

`/etc/systemd/system/dfssvc.service` を作成します。

```ini
[Unit]
Description=DFS Root & Relay Hub Service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=ubuntu
Group=ubuntu
WorkingDirectory=/home/ubuntu/dfs
Environment=HOME=/home/ubuntu
Environment=PYTHONUNBUFFERED=1
# パターン A（リレー専任）でディスクを使わせない場合は 0 を指定
Environment=DFS_OST_MAX_BYTES=0
ExecStart=/home/ubuntu/dfs/dfssvc start \
  --name myhub \
  --hub \
  --root-anchor /example.com \
  --advertise l2.example.com \
  --port 9440 \
  --foreground
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

* **補足**: `--port 9440` を指定すると、L2/Relay HTTP が `9440`、L3 OST (TLS) が `9441` に割り当てられます。別のサービスとポートが衝突する場合は `--registry-port 9440 --ost-port 9442` のように明示できます。
* リレーだけでなく L3 OST の保管庫としても使う場合（パターン B）は、`DFS_OST_MAX_BYTES=0` を外すか適切な上限バイト数を設定してください。

サービスを有効化して起動します:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now dfssvc
sudo systemctl status dfssvc
```

---

## 5. Caddy リバースプロキシの設定

Caddy をインストールし、`/etc/caddy/Caddyfile` を用途に合わせて設定します。

### パターン A: リレーハブ専任（推奨・最小公開面）

L2 名簿への書き込みや L3 HTTP を外部に晒さず、NAT 越えリレーと libp2p ピア探索のみを公開します。

```caddyfile
l2.example.com {
	@relay {
		path /_relay/* /relay/* /_p2p/*
	}
	handle @relay {
		reverse_proxy 127.0.0.1:9440
	}
	respond 404
}
```

### パターン B: 自己 root ドメイン（L2 名簿 + L3 + リレー）

```caddyfile
l2.example.com {
	@reads {
		method GET POST
		path /v1/resolve /v1/history /v1/paths /v1/ost /v1/archives /v1/candidacy /_ice/*
	}
	@writes {
		method POST
		path /v1/announce /v1/delegate /v1/replicate /v1/archive /v1/candidacy /v1/auto-delegate
	}
	@relay {
		path /_relay/* /relay/* /_p2p/*
	}

	handle @reads {
		reverse_proxy 127.0.0.1:9440
	}
	handle @writes {
		reverse_proxy 127.0.0.1:9440
	}
	handle @relay {
		reverse_proxy 127.0.0.1:9440
	}

	respond 404
}
```

Caddy を再読み込みします:

```bash
sudo systemctl reload caddy
```

---

## 6. 疎通確認

外部端末から `curl` で応答を確認します。

```bash
# 1. リレーハブ制御エンドポイント（認証トークン未指定で 403 が返れば Caddy + dfs ともに正常）
curl -i https://l2.example.com/_p2p/peers

# 2. リレー転送経路（503 "Relay node ... is not connected" が返れば正常、502 なら dfssvc 未起動）
curl -i https://l2.example.com/relay/nonexistent/v1/ost
```

---

## 7. DNSSEC による自己 root ドメイン公開（任意）

パターン B で、クライアントが `dfscli discover example.com` により DNSSEC 経由でルート公開鍵と接続先を自動検証できるようにする場合:

```bash
# TXT レコード用の JSON を生成
~/dfs/dfssvc dnssec myhub --domain example.com --url https://l2.example.com
```

出力された JSON 文字列を DNSSEC 有効な DNS ゾーンの **`_dfs.example.com` TXT レコード** として登録します。クライアント側からは以下で検証・参加できます:

```bash
dfscli discover example.com
dfscli join example.com
```

---

## 8. クライアントからの利用 & 複数ハブによる冗長化

### 単一の自前ハブに参加する場合

```bash
dfs start --hub https://l2.example.com
# または
dfssvc start --join https://l2.example.com
```

### 複数ハブ（Dual-Homing）で冗長化する場合

2 台目の VPS（例: `eu.example.com`）にも同じ手順でリレーハブを立てたうえで、各ノードを**両方**のハブへ同時参加させます。クライアントは生存していて RTT が低い方のハブを自動で優先利用し、片系停止時はもう片方へ自動フォールバックします。

```bash
# 環境変数で既定ハブを上書きする場合
export DFS_DEFAULT_HUB="https://l2.example.com,https://eu.example.com"
dfs start

# コマンド引数で複数指定する場合
dfs start --hub https://l2.example.com --hub https://eu.example.com
dfssvc start --join https://l2.example.com --join https://eu.example.com
```
