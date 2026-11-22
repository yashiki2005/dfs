# Self-Hosting a Root Domain & Relay Hub

> **English** | [日本語](self-hosting.ja.md)

This guide explains how to host your own **dfs** public relay hub (for NAT traversal) or self-hosted root domain (L2 registry + L3 chunk store + DNSSEC) on a VPS.

---

## 1. Choose a Deployment Mode

| Mode | Exposed Features | Server Disk Usage | Required Ports |
|---|---|---|---|
| **A. Relay-Only Hub** | NAT traversal relay only (`/_relay/*`, `/relay/*`, `/_p2p/*`) | **~0 bytes** (in-memory forwarding) | `80`, `443` (TCP) |
| **B. Self-Hosted Root Domain** | L2 registry + L1 delegation + L3 OST + relay hub | Proportional to stored data | `80`, `443` (TCP) + optional L3 OST port |

---

## 2. Prerequisites (DNS & Firewall)

1. **DNS Record**: Point a hostname (e.g. `l2.example.com`) to your VPS public IPv4 (`A`) / IPv6 (`AAAA`).
2. **Firewall**: Open TCP `80` and `443` so Caddy can issue and terminate Let's Encrypt TLS certificates.
   * If all traffic goes through HTTPS/WSS relay, the internal `dfs` port (e.g. `9440`) does not need to be exposed publicly.

---

## 3. Install `dfs`

```bash
git clone https://github.com/yashiki2005/dfs.git ~/dfs
cd ~/dfs
python3 -m venv ~/dfs-venv
~/dfs-venv/bin/pip install -r requirements.txt
```

`dfssvc` automatically prefers `$HOME/dfs-venv/bin/python` when present.

---

## 4. Configure & Start `systemd` Service

Create `/etc/systemd/system/dfssvc.service`:

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
# Set to 0 for a relay-only hub so no L3 chunks are stored on disk
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

* `--port 9440` binds L2/Relay HTTP on `9440` and L3 OST (TLS) on `9441`. Use `--registry-port` and `--ost-port` explicitly if another service uses `9441`.
* For Mode B (also storing L3 chunks), remove `DFS_OST_MAX_BYTES=0` or set an appropriate byte cap.

Enable and start the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now dfssvc
sudo systemctl status dfssvc
```

---

## 5. Configure Caddy Reverse Proxy

Install Caddy and update `/etc/caddy/Caddyfile` according to your mode.

### Mode A: Relay-Only Hub (Recommended Minimal Surface)

Exposes only the relay and libp2p peer discovery endpoints without exposing L2 registry writes or L3 HTTP storage:

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

### Mode B: Self-Hosted Root Domain (L2 + L3 + Relay)

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

Reload Caddy:

```bash
sudo systemctl reload caddy
```

---

## 6. Verify Connectivity

Test from an external machine with `curl`:

```bash
# 1. Relay control endpoint (403 without token confirms both Caddy and dfs are responding)
curl -i https://l2.example.com/_p2p/peers

# 2. Relay forwarding path (503 "Relay node ... is not connected" is expected; 502 means dfssvc is down)
curl -i https://l2.example.com/relay/nonexistent/v1/ost
```

---

## 7. Publish via DNSSEC (Optional, Mode B)

To let clients verify your root public key and discover endpoints via `dfscli discover example.com`:

```bash
~/dfs/dfssvc dnssec myhub --domain example.com --url https://l2.example.com
```

Publish the generated JSON string as a **`_dfs.example.com` TXT** record in a DNSSEC-signed zone. Clients can then verify and join via:

```bash
dfscli discover example.com
dfscli join example.com
```

---

## 8. Connect Clients & Multi-Hub Redundancy (Dual-Homing)

### Single Custom Hub

```bash
dfs start --hub https://l2.example.com
# or
dfssvc start --join https://l2.example.com
```

### Dual-Hub Redundancy

Set up a second hub (e.g. `eu.example.com`) with the same steps and join **both** hubs simultaneously. Clients automatically rank healthy hubs by lowest RTT and fail over if one goes offline:

```bash
# Override default hubs via environment variable
export DFS_DEFAULT_HUB="https://l2.example.com,https://eu.example.com"
dfs start

# Or pass multiple flags explicitly
dfs start --hub https://l2.example.com --hub https://eu.example.com
dfssvc start --join https://l2.example.com --join https://eu.example.com
```
