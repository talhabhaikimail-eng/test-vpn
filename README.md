# SSH + WebSocket Tunnel on GitHub Actions

This repository provides an OpenSSH + WebSocket tunnel over Ngrok for use with clients like NetMod, HTTP Custom, or any SSH client.

## Repository Configuration
- **Ngrok Domain**: `wand-dedicate-output.ngrok-free.dev`
- **Secret**: `NGROK_AUTH_TOKEN` (configured in repository secrets)

## NetMod Configuration (SSH + WebSocket)

In **NetMod**:

### 1. SSH Profile Settings
- **Mode**: `SSH`
- **Tunnel / Connection Type**: `SSH + SSL (TLS)` or `SSH + WS (WebSocket)`
- **SSH Host**: `wand-dedicate-output.ngrok-free.dev`
- **SSH Port**: `443`
- **SSL / SNI**: `wand-dedicate-output.ngrok-free.dev`
- **Username**: `vpnuser`
- **Password**: `VpnPass1234!`

### 2. Custom Payload
In NetMod's **Payload** box, paste:
```http
GET / HTTP/1.1[crlf]Host: wand-dedicate-output.ngrok-free.dev[crlf]ngrok-skip-browser-warning: 1[crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf][crlf]
```

## How It Works
1. NetMod connects to Ngrok over HTTPS/TLS (`port 443`).
2. NetMod sends the WebSocket upgrade request with custom header `ngrok-skip-browser-warning: 1`.
3. Ngrok skips the free-tier interstitial page and routes the WebSocket stream to `proxy.py` on port 80.
4. `proxy.py` returns `HTTP/1.1 101 Switching Protocols` and transparently bridges the raw TCP stream to the OpenSSH server on `127.0.0.1:22`.
5. NetMod authenticates and routes traffic as a SOCKS5/VPN tunnel.

