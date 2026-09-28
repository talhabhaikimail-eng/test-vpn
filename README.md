# Cloudflare + SSH + WebSocket Tunnel on GitHub Actions

This repository provides an OpenSSH + WebSocket tunnel connected directly to **Cloudflare's CDN Network** via `cloudflared`.

## Features
- **Cloudflare Edge**: Connected to Cloudflare's Anycast network (no Ngrok browser warning page).
- **Bug Host / Zero-Rating Support**: Dial any Cloudflare zero-rated Bug Host (e.g. `jsbl.com:80`) with `Host: <cloudflare-domain>`.
- **WS-ePRO Python Bridge**: Automatically responds with `HTTP/1.1 101 Switching Protocols` and passes raw SSH streams directly to OpenSSH.
- **Quick Tunnel & Named Tunnel**: Automatically creates a free `*.trycloudflare.com` domain by default, or accepts a permanent Cloudflare Tunnel token.

## Configuration for Tunnel Clients (NetMod / Download Engine)

- **Bug Host**: `jsbl.com` (or your carrier zero-rated host)
- **Bug Port**: `80`
- **Use TLS**: `false` (for port 80) or `true` (for port 443 with SNI)
- **SSH Host**: `<assigned>.trycloudflare.com` (or your permanent domain)
- **SSH Port**: `80`
- **Username**: `vpnuser`
- **Password**: `VpnPass1234!`

### Payload
```http
GET / HTTP/1.1[crlf]Host: [host][crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf][crlf]
```
