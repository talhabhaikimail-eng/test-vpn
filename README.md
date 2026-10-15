# Cloudflare + SSH + WebSocket Tunnel on GitHub Actions (Dual-Server HA)

This repository provides a High-Availability, Dual-Server OpenSSH + WebSocket tunnel connected directly to **Cloudflare's CDN Anycast Network** via `cloudflared`.

## Dual-Server High-Availability Architecture

To prevent downtime from runner restarts, network freezes, or single-point crashes, this repository operates **two independent runner instances** (Server 1 & Server 2) acting as 2 distinct servers:

| Property | Server 1 (Primary Node) | Server 2 (Secondary Node) |
| :--- | :--- | :--- |
| **Workflow** | [server-node-1.yml](file:///.github/workflows/server-node-1.yml) | [server-node-2.yml](file:///.github/workflows/server-node-2.yml) |
| **Tunnel Mode** | Named Cloudflare Tunnel (`CLOUDFLARE_TUNNEL_TOKEN`) | Quick Tunnel (`*.trycloudflare.com`) or Token |
| **Domain Storage** | Line 1 of [live_domain.txt](file:///live_domain.txt) | Line 2 of [live_domain.txt](file:///live_domain.txt) & [live_domain_secondary.txt](file:///live_domain_secondary.txt) |
| **Cron Schedule** | `0 0,6,12,18 * * *` (00:00, 06:00, 12:00, 18:00 UTC) | `0 3,9,15,21 * * *` (03:00, 09:00, 15:00, 21:00 UTC) |
| **Stagger Offset** | **Phase A (0h offset)** | **Phase B (3h offset)** — Never restart at the same time |
| **Mutual Watchdog** | Monitors Server 2 every 3m; resurrects if down | Monitors Server 1 every 3m; resurrects if down |

### Key Resilience Guarantees:
1. **Never Down Simultaneously (3-Hour Phase Shift)**:
   - Server 1 and Server 2 schedules are intentionally offset by 3 hours.
   - When Server 1 restarts at hour 6, Server 2 is at hour 3 (peak uptime).
   - When Server 2 restarts at hour 9, Server 1 is at hour 3 (peak uptime).
2. **Mutual Cross-Resurrection**:
   - Each runner executes an active watchdog loop. If Server 1 crashes or gets terminated, Server 2 detects it within 3 minutes and dispatches Server 1, and vice-versa!
3. **Dual Domain Tracking in `live_domain.txt`**:
   - Line 1: Primary Server (e.g. `tunnel.ufone-claim.site`)
   - Line 2: Secondary Server (e.g. `*.trycloudflare.com` Cloudflare Quick Tunnel)
4. **Zero Shared Failure Point**:
   - Server 1 runs on the permanent custom domain.
   - Server 2 runs on Cloudflare's own free Quick Tunnel (`trycloudflare.com`), requiring no extra domain or token.

## V2Ray / Xray Node (XHTTP + WebSocket)

[server-v2ray.yml](file:///.github/workflows/server-v2ray.yml) runs Xray-core behind the same Cloudflare Tunnel pattern
(`v2ray.ufone-claim.site`, tracked in [live_domain_v2ray.txt](file:///live_domain_v2ray.txt)). Transports:

| Transport | Path | Use it for |
| :--- | :--- | :--- |
| **VLESS XHTTP** (`mode=packet-up`) | `/xh` | Recommended. Xray clients: v2rayNG, v2rayN, Hiddify, Streisand, Shadowrocket. |
| VLESS WS (early data) | `/vless?ed=2048` | Any V2Ray client. Enable the client's **Mux** (concurrency 8). |
| VMess WS (early data) | `/vmess?ed=2048` | NetMod, NapsternetV. Enable Mux if available. |

Why XHTTP: measured from Pakistan, a plain HTTP request through the tunnel round-trips in ~300 ms, but a WebSocket
upgrade takes ~900 ms (Cloudflare opens a fresh inter-colo connection per WebSocket; `Server-Timing: cfOrigin` shows it).
Every new proxied TCP connection is a new WebSocket, so each one paid ~1 s before data flowed. XHTTP uses plain requests
and multiplexes sessions over warm HTTP/2 connections, so a new session starts in about one round trip.

```bash
python generate_v2ray_links.py            # import links (XHTTP, VLESS WS, VMess WS, bug-host variants)
python test_v2ray.py --data --ed -n 10    # WS end-to-end TTFB benchmark (VLESS)
```

### `/mux` session protocol (Download Engine / WSTunnel desktop client)

The same node also serves a purpose-built transport on the `/mux` path for the Windows client
(`D:\download-engine\pkg\tunnel`, profile **Onic Mux (Fast)**). The client opens one "WebSocket"
through the bug host and multiplexes every TCP connection and DNS query over it with AES-256-GCM
framing (`muxproto.go`, shared verbatim with the client; `muxserver.go` is the in-process handler).
A stream opens without a confirmation round trip and DNS is answered in one frame on the node.

Measured from Pakistan via the bug host (same session, new connection each request):

| | SSH over WS | `/mux` |
| :--- | :--- | :--- |
| Connect | ~2.5 s | ~1.2 s |
| New HTTP connection (TTFB) | ~600 ms | ~305 ms |
| New HTTPS connection (TTFB) | ~925 ms | ~640 ms |
| DNS lookup | ~660 ms (2 round trips) | ~310 ms |

The pre-shared key is `secrets.SSH_PASSWORD` (installed as `/etc/v2ray/mux.key` by `setup_v2ray.sh`
when `MUX_PSK` is set; without it `/mux` is disabled). The handler refuses loopback and private targets.

## Testing & Benchmarking

Use the built-in [test_proxy.py](file:///test_proxy.py) benchmark tool:

```bash
# Test Primary Server (reads line 1 of live_domain.txt or .env):
python test_proxy.py

# Test Secondary Server (reads line 2 of live_domain.txt):
python test_proxy.py --server 2

# Audit BOTH servers in one run:
python test_proxy.py --all

# Concurrency stress test:
python test_proxy.py -n 20 -c 5
```

## Client Configuration (NetMod / Download Engine / OpenTunnel)

- **Bug Host**:  (or your carrier zero-rated host)
- **Bug Port**: `80`
- **Use TLS**: `false` (for port 80) or `true` (for port 443 with SNI)
- **SSH Host**: `<domain-from-live_domain.txt>`
- **SSH Port**: `80` (or `443` via Cloudflare SSL)
- **Username**: `vpnuser`
- **Password**: `<configured-in-github-secrets>`

### Payload
```http
GET / HTTP/1.1[crlf]Host: [host][crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf][crlf]
```
