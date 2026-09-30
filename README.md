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

- **Bug Host**: `jsbl.com` (or your carrier zero-rated host)
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
