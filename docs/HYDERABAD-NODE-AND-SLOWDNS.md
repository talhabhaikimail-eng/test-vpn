# Hyderabad VPS node: Mux 3 + SlowDNS (work log, 23 Oct 2026)

Local notes only. NOT committed. Contains no secrets (no keys, no PSK).
Companion file for the app side: `D:\download-engine\docs\SLOWDNS-AND-MUX3.md`.

## 1. Why this exists

The GitHub Actions nodes (Mux 1 / Mux 2) are US runners (~300 ms floor from Pakistan), restart every
6 h, and GitHub's terms do not really allow running proxies on Actions. Render got the account
suspended, and a Cloudflare Worker proxy was auto-disabled (error 1101) within minutes. The
existing Oracle VPS in Hyderabad is the only always-on option that costs nothing.

## 2. The VPS (140.245.201.178, Oracle, Ubuntu 20.04, 2 vCPU / 1 GB)

SSH: user `ubuntu`, key `ssh-key-2026-03-15.key` (repo root, git-ignored via `*.key`).
It was already running other things; none of them were touched:
nginx vhosts `talhacodes.conf`, `proxy-talhacodes.conf` (proxy.talhacodes.site -> WS-SSH on 8088),
`xray.conf`; `proxy_vps`, xray, ws-stunnel, pptp/l2tp, docker, fail2ban.

### 2.1 Added: Mux node ("Onic Mux 3")

| Item | Value |
|---|---|
| Binary | `/usr/local/bin/proxy_mux` (built from `proxy_v2ray.go quickack_linux.go muxproto.go muxserver.go`, linux/amd64) |
| Service | `v2ray-mux.service`, user `nobody`, listens `127.0.0.1:8089`, mux-only (`--vless 127.0.0.1:9 --vmess "" --xhttp ""`) |
| Key | `/etc/v2ray/mux.key` (root:nogroup 640). It is the app's built-in PSK (the XOR-obfuscated `obfPass` in `builtin.go`). Never print it. |
| nginx | `/etc/nginx/conf.d/mux-talhacodes.conf`: `mux.talhacodes.site` on 80 and 443 (uses the talhacodes.site Let's Encrypt cert), `/mux` and `/health` -> 8089, raw bytes after the 101, 86400 s timeouts |
| Rebuild | `CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o proxy_mux proxy_v2ray.go quickack_linux.go muxproto.go muxserver.go` then scp, `sudo install`, `systemctl restart v2ray-mux` |

### 2.2 Changed: SlowDNS server (dnstt)

| Item | Value |
|---|---|
| Binary | `/opt/dnstt/dnstt-server`: **patched** dnstt v1.20260501.0 (see 4.) |
| Backups | `dnstt-server.orig` (original, Oct 8), `.1200`, `.512` (earlier patch steps) in `/opt/dnstt/` |
| Unit | `/etc/systemd/system/dnstt-server.service`, domain moved to `dns.talhacodes.site`; old unit saved as `dnstt-server.service.bak-ufone` |
| Key | same server key, so public key unchanged: `47e075201d09c1b268e0e2e0e98327f6c198e10113a3c4da688c96dcce1bc772` |
| Port | UDP 53, upstream `127.0.0.1:22` |

The old domain `dns.ufone-claim.site` no longer works (the server serves one domain).

## 3. Cloudflare DNS (zone talhacodes.site)

| Type | Name | Content | Proxy |
|---|---|---|---|
| A | `mux` | 140.245.201.178 | Proxied (needed for the zero-rated bug host) |
| A | `ns` | 140.245.201.178 | **DNS only** (orange cloud breaks the delegation) |
| NS | `dns` | `ns.talhacodes.site` | n/a |

`ufone-claim.site` is about to expire. It is still used by Mux 1/2 hosts and the old SlowDNS
default; only the SlowDNS names and `deploy_slowdns_vps.sh` were moved so far.

## 4. dnstt patches (why SlowDNS did not work on the SIM)

Three carrier-resolver limits, found by capture on the VPS + probes from the phone:

1. Resolver advertises EDNS 1220 (drops to 512 after errors); stock server requires >= 1232 -> FORMERR.
   Fix: server `maxUDPPayload` 1232 -> 512. (Resolver caches a "bad" server, so this had to be
   deployed before it could recover.)
2. Server held empty replies 1 s (`maxResponseDelay`); the carrier resolver retries after ~120 ms and
   drops late answers. Fix: 40 ms.
3. Carrier silently drops query names longer than ~145 chars (144 ok, 147 fail); dnstt uses up to 253.
   Fix (client): name capacity 255 -> 140, min MTU check 80 -> 40 (effective MTU 60).

Source: module `www.bamsoftware.com/git/dnstt.git@v1.20260501.0`, built with
`CGO_ENABLED=0 GOOS=linux GOARCH=<amd64 server | arm64 client>`; only constants changed.
Patched trees were in the session scratch folder (not kept in the repo).

Measured on the phone through carrier resolvers `39.39.39.39` / `182.176.100.13`:
session up in ~10 s; stream open -> SSH banner 320-560 ms. Upstream is ~36 B per query, so
expect a few KB/s at best (chat/text only).

## 5. What the carrier allows (phone, mobile data, VPN off)

- TCP: only `141.193.213.11` (the bug host, a Cloudflare IP) connects. Everything else is refused at
  TCP level: VPS direct (any port), other Cloudflare IPs, 1.1.1.1. So no SNI trick and no direct VPS.
- DNS (UDP 53): only the carrier resolvers answer; 1.1.1.1/8.8.8.8/9.9.9.9 and the VPS are dropped.
- Phone -> bug IP RTT is 85-105 ms (PC: 7 ms).

## 6. Measurements (mux through bug host, from PC, Host: mux.talhacodes.site)

connect ~800 ms, new HTTP conn median 322 ms, DNS 247 ms, stream first byte 307 ms, 32 MB at ~40 Mbps,
transport ping 217-251 ms. Phone speedtest latency 254 ms. PC -> VPS direct is 154 ms; the
Cloudflare path (ISB colo -> Hyderabad) adds ~80-100 ms. A cloudflared tunnel from the VPS was
worse (341 ms) and was removed. Under 200 ms from the phone needs Argo or a closer origin (money).

## 7. Tried and abandoned

- Render (singapore): files kept (`render.yaml`, `render/`, mux sources added to the Docker build,
  domain set to v2ray-sg.talhacodes.site, committed 6acf868). Account suspended; never deployed.
- Cloudflare Worker VLESS proxy (`cf-worker/`, untracked): passed local tests, then error 1101
  on every route minutes after the first VLESS session. Worker `vless-edge` still deployed (dead,
  UUID secret). Do not try to disguise it to get past Cloudflare.
- Direct-to-VPS with SNI of a free site: carrier refuses the TCP connection.

## 7b. Android 10 crash (SIGSYS) fixed

`os/exec` in the SlowDNS launcher called `pidfd_open` (syscall 434), blocked by Android 10's app
seccomp filter. Now `syscall.ForkExec`. See the app notes for details.

## 8. Open items

- In-app SlowDNS test: three bugs already fixed (bug-host check, dnstt path lost in the store merge);
  next possible failure is the SSH login over the tunnel (built-in account on this VPS unverified).
- Mux 3 on mobile data: does the data balance drop with SNI `mux.talhacodes.site`? (old code comment
  says the SNI should stay a ufone-claim.site name to keep zero-rating; unverified).
- Nothing from this session is committed except render changes (38d4339, 6acf868).
- When ufone-claim.site expires: Mux 1/2 default hosts must move.
