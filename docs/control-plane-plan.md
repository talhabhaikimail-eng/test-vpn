# Control plane plan: server list API, admin portal, OTA, VPS stats

Date: 3 Nov 2026. Target host: spare Riyadh VPS <control-plane-ip> .
Apps affected: Android `D:\download-engine\android-wstunnel`, Windows desktop `D:\download-engine` (pkg/tunnel + React UI).
All VPS work is done manually over SSH, one server at a time, never through GitHub Actions.

---

## 0. Ground truth today (why this is needed)

- Server list is hardcoded in three places: `pkg/tunnel/builtin.go`, `cmd/libwstunnel/builtin.go`, `ConfigManager.java`.
  Adding or removing a server (Mumbai now) means editing code and shipping new APKs/EXEs.
- One shared mux PSK (the SSH password) is compiled, obfuscated, into the native libs.
  Anyone who extracts it from one APK can use every node, and it can't be revoked without breaking every user.
- No visibility into node health except SSH-ing in.

### Honest security note (shapes the whole design)

A key that ships inside the app can always be extracted by a determined reverser, whatever the obfuscation.
Certificate pinning stops network interception (mitmproxy, a user-installed CA) but does nothing against static analysis of the APK.
So the plan does not rely on hiding a secret in the app. Instead:

1. **The app only embeds public keys.** These are safe to extract.
2. **Every config payload is signed** (Ed25519) by the backend. The app rejects anything not signed by our key, so a fake server or MITM can't inject servers.
3. **Payloads are encrypted per device.** The device generates its own keypair inside Android Keystore / Windows DPAPI, and the backend encrypts to that device's public key.
   A stolen response is useless on another device.
4. **Per-user node credentials replace the shared PSK.** A leaked key exposes one user, and the admin revokes it with one click.
5. **Pinning is added on top** to block casual MITM.

---

## Phase 1: Clean up and inventory (small, first)

1. Remove Mux 6 Mumbai from `pkg/tunnel/builtin.go`, `cmd/libwstunnel/builtin.go` and `ConfigManager.java`.
   Point Dubai (Mux 5) fallback back to Mux 1, and add a migration that drops saved `builtin_onic_mux6` profiles.
2. Rebuild the APK (native .so included) and the desktop EXE.
3. Read-only check of the spare server: arch, RAM, disk, OS, open OCI ports.
   This decides the sizing. If it's an A1 arm64 box, there's plenty of room. If it's an E2.1.Micro (~1 GB), add swap and stay lean.
4. Write `inventory.yaml`, the single source of truth for every active endpoint:

| Name | Type | Host / bug IP | Notes |
|---|---|---|---|
| Mux 1 / 2 | mux over CF tunnel | v2ray / tunnel-udp.ufone-claim.site | GH Actions, domain rotates |
| Mux 3 Hyderabad | mux | mux.talhacodes.site via <bug-host-3> | |
| Mux 4 Riyadh | mux | jedah.talhacodes.site via <bug-ip> | |
| Mux 5 Dubai | mux | dubai.talhacodes.site via <bug-ip> | ~500 MB RAM, careful |
| x-ui <xui-ip> | VLESS WS/TLS | xui.talhacodes.site via <bug-ip> | 3x-ui panel |
| API Gateway UAE | VLESS XHTTP | <cloudfront-bug-ip> → riyadh-vps.talhacodes.site | 29 s cut, octet-stream |
| S1 / S2 | SSH | tunnel / tunnel2.ufone-claim.site | |
| SlowDNS | DNSTT | dns.talhacodes.site (Hyderabad) | |

---

## Phase 2: Backend on the spare Riyadh VPS ("control plane")

**Stack:** one Go binary (`onic-cp`) with SQLite (WAL) and an embedded React admin UI.
Same language as the existing tunnel code, ~20–40 MB RAM, no Docker, runs as a systemd unit.

**Reachability:** the app must fetch servers before the VPN is up, on a carrier that only zero-rates bug IPs.
- Put the API behind Cloudflare as `api.talhacodes.site`, proxied, the same pattern as the mux nodes. The app dials bug IP <bug-ip> with SNI = api host, exactly like it dials Mux 4/5.
- Fallback 1: fetch through any already-working tunnel.
- Fallback 2: last-known-good cached list, plus the hardcoded list as a final bootstrap.
- The admin portal is a separate hostname (`admin.talhacodes.site`) behind **Cloudflare Access** (free up to 50 users, email OTP). It is never reachable without passing Access, plus its own login with TOTP.

**Data model:**
- `nodes`: id, name, location, type (mux / vless / xhttp / ssh / dns), host, bug IP, SNI, path, payload, enabled, weight, order, tags.
- `users`: id, name, status, expiry, data quota, max devices, notes.
- `devices`: id, user, device public key, platform, app version, last seen, revoked.
- `node_creds`: per-user secret per node type (derived, see Phase 4).
- `releases`: platform, version, URL, sha256, signature, rollout %, min version.
- `ui_config`: versioned JSON blobs (themes, strings, feature flags, server-driven layouts).
- `stats`: time series per node (agent pushes).
- `audit_log`: every admin action.

**API (all responses Ed25519-signed, device-encrypted):**

| Method | Path | Purpose |
|---|---|---|
| POST | /v1/activate | activation code + device pubkey → device id + user creds |
| POST | /v1/config | device-auth'd; returns nodes, creds, ui_config version, latest release |
| POST | /v1/ota/check | returns a signed release manifest |
| POST | /v1/heartbeat | optional: app version, current node, rough quality (for stats) |
| POST | /v1/agent/push | node agents push stats (mTLS or HMAC per node) |
| POST | /v1/ci/domain | GitHub Actions posts the new trycloudflare domain instead of committing `live_domain_*.txt` |

**Response envelope:**
```
{ v, kid, ts, nonce, exp, ct }   ct = X25519(ephemeral, devicePub) → HKDF → AES-256-GCM(payload)
sig = Ed25519(serverSignKey, all fields above)
```
- The app checks `sig` with the embedded public key and `ts`/`exp` (anti-replay, max 10 min), then decrypts with its Keystore-held private key.
- `kid` lets us rotate the signing key: the app ships two public keys (current + next).

**Backups:** a nightly SQLite `.backup` copied off-box with `scp` to another VPS. The signing private key lives only on the server, `chmod 600`, plus an offline copy you keep.

---

## Phase 3: Admin portal

Built in React, embedded in the Go binary. Sections:

1. **Dashboard:** all nodes with status (up / degraded / down), active connections, CPU, RAM, swap, net in/out, uptime, xray/mux version, last-seen.
   Each node has a 24 h sparkline.
2. **Nodes:** add, edit, disable, reorder. Changes go live on the next app config fetch, with no rebuild.
   Includes a "test" button where the backend probes the node (TLS + /health).
3. **Users / accounts:** create, extend expiry, set quota, limit devices, revoke a user or a single device, and generate activation codes or QR codes.
   Optionally syncs 3x-ui clients through its panel API for the x-ui node.
4. **Releases (OTA):** upload an APK/EXE, which is hashed and signed automatically. Set rollout % and a forced minimum version.
5. **Remote UI config:** edit theme colours, strings, banners/announcements, feature flags, and server order per user group.
   Every change is versioned with one-click rollback.
6. **Audit log, plus settings:** admin users, TOTP, key rotation.

---

## Phase 4: Per-user credentials on the nodes (replaces the shared PSK)

**Mux nodes:**
- Change the `muxproto.go` HELLO to carry a `user_id`.
- The node derives `K_user = HKDF(node_master, user_id)` and keeps a small allow/revoke list pulled from the backend every 60 s, cached on disk so a backend outage never blocks users.
- The backend gives the device `K_user`, never `node_master`.
- Keep the old shared PSK accepted during a transition window, then turn it off.

**Xray / x-ui nodes:**
- One UUID per user, created through the 3x-ui API (x-ui node) or a small sync script (Riyadh xray-xh).
- Revoking a user removes the UUID.

**Safety:**
- Roll out one node at a time, starting with Riyadh (Mux 4).
- The client and server muxproto changes must stay byte-identical across repos, as today.
- The old APK keeps working until the PSK is disabled.

---

## Phase 5: App changes (Android + desktop)

1. **Bootstrap:** on first run, generate a device keypair (Android Keystore EC/X25519 via Tink, or a raw key wrapped by `SecureStore` AES-GCM; DPAPI on Windows).
   The user enters an activation code once.
2. **Fetch on connect:** when the user taps Connect, run `/v1/config` with a 3 s budget.
   - If it fails, use the cached signed config and connect anyway, so a backend outage never blocks a connection.
   - Refresh again in the background once the tunnel is up.
3. **Dynamic server list:** profiles are built from the config instead of the hardcoded `builtin_onic_mux*` list.
   The fallback ring comes from node `order`, and the hardcoded list remains only as a first-run bootstrap.
4. **Pinning:**
   - Android uses `network_security_config` `<pin-set>`, or OkHttp-style manual pinning in our own TLS dialer (the Go side does the dialing, so pin in Go: check the SPKI hash in `tls.Config.VerifyPeerCertificate`).
   - Because Cloudflare rotates edge certificates, pin the **Cloudflare intermediate/root SPKIs** (several, with backups), not the leaf.
   - The real protection is the Ed25519 signature check, which doesn't depend on TLS at all.
5. **Hardening:**
   - Enable R8 shrinking/obfuscation (the current build uses D8 only).
   - Move the config parsing and crypto into the Go .so.
   - Add root/Frida checks as speed bumps only.
   - Keep FLAG_SECURE, and don't log secrets.

---

## Phase 6: OTA updates

What's realistic for a sideloaded app:

| What | How | Risk |
|---|---|---|
| Servers, creds, order | config API (Phase 2) | none, instant |
| UI theme, strings, banners, flags, layout tweaks | **server-driven UI**: signed `ui_config` JSON that the app applies at runtime (colours, texts, which buttons and sections show, order) | low, instant, rollback in portal |
| New code / features | **signed APK self-update**: the app downloads the APK (via the tunnel, or zero-rated through Cloudflare), checks sha256 + Ed25519 signature, then opens the system installer (`REQUEST_INSTALL_PACKAGES`). The user taps "Install", once per update. | low, same APK signing key required by Android |
| Desktop | same manifest; the EXE downloads, verifies, and the installer swaps it on restart | low |

**Not recommended:** hot-loading downloaded code (DexClassLoader, or downloading a new .so).
- It's the classic malware pattern, so Play Protect flags it.
- If the update channel is ever compromised, it hands an attacker code execution on every phone.

The signed-APK flow plus server-driven UI covers ~95% of the need.

**Server load:** APK ~10–15 MB.
- Serve it from Cloudflare (cached at the edge, so the VPS is barely touched), or from GitHub Releases as a mirror.
- Release rollout % prevents everyone downloading at once.
- The spare VPS handles this easily.

---

## Phase 7: Per-VPS stats agent (lightweight)

Tiny static Go binary `onic-agent` (~5–8 MB RAM, CGO off; arm64 + amd64 builds).
- Every 30 s it reads only `/proc` files:
  - `/proc/stat` (CPU)
  - `/proc/meminfo` (RAM/swap)
  - `/proc/net/dev` (bytes)
  - `/proc/loadavg`
  - uptime
  - `/proc/net/tcp*` (count of ESTABLISHED sockets on 443/80, giving active connections)
- Service status checks: xray, x-ui, proxy_mux, nginx.
- **Mux active sessions/streams:** add a localhost-only `/stats` endpoint to the mux server (it already tracks sessions), which the agent reads.
- **Xray/x-ui:** read the xray stats API (already enabled by 3x-ui) for per-user traffic and online clients.
- Pushes one small JSON (~1 KB) to `/v1/agent/push` over HTTPS with a per-node HMAC key.
- Cost is negligible: about 0.1% CPU and ~3 KB/min of traffic. Safe even on Dubai (500 MB).
- No dnf/apt: install by copying the binary and a systemd unit only.
- The backend keeps 7 days at 30 s resolution and 90 days of hourly rollups, and raises a "node down" alert if 3 pushes are missed (optional Telegram bot alert).

Rollout order: the spare server itself → Riyadh → x-ui node → Hyderabad → Dubai (last, most fragile). GH Actions nodes get it via their workflow, only with your OK.

---

## Phase 8: Order of work and milestones

| # | Milestone | Touches | Rough size |
|---|---|---|---|
| 1 | Mumbai removed, APK/EXE rebuilt | apps | small |
| 2 | Spare VPS provisioned: swap, nginx/TLS, Cloudflare DNS (you add `api.` + `admin.` records), Access policy | spare VPS | small |
| 3 | `onic-cp` backend + DB + signed/encrypted config API, nodes seeded from inventory | spare VPS | medium |
| 4 | Admin portal: dashboard, nodes, users, devices, audit | spare VPS | medium |
| 5 | `onic-agent` on all nodes, stats in dashboard | every VPS, one at a time | small-medium |
| 6 | Apps: activation, fetch-on-connect, cache, dynamic list, Go-side pinning, R8 | apps | medium-large |
| 7 | Per-user mux keys (muxproto HELLO change), xray UUID sync, revoke | nodes + apps | large, riskiest |
| 8 | OTA: release manifest, signed APK self-update, server-driven UI config | backend + apps | medium |
| 9 | Disable the shared PSK after all users are on new builds | nodes | small |

**Decisions needed from you before milestones 2 and 6:**
- Hostnames: `api.talhacodes.site` and `admin.talhacodes.site` OK?
- Accounts: are users individual people you hand activation codes to, or one shared "everyone" account for now (simpler, still revocable per device)?
- Is a one-tap "Install update" prompt acceptable? Fully silent install isn't possible without root or device-owner mode.

---

## Status (3 Nov 2026)

| # | Milestone | State |
|---|---|---|
| 1 | Mumbai removed from apps, APK + EXE rebuilt | **done** (not committed) |
| 2 | Spare VPS: TLS (Let's Encrypt), firewall (80/443 Cloudflare-only), systemd | **done** |
| 3 | `onic-cp` backend, signed + device-encrypted `/v1/activate` and `/v1/config`, nodes seeded | **done**, selftest passes on the server |
| 4 | Admin portal (dashboard, nodes, users/codes, devices, remote UI, releases, audit, settings) | **done**, login = password + TOTP |
| 5 | `onic-agent` on cp, Riyadh (mux4), Hyderabad (mux3), Dubai (mux5), Frankfurt (mux6, 5 Nov) | **done**; x-ui node pending (SSH key rejected) |
| 6 | Apps fetch config from the API | **done 5 Nov 2026** (Android 1.2.0, desktop 3.1.0): silent activation with a shared code (user "Public (silent)", unlimited code in /root/public-activation-code.txt on cp), mux nodes only, refresh button; pinning/R8 not done |
| 7 | Per-user mux keys | later |
| 8 | OTA in apps (signed APK self-update, server-driven UI) | backend side done; app side next |
| 9 | Disable the shared PSK | last |

Deviations from the plan:
- Admin UI is plain HTML/JS embedded in the binary (no React build step), strict CSP.
- Admin is not yet behind Cloudflare Access (needs the user's Cloudflare dashboard); it has its own password + TOTP + rate limiting meanwhile.
- Server Ed25519 public key (embed in apps): `YnC2i0LKINftwa6rz42hQXa/lmQGC71bqiJyBi7z7Ro=` (kid `k20261103`).

### App protocol reference (for milestone 6)
- `POST https://api.talhacodes.site/v1/activate` `{code, device_pub(base64 X25519), platform, app_version, label}`
- `POST /v1/config` `{device_id, token, platform, app_version, ui_version}`
- Success = Envelope `{v,kid,ts,exp,nonce,epk,ct,sig}`; verify `sig` (Ed25519) over `"onic-v1\nkid\nts\nexp\nnonce\nepk\nct"`, check `exp`, then X25519(devicePriv, epk) → HKDF-SHA256(salt = epk‖devicePub, info "onic-cp v1") → AES-256-GCM(nonce, aad = `"onic-v1|kid|ts|exp"`).
- Errors = `{error, message, ts, kid, sig}`, sig over `"onic-err\ncode\nts"`; only act on `revoked`/`account_inactive` when the signature verifies.
- Release `sig` = Ed25519 over `"onic-release\nplatform\nversion_code\nsha256hex"`.
- Reference implementation of the client side: `controlplane/cmd/onic-cp/crypto.go` `openEnvelope`.
