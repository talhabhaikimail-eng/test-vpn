# V2Ray node on Render (Singapore)

Same V2Ray stack as the GitHub Actions node (VLESS + VMess over WS, early data, IPv4 outbound),
plus a password-protected web panel with import links, QR codes and a speed test.
Singapore is ~110 ms from Pakistan vs ~235 ms for the US GitHub runners.

```
client --TLS--> Cloudflare edge (bug host jsbl.com) --> Render Singapore :$PORT
                                                         └─ proxy_v2ray ─┬─ WS /vless → v2ray :10085
                                                                         ├─ WS /vmess → v2ray :10086
                                                                         ├─ /health
                                                                         └─ other HTTP → panel :10090
```

## Deploy

1. **Render** → New → **Blueprint** → select this repo. It reads `render.yaml`.
   - Enter **V2RAY_UUID** when prompted (same value as the GitHub secret, so existing links keep working).
   - Plan is `starter` (always on). Use `standard` if many users share the node.
2. Wait for the deploy, then open `https://v2ray-sg.onrender.com/health` (your service URL may differ). It should say `OK`.
3. **Custom domain** (needed for the bug host to work, since the bug host only reaches Cloudflare):
   1. Cloudflare DNS → add `CNAME v2ray-sg` → `<your-service>.onrender.com`, **DNS only (grey cloud)**.
   2. Render → service → Settings → Custom Domains → verify `v2ray-sg.talhacodes.site` and wait for the certificate.
   3. Switch the Cloudflare record to **Proxied (orange cloud)**. SSL/TLS mode must be **Full** or **Full (strict)**.
4. **Panel**: open `https://v2ray-sg.talhacodes.site/`, log in as `admin` with **UI_PASSWORD**
   (Render → Environment tab; it was generated for you). Copy the links or scan the QR codes.

## Client settings

| Field | Value |
|---|---|
| Address | `jsbl.com` (bug host) |
| Port / TLS | `443` / on |
| SNI and Host | `v2ray-sg.talhacodes.site` |
| Network / Path | `ws` / `/vless?ed=2048` (VMess: `/vmess?ed=2048`) |

## Test from your PC

```
python test_v2ray.py --data --ed --domain v2ray-sg.talhacodes.site -n 20
```

## Environment variables

| Key | Purpose |
|---|---|
| `V2RAY_UUID` | Required. Client UUID. |
| `UI_PASSWORD` | Panel password. Remove it to disable the panel (it shows the UUID). |
| `UI_USER` | Panel username (default `admin`). |
| `BUG_HOST` | Default bug host shown in the panel (editable there). |
| `PUBLIC_HOST` | Hostname used in links (defaults to the host you open the panel on). |
| `NODE_NAME` | Label in the panel and `/health`. |
