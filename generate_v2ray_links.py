#!/usr/bin/env python3
"""
Generate client share links for the Xray node behind Cloudflare Tunnel (TLS at the edge).

  VLESS XHTTP  (recommended) plain HTTP transport: no WebSocket upgrade, so a new
               session opens in ~1 round trip instead of ~3 through the tunnel.
               Xray-based clients: v2rayNG, v2rayN, Hiddify, Streisand, Shadowrocket, NekoBox.
  VLESS/VMess WS  for clients without XHTTP (NetMod, NapsternetV, ...). Enable the
               client's Mux so one WebSocket carries many connections.
"""

import sys
import os
import json
import base64
import urllib.parse

def get_uuid():
    if len(sys.argv) > 1 and sys.argv[1].strip():
        return sys.argv[1].strip()
    if os.environ.get("V2RAY_UUID"):
        return os.environ.get("V2RAY_UUID").strip()
    if os.path.exists(".v2ray_uuid"):
        try:
            with open(".v2ray_uuid") as f:
                val = f.read().strip()
                if val: return val
        except Exception:
            pass
    if os.path.exists("/etc/v2ray/uuid.txt"):
        try:
            with open("/etc/v2ray/uuid.txt") as f:
                val = f.read().strip()
                if val: return val
        except Exception:
            pass
    return ""

def get_domain():
    if len(sys.argv) > 2 and sys.argv[2].strip():
        return sys.argv[2].strip()
    if os.environ.get("DOMAIN"):
        return os.environ.get("DOMAIN").strip()
    if os.environ.get("V2RAY_DOMAIN"):
        return os.environ.get("V2RAY_DOMAIN").strip()
    if os.path.exists("live_domain_v2ray.txt"):
        with open("live_domain_v2ray.txt") as f:
            line = f.readline().strip()
            if line:
                return line
    if os.path.exists("live_domain.txt"):
        with open("live_domain.txt") as f:
            line = f.readline().strip()
            if line:
                return line
    return "YOUR_DOMAIN"

def generate_vless_link(uuid, domain, path="/vless", name="V2Ray-VLESS-Cloudflare", address=None):
    # vless://UUID@DOMAIN:443?encryption=none&security=tls&sni=DOMAIN&type=ws&host=DOMAIN&path=%2Fvless#NAME
    params = {
        "encryption": "none",
        "security": "tls",
        "sni": domain,
        "type": "ws",
        "host": domain,
        "path": path,
    }
    query_str = urllib.parse.urlencode(params)
    link = f"vless://{uuid}@{address or domain}:443?{query_str}#{urllib.parse.quote(name)}"
    return link

def generate_xhttp_link(uuid, domain, path="/xh", name="VLESS-XHTTP", address=None, mode="packet-up"):
    # vless://UUID@ADDR:443?encryption=none&security=tls&sni=D&type=xhttp&host=D&path=%2Fxh&mode=packet-up#NAME
    # packet-up is the mode that works through CDNs that buffer uploads (Cloudflare without gRPC).
    params = {
        "encryption": "none",
        "security": "tls",
        "sni": domain,
        "type": "xhttp",
        "host": domain,
        "path": path,
        "mode": mode,
    }
    query_str = urllib.parse.urlencode(params)
    return f"vless://{uuid}@{address or domain}:443?{query_str}#{urllib.parse.quote(name)}"

def generate_vmess_link(uuid, domain, path="/vmess", name="V2Ray-VMess-Cloudflare", address=None):
    # VMess standard JSON format base64 encoded
    config = {
        "v": "2",
        "ps": name,
        "add": address or domain,
        "port": "443",
        "id": uuid,
        "aid": "0",
        "scy": "auto",
        "net": "ws",
        "type": "none",
        "host": domain,
        "path": path,
        "tls": "tls",
        "sni": domain,
        "alpn": ""
    }
    raw_json = json.dumps(config, separators=(',', ':'))
    b64 = base64.b64encode(raw_json.encode('utf-8')).decode('utf-8')
    return f"vmess://{b64}"

def main():
    uuid = get_uuid()
    domain = get_domain()

    if not uuid:
        print("[!] No UUID provided. Please provide UUID or set V2RAY_UUID environment variable.")
        return

    # ?ed=2048: Xray-based clients (v2rayNG, v2rayN, NekoBox) put the first request in the WS
    # upgrade (early data), saving one round trip per new connection. Older clients ignore it.
    vless_link = generate_vless_link(uuid, domain, path="/vless?ed=2048", name=f"VLESS-{domain}")
    vmess_link = generate_vmess_link(uuid, domain, path="/vmess?ed=2048", name=f"VMess-{domain}")

    xhttp_link = generate_xhttp_link(uuid, domain, name=f"XHTTP-{domain}")

    # Bug-host variants: client dials the carrier bug host (Cloudflare IP), SNI/Host stay on our domain
    bug_host = os.environ.get("BUG_HOST", "jsbl.com").strip()
    bug_xhttp = generate_xhttp_link(uuid, domain, name=f"XHTTP-{bug_host}", address=bug_host) if bug_host else ""
    bug_vless = generate_vless_link(uuid, domain, path="/vless?ed=2048", name=f"VLESS-{bug_host}", address=bug_host) if bug_host else ""
    bug_vmess = generate_vmess_link(uuid, domain, path="/vmess?ed=2048", name=f"VMess-{bug_host}", address=bug_host) if bug_host else ""

    print("=" * 70)
    print(" XRAY XHTTP + WS (TLS AT CLOUDFLARE EDGE, CLOUDFLARE TUNNEL)")
    print("=" * 70)
    print(f"Domain / Hostname : {domain}")
    print(f"Cloudflare Port   : 443 (TLS)")
    print(f"Local Reverse Port: 8080 (Cloudflare dashboard maps to localhost:8080)")
    print(f"XHTTP Path        : /xh  (mode packet-up)  <- fastest connects")
    print(f"VLESS WS Path     : /vless?ed=2048 (or /vless, /)")
    print(f"VMess WS Path     : /vmess?ed=2048 (or /vmess)")
    print("-" * 70)
    print(">>> VLESS XHTTP Link, recommended (v2rayNG / v2rayN / Hiddify / Streisand / Shadowrocket):")
    print(xhttp_link)
    print("-" * 70)
    print(">>> VLESS WS Link (any V2Ray client; turn on Mux, concurrency 8):")
    print(vless_link)
    print("-" * 70)
    print(">>> VMess WS Link (NetMod / NapsternetV; turn on Mux if the app has it):")
    print(vmess_link)
    if bug_host:
        print("-" * 70)
        print(f">>> Via Bug Host {bug_host} (address={bug_host}, SNI/Host={domain}):")
        print(bug_xhttp)
        print(bug_vless)
        print(bug_vmess)
    print("-" * 70)
    print("Why: through Cloudflare Tunnel every WebSocket upgrade costs ~3 round trips")
    print("(~900 ms from PK) while a plain HTTP request costs ~1 (~300 ms). XHTTP uses plain")
    print("requests; Mux makes WS clients pay the upgrade once instead of per connection.")
    print("=" * 70)

    # Output to GitHub step summary if running in GitHub Actions
    summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_file and os.path.exists(os.path.dirname(summary_file)):
        with open(summary_file, "a") as f:
            f.write("### 🚀 V2Ray WS + TLS Node Live\n")
            f.write(f"- **Domain / SNI**: `{domain}`\n")
            f.write(f"- **Port**: `443` (TLS enabled)\n")
            f.write(f"- **Cloudflared Reverse Proxy Target**: `localhost:8080`\n")
            f.write(f"- **VLESS Path**: `/vless?ed=2048` (early data; `/vless` also works)\n")
            f.write(f"- **VMess Path**: `/vmess?ed=2048` (early data; `/vmess` also works)\n\n")
            f.write("#### 🔗 Client Import Links:\n")
            f.write("```text\n")
            f.write(f"# VLESS WS + TLS\n{vless_link}\n\n")
            f.write(f"# VMess WS + TLS\n{vmess_link}\n")
            f.write("```\n")

if __name__ == "__main__":
    main()
