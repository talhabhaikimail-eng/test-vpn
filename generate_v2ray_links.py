#!/usr/bin/env python3
"""
Generate V2Ray VLESS & VMess client share links and configurations.
Works with Cloudflare Tunnel (WS + TLS).
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

def generate_vless_link(uuid, domain, path="/vless", name="V2Ray-VLESS-Cloudflare"):
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
    link = f"vless://{uuid}@{domain}:443?{query_str}#{urllib.parse.quote(name)}"
    return link

def generate_vmess_link(uuid, domain, path="/vmess", name="V2Ray-VMess-Cloudflare"):
    # VMess standard JSON format base64 encoded
    config = {
        "v": "2",
        "ps": name,
        "add": domain,
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

    vless_link = generate_vless_link(uuid, domain, path="/vless", name=f"VLESS-{domain}")
    vmess_link = generate_vmess_link(uuid, domain, path="/vmess", name=f"VMess-{domain}")

    print("=" * 70)
    print(" V2RAY WS + TLS CONFIGURATION (CLOUDFLARE TUNNEL)")
    print("=" * 70)
    print(f"Domain / Hostname : {domain}")
    print(f"Cloudflare Port   : 443 (HTTPS / WSS with TLS)")
    print(f"Local Reverse Port: 8080 (Cloudflare dashboard maps to localhost:8080)")
    print(f"VLESS Path        : /vless (or /)")
    print(f"VMess Path        : /vmess")
    print("-" * 70)
    print(">>> VLESS Link (v2rayNG / Clash Meta / Sing-box / Shadowrocket):")
    print(vless_link)
    print("-" * 70)
    print(">>> VMess Link (v2rayNG / V2RayN / NetMod / NapsternetV):")
    print(vmess_link)
    print("=" * 70)

    # Output to GitHub step summary if running in GitHub Actions
    summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_file and os.path.exists(os.path.dirname(summary_file)):
        with open(summary_file, "a") as f:
            f.write("### 🚀 V2Ray WS + TLS Node Live\n")
            f.write(f"- **Domain / SNI**: `{domain}`\n")
            f.write(f"- **Port**: `443` (TLS enabled)\n")
            f.write(f"- **Cloudflared Reverse Proxy Target**: `localhost:8080`\n")
            f.write(f"- **VLESS Path**: `/vless` (or `/`)\n")
            f.write(f"- **VMess Path**: `/vmess`\n\n")
            f.write("#### 🔗 Client Import Links:\n")
            f.write("```text\n")
            f.write(f"# VLESS WS + TLS\n{vless_link}\n\n")
            f.write(f"# VMess WS + TLS\n{vmess_link}\n")
            f.write("```\n")

if __name__ == "__main__":
    main()
