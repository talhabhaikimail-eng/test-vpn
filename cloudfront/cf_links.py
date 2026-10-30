#!/usr/bin/env python3
"""
cf_links.py - client links for the Xray node reached through CloudFront.

  address = CloudFront bug host (zero-rated host whose IPs are CloudFront)
  SNI/Host = our xxxx.cloudfront.net (CloudFront rejects a foreign SNI, so it can't be the bug host)

Usage:
  python3 cloudfront/cf_links.py [UUID]
  env: V2RAY_UUID, CF_DOMAIN (else cloudfront/domain.txt), CF_BUG_HOST (else the CF domain itself)
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from generate_v2ray_links import generate_vless_link, generate_vmess_link, generate_xhttp_link  # noqa: E402


def read(path):
    try:
        with open(path) as f:
            return f.readline().strip()
    except OSError:
        return ""


def main():
    uuid = (sys.argv[1] if len(sys.argv) > 1 else "") or os.environ.get("V2RAY_UUID", "") or read(".v2ray_uuid")
    dist = os.environ.get("CF_DOMAIN", "").strip() or read(os.path.join(HERE, "domain.txt"))
    if not uuid or not dist:
        sys.exit("need UUID (arg / V2RAY_UUID) and CF_DOMAIN (or run cloudfront/deploy.sh first)")
    bug = os.environ.get("CF_BUG_HOST", "").strip() or dist

    print(f"CloudFront: {dist}   address: {bug}\n")
    print("# VLESS XHTTP (recommended)")
    print(generate_xhttp_link(uuid, dist, name=f"CF-XHTTP-{bug}", address=bug))
    print("\n# VLESS WS")
    print(generate_vless_link(uuid, dist, path="/vless?ed=2048", name=f"CF-VLESS-{bug}", address=bug))
    print("\n# VMess WS")
    print(generate_vmess_link(uuid, dist, path="/vmess?ed=2048", name=f"CF-VMess-{bug}", address=bug))


if __name__ == "__main__":
    main()
