#!/usr/bin/env python3
"""
cf_check.py - is a host usable as a CloudFront bug host for our distribution?

For each candidate host:
  1. Resolve it and check whether its IPs are in AWS's published CLOUDFRONT ranges.
     (Not CloudFront -> useless for this method; it may still be a Cloudflare bug host.)
  2. With --dist: connect to the candidate's IP, send SNI = Host = our distribution
     and request /xh. A reply from Xray/origin means the front works on that IP.
     A CloudFront 403/421 means the distribution is not deployed or the request was rejected.
  3. With --dist: also try SNI = candidate, Host = distribution (classic domain fronting).
     CloudFront blocks this since 2024, so expect a failure. It is shown so you know
     an SNI-checking carrier cannot be beaten with this method.

Whether the carrier actually bills 0 bytes can only be learned by pushing a few MB
through the link and checking the balance.

Usage:
  python3 cloudfront/cf_check.py www.example.com
  python3 cloudfront/cf_check.py --dist d1234abcd.cloudfront.net host1 host2
  python3 cloudfront/cf_check.py --dist "$(cat cloudfront/domain.txt)" --file candidates.txt
"""

import argparse
import ipaddress
import json
import socket
import ssl
import urllib.request

RANGES_URL = "https://ip-ranges.amazonaws.com/ip-ranges.json"


def cloudfront_nets():
    with urllib.request.urlopen(RANGES_URL, timeout=15) as r:
        data = json.load(r)
    nets = [ipaddress.ip_network(p["ip_prefix"]) for p in data["prefixes"] if p["service"] == "CLOUDFRONT"]
    nets += [ipaddress.ip_network(p["ipv6_prefix"]) for p in data["ipv6_prefixes"] if p["service"] == "CLOUDFRONT"]
    return nets


def resolve(host):
    try:
        return sorted({ai[4][0] for ai in socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)})
    except socket.gaierror as e:
        return str(e)


def probe(ip, sni, host, path="/xh"):
    """TLS to ip with the given SNI, one HTTP/1.1 GET; returns (status line, server, x-cache) or error."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((ip, 443), timeout=8) as raw, ctx.wrap_socket(raw, server_hostname=sni) as s:
            s.sendall(f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n".encode())
            s.settimeout(8)
            buf = b""
            while b"\r\n\r\n" not in buf and len(buf) < 16384:
                chunk = s.recv(4096)
                if not chunk:
                    break
                buf += chunk
    except Exception as e:
        return f"error: {e}", "", ""
    lines = buf.split(b"\r\n\r\n")[0].decode(errors="replace").split("\r\n")
    hdr = {k.strip().lower(): v.strip() for k, _, v in (l.partition(":") for l in lines[1:])}
    return lines[0] if lines else "(no response)", hdr.get("server", ""), hdr.get("x-cache", "")


def verdict(status, server, xcache):
    if status.startswith("error"):
        return "FAIL"
    code = status.split()[1] if len(status.split()) > 1 else ""
    # x-cache says "from cloudfront" on passed-through replies too; only CloudFront's own
    # error pages carry Server: CloudFront (origin replies via the tunnel say cloudflare).
    if code in ("403", "421") and server.lower() == "cloudfront":
        return "FAIL (rejected by CloudFront)"
    if code in ("502", "504"):
        return "FAIL (CloudFront reached, origin down/unreachable)"
    return "OK (reached origin)"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("hosts", nargs="*")
    ap.add_argument("--file", help="one candidate host per line")
    ap.add_argument("--dist", help="our xxxx.cloudfront.net (cloudfront/domain.txt)")
    a = ap.parse_args()

    hosts = list(a.hosts)
    if a.file:
        with open(a.file) as f:
            hosts += [l.strip() for l in f if l.strip() and not l.startswith("#")]
    if not hosts:
        ap.error("give at least one host")

    nets = cloudfront_nets()
    for h in hosts:
        print(f"\n=== {h} ===")
        ips = resolve(h)
        if isinstance(ips, str):
            print(f"  resolve failed: {ips}")
            continue
        cf_ips = [ip for ip in ips if any(ipaddress.ip_address(ip) in n for n in nets)]
        for ip in ips:
            print(f"  {ip:<40} {'CLOUDFRONT' if ip in cf_ips else 'not CloudFront'}")
        if not cf_ips:
            print("  -> not a CloudFront bug host")
            continue
        if a.dist:
            ip = next((i for i in cf_ips if ":" not in i), cf_ips[0])
            st = probe(ip, a.dist, a.dist)
            print(f"  SNI={a.dist} Host={a.dist}: {st[0]} [server={st[1]} x-cache={st[2]}] -> {verdict(*st)}")
            st = probe(ip, h, a.dist)
            print(f"  SNI={h} Host={a.dist} (domain fronting): {st[0]} [server={st[1]}] -> {verdict(*st)}")


if __name__ == "__main__":
    main()
