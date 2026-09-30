#!/usr/bin/env python3
"""
Writes the SSH pre-auth banner and ANSI MOTD.
Usage: python3 write_banners.py "29 Sep 2026 11:47 PKT" "29 Sep 2026 17:47 PKT"
"""
import sys
import json
import urllib.request

start       = sys.argv[1] if len(sys.argv) > 1 else "Active"
shutdown    = sys.argv[2] if len(sys.argv) > 2 else "6 Hours"
server_name = sys.argv[3] if len(sys.argv) > 3 else "Server 1"

def fetch_location():
    endpoints = [
        ("http://ip-api.com/json/?fields=city,regionName,country", lambda d: [d.get("city"), d.get("regionName"), d.get("country")]),
        ("https://ipinfo.io/json", lambda d: [d.get("city"), d.get("region"), d.get("country")]),
    ]
    for url, extractor in endpoints:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "curl/7.68.0"})
            with urllib.request.urlopen(req, timeout=3) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                parts = [p.strip() for p in extractor(data) if p and p.strip()]
                if parts:
                    return ", ".join(parts)
        except Exception:
            continue
    return "Global Edge"

location = fetch_location()

# ── Pre-auth banner — HTML styled for mobile tunnel apps (OpenTunnel / HTTP Custom / NetMod) ──
banner = f"""<div style="text-align: left; font-family: monospace; padding: 12px; background-color: #0d1117; color: #c9d1d9; border-left: 5px solid #58a6ff; line-height: 1.6; font-size: 13px; border-radius: 6px; border: 1px solid #30363d; margin: 8px 0;">
  <font color="#ffffff">[✦] STATUS: </font><font color="#76ff03"><b>ACTIVE SERVER</b></font><br>
  <font color="#c9d1d9">-----------------------------------</font><br>
  Node     : <span style="color: #58a6ff; font-weight: bold; font-size: 1.1em; text-shadow: 0 0 5px #58a6ff;">{server_name}</span><br>
  Author   : <font color="#ffd600">Made By Talha &#10084;</font><br>
  <font color="#c9d1d9">-----------------------------------</font><br>
  <font color="#ffffff">[✓]</font> Protocol : <font color="#ffd600">SSH WebSocket</font><br>
  <font color="#ffffff">[✓]</font> Started  : <font color="#00e5ff">{start}</font><br>
  <font color="#ffffff">[✓]</font> Restarts : <font color="#ffab00">{shutdown}</font><br>
  <font color="#ffffff">[✓]</font> Location : <font color="#76ff03">{location}</font><br>
  <font color="#c9d1d9">-----------------------------------</font><br>
  <font color="#ff1744"><b>[!] NO DDOS | NO TORRENT | ZERO LOGS</b></font>
</div>
"""

try:
    with open("/etc/ssh/banner", "w", encoding="utf-8") as f:
        f.write(banner)
    print(f"SSH banner written with location: {location}")
except Exception as e:
    # If running locally on Windows for testing
    print(f"Local test - location detected: {location}")

# ── MOTD — ANSI 256-color (terminal fully negotiated post-login) ─────────────
C = "\033[1;36m"   # bold cyan
G = "\033[1;32m"   # bold green
Y = "\033[1;33m"   # bold yellow
M = "\033[1;35m"   # bold magenta
W = "\033[0;37m"   # dim white
R = "\033[0m"      # reset

motd = (
    "\n"
    f"{C}  +========================================================+{R}\n"
    f"{C}  |{R}  {M}Made By Talha \u2764  \u2014  {server_name}{R}\n"
    f"{C}  +========================================================+{R}\n"
    f"{C}  |{R}  {W}Started   :{R}  {G}{start:<39}{C}|{R}\n"
    f"{C}  |{R}  {W}Restarts  :{R}  {Y}{shutdown:<39}{C}|{R}\n"
    f"{C}  |{R}  {W}Location  :{R}  {G}{location:<39}{C}|{R}\n"
    f"{C}  +========================================================+{R}\n"
    f"{C}  |{R}  {G}Stay connected. Zero logs. Full speed ahead.{R}          {C}|{R}\n"
    f"{C}  +========================================================+{R}\n"
    "\n"
)
try:
    with open("/etc/motd", "w", encoding="utf-8") as f:
        f.write(motd)
    print("MOTD written.")
except Exception:
    pass
