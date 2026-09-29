#!/usr/bin/env python3
"""
Writes the SSH pre-auth banner (HTML formatted for OpenTunnel / HTTP Custom / NetMod) and ANSI MOTD.
Usage: python3 write_banners.py "29 Sep 2026 11:47 PKT" "29 Sep 2026 17:47 PKT"
"""
import sys

start    = sys.argv[1] if len(sys.argv) > 1 else "Active"
shutdown = sys.argv[2] if len(sys.argv) > 2 else "6 Hours"

# ── Pre-auth banner — HTML styled for mobile tunnel apps (OpenTunnel / HTTP Custom / NetMod) ──
banner = f"""<div style="text-align: left; font-family: monospace; padding: 15px; background-color: #0d1117; color: #c9d1d9; border-left: 5px solid #58a6ff; line-height: 1.6; font-size: 14px; border-radius: 6px; border: 1px solid #30363d; margin: 10px 0;">
  <font color="#ffffff">[✦] STATUS: </font><font color="#76ff03"><b>ACTIVE SERVER</b></font><br>
  <font color="#c9d1d9">-----------------------------------</font><br>
  File By : <span style="color: #58a6ff; font-weight: bold; font-size: 1.2em; text-shadow: 0 0 5px #58a6ff;">Talha XD</span><br>
  <font color="#c9d1d9">-----------------------------------</font><br>
  <font color="#ffffff">[✓]</font> Protocol: <font color="#ffd600">SSH WebSocket</font><br>
  <font color="#ffffff">[✓]</font> Started  : <font color="#00e5ff">{start}</font><br>
  <font color="#ffffff">[✓]</font> Restarts : <font color="#ffab00">{shutdown}</font><br>
  <font color="#c9d1d9">-----------------------------------</font><br>
  <font color="#ff1744"><b>[!] NO DDOS | NO TORRENT | ZERO LOGS</b></font>
</div>
"""

with open("/etc/ssh/banner", "w", encoding="utf-8") as f:
    f.write(banner)
print("SSH banner written.")

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
    f"{C}  |{R}  {M}Made By Talha \u2764  \u2014  WS-SSH Tunnel{R}                       {C}|{R}\n"
    f"{C}  +========================================================+{R}\n"
    f"{C}  |{R}  {W}Started  :{R}  {G}{start:<42}{C}|{R}\n"
    f"{C}  |{R}  {W}Restarts :{R}  {Y}{shutdown:<42}{C}|{R}\n"
    f"{C}  +========================================================+{R}\n"
    f"{C}  |{R}  {G}Stay connected. Zero logs. Full speed ahead.{R}          {C}|{R}\n"
    f"{C}  +========================================================+{R}\n"
    "\n"
)
with open("/etc/motd", "w", encoding="utf-8") as f:
    f.write(motd)
print("MOTD written.")
