#!/usr/bin/env python3
"""
Writes the SSH pre-auth banner and ANSI-colored MOTD.
Usage: python3 write_banners.py "29 Sep 2026 04:01 PKT" "29 Sep 2026 10:01 PKT"
"""
import sys

start    = sys.argv[1]
shutdown = sys.argv[2]

# ── Pre-auth banner — plain ASCII (OpenSSH strips ANSI codes) ────────────────
banner = (
    "\n"
    "  +=======================================================+\n"
    "  |       Made By Talha  -  WS-SSH Tunnel               |\n"
    "  +=======================================================+\n"
    f"  |  Started  : {start:<38}|\n"
    f"  |  Restarts : {shutdown:<38}|\n"
    "  +=======================================================+\n"
    "  |  Stay connected. Zero logs. Full speed ahead.        |\n"
    "  +=======================================================+\n"
    "\n"
)
with open("/etc/ssh/banner", "w") as f:
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
with open("/etc/motd", "w") as f:
    f.write(motd)
print("MOTD written.")
