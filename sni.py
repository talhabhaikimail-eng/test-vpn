#!/usr/bin/env python3
"""
sni_check.py - classify whether a host is usable as a (spoofed) SNI.

"Usable as SNI" is TWO independent conditions. This tool is explicit about
which half it can and cannot answer:

  1. Server / on-the-wire half  -> FULLY scriptable (this tool does it):
       - Is the SNI sent in cleartext? (ECH / HTTPS-record check)
       - Does the candidate domain itself complete a normal TLS handshake?
       - Does YOUR endpoint accept this arbitrary SNI? (SNI<->IP decoupling)
       - What certificate does each side present?

  2. ISP zero-rating / accounting half -> NOT scriptable. Whether the carrier
       actually bills 0 bytes for this SNI can only be learned by pushing
       measured traffic and watching your quota. Run with --quota-guide for
       the exact procedure.

A green result here means "the TLS mechanics work". It does NOT prove the
carrier zero-rates it. Both halves must hold. See the earlier discussion:
carriers that check SNI-string-only -> any live FQDN works; carriers that
also verify destination IP / do stateful correlation -> spoofing your own
endpoint's IP will get billed regardless of what this tool reports.

Note: circumventing data charges this way typically violates an ISP's terms
of service and may have legal exposure depending on jurisdiction. This is a
diagnostic tool; know where you stand before relying on it.

Usage:
  python3 sni_check.py example.com cdn.example.com
  python3 sni_check.py example.com --endpoint 203.0.113.9
  python3 sni_check.py --file candidates.txt --endpoint 203.0.113.9:443
  python3 sni_check.py --quota-guide

Optional (nicer cert details):  pip install cryptography
"""

import argparse
import socket
import ssl
import subprocess
import sys

# ---- optional pretty cert parsing -------------------------------------------
try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    _HAVE_CRYPTO = True
except Exception:
    _HAVE_CRYPTO = False

# ---- tiny ANSI helpers ------------------------------------------------------
def _c(code, s):
    return f"\033[{code}m{s}\033[0m" if sys.stdout.isatty() else s
def ok(s):   return _c("32", s)
def bad(s):  return _c("31", s)
def warn(s): return _c("33", s)
def dim(s):  return _c("90", s)
def head(s): return _c("1;36", s)

TIMEOUT = 8


# ---- DNS / ECH --------------------------------------------------------------
def resolve(host):
    """Return list of (family, ip) A/AAAA records."""
    out = []
    try:
        for fam, _, _, _, sa in socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP):
            ip = sa[0]
            tag = "AAAA" if fam == socket.AF_INET6 else "A"
            if (tag, ip) not in out:
                out.append((tag, ip))
    except socket.gaierror as e:
        return [], str(e)
    return out, None


def https_record(host):
    """
    Query the HTTPS (SVCB type 65) record via `dig` and detect an `ech=` param.
    Returns (raw_text_or_None, ech_present_bool, note).
    """
    for args in (["dig", "+short", "HTTPS", host],
                 ["dig", "+short", "TYPE65", host]):
        try:
            r = subprocess.run(args, capture_output=True, text=True, timeout=TIMEOUT)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return None, False, "dig not available - ECH not checked"
        txt = r.stdout.strip()
        if txt:
            ech = "ech=" in txt.lower()
            return txt, ech, None
    return None, False, None  # no HTTPS record published


# ---- TLS probe (the core: SNI is decoupled from the connect target) ---------
def tls_probe(connect_ip, sni, port=443):
    """
    Open TCP to connect_ip:port, send `sni` as the SNI, accept ANY cert.
    Returns a result dict describing what happened.
    """
    res = {"ok": False, "status": "", "tls": None, "cipher": None,
           "alpn": None, "cert_der": None, "detail": ""}
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE          # we care about the handshake, not trust
    try:
        ctx.set_alpn_protocols(["h2", "http/1.1"])
    except NotImplementedError:
        pass

    try:
        raw = socket.create_connection((connect_ip, port), timeout=TIMEOUT)
    except (socket.timeout, TimeoutError):
        res["status"] = "tcp-timeout"; res["detail"] = "no TCP response (filtered?)"
        return res
    except OSError as e:
        res["status"] = "tcp-fail"; res["detail"] = str(e)
        return res

    try:
        with ctx.wrap_socket(raw, server_hostname=sni) as s:
            res["ok"] = True
            res["status"] = "handshake-ok"
            res["tls"] = s.version()
            c = s.cipher()
            res["cipher"] = c[0] if c else None
            res["alpn"] = s.selected_alpn_protocol()
            res["cert_der"] = s.getpeercert(binary_form=True)
    except ssl.SSLError as e:
        reason = (getattr(e, "reason", "") or "").upper()
        if "UNRECOGNIZED_NAME" in reason:
            res["status"] = "reject-unrecognized-name"
            res["detail"] = "server refuses this SNI (no matching vhost / reject-handshake)"
        elif "HANDSHAKE_FAILURE" in reason:
            res["status"] = "reject-handshake-failure"
            res["detail"] = reason
        else:
            res["status"] = "tls-error"
            res["detail"] = reason or str(e)
    except ConnectionResetError:
        res["status"] = "reset"; res["detail"] = "RST during handshake (DPI / firewall?)"
    except (socket.timeout, TimeoutError):
        res["status"] = "tls-timeout"; res["detail"] = "handshake stalled"
    except OSError as e:
        res["status"] = "io-error"; res["detail"] = str(e)
    finally:
        try: raw.close()
        except Exception: pass
    return res


def cert_summary(der):
    if not der:
        return dim("(no cert captured)")
    if not _HAVE_CRYPTO:
        return dim(f"cert present, {len(der)} bytes  (pip install cryptography for subject/issuer)")
    try:
        cert = x509.load_der_x509_certificate(der, default_backend())
        subj = cert.subject.rfc4514_string()
        iss = cert.issuer.rfc4514_string()
        sans = []
        try:
            ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            sans = ext.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            pass
        san_str = ", ".join(sans[:6]) + (" ..." if len(sans) > 6 else "")
        return (f"subject: {subj}\n"
                f"        issuer : {iss}\n"
                f"        SAN    : {san_str or '(none)'}")
    except Exception as e:
        return dim(f"cert parse failed: {e}")


# ---- per-host report --------------------------------------------------------
def check_host(sni, endpoint=None):
    print(head(f"\n=== {sni} ==="))

    # 1. resolution
    ips, err = resolve(sni)
    if err:
        print(bad(f"[DNS]  resolve failed: {err}"))
        print(dim("       (if the carrier zero-rates by SNI string only, resolution"))
        print(dim("        may not even matter - but you can't baseline-test it.)"))
        own_ip = None
    else:
        own_ip = ips[0][1]
        pretty = ", ".join(f"{t} {ip}" for t, ip in ips[:4])
        print(f"[DNS]  {pretty}" + (dim("  ...") if len(ips) > 4 else ""))

    # 2. ECH / HTTPS record
    raw, ech, note = https_record(sni)
    if note:
        print(warn(f"[ECH]  {note}"))
    elif ech:
        print(warn("[ECH]  HTTPS record advertises ECH -> real clients hide the SNI."))
        print(dim("       The carrier likely does NOT see this domain's SNI in cleartext"))
        print(dim("       for normal traffic, so it probably zero-rates by IP, not SNI."))
        print(dim("       Spoofing this SNI to your own IP is likely to be billed."))
    elif raw is not None:
        print(ok("[ECH]  HTTPS record present, no ECH param -> SNI is cleartext. Good."))
    else:
        print(ok("[ECH]  no HTTPS record -> SNI is cleartext on the wire. Good."))

    # 3. baseline: does the domain itself complete a handshake with its own SNI?
    if own_ip:
        r = tls_probe(own_ip, sni)
        if r["ok"]:
            print(ok(f"[BASE] handshake to {own_ip} OK  "
                     f"({r['tls']}, {r['cipher']}, alpn={r['alpn']})"))
            print(dim("       " + cert_summary(r["cert_der"])))
        else:
            print(bad(f"[BASE] handshake to its own IP failed: {r['status']} - {r['detail']}"))
            print(dim("       domain may be dead/misconfigured; weak SNI candidate."))

    # 4. decoupling test: does YOUR endpoint accept this spoofed SNI?
    if endpoint:
        ep_ip, _, ep_port = endpoint.partition(":")
        ep_port = int(ep_port) if ep_port else 443
        r = tls_probe(ep_ip, sni, ep_port)
        if r["ok"]:
            print(ok(f"[YOURS] {ep_ip}:{ep_port} ACCEPTS SNI '{sni}'  "
                     f"({r['tls']}, alpn={r['alpn']})"))
            print(dim("       -> your server will terminate TLS for this spoofed SNI."))
            print(dim("       " + cert_summary(r["cert_der"])))
        else:
            print(bad(f"[YOURS] {ep_ip}:{ep_port} rejected SNI '{sni}': "
                      f"{r['status']} - {r['detail']}"))
            print(dim("       -> fix your endpoint config (default_server / serverNames)."))
    else:
        print(dim("[YOURS] skipped - pass --endpoint YOUR_IP[:port] to test your server."))

    # 5. the part no script can answer
    print(warn("[ISP]  zero-rating is NOT verified here. Measure quota (--quota-guide)."))


QUOTA_GUIDE = """\
CARRIER ZERO-RATING TEST  (the half no script can do for you)
------------------------------------------------------------
The tool above only proves the TLS mechanics. Whether the carrier bills
0 bytes for a given SNI is empirical. Procedure:

 1. Calibration (prove your measurement works at all):
      - Record your exact data balance / quota.
      - Push a KNOWN-BILLED payload (~20-50 MB) to a non-zero-rated host.
      - Record balance again. It MUST drop. If it doesn't, your meter is
        too coarse to trust any "free" result below.

 2. Candidate test:
      - Record balance.
      - Bring up your tunnel with SNI = candidate FQDN, terminating on YOUR
        endpoint IP. Transfer the SAME measured payload size.
      - Record balance again.

 3. Classify your carrier from the delta:
      balance UNCHANGED  -> SNI-string-only accounting. The spoof works;
                            essentially any live zero-rated FQDN will do.
      balance DROPPED    -> carrier checks more than the SNI string
                            (destination IP, SNI<->IP correlation, or cert).
                            No client-side change fixes this; you'd need an
                            endpoint inside the zero-rated IP range, which you
                            don't control.

 Notes:
   - Test the EXACT FQDN you'll use. Zero-rating is usually per-FQDN, not
     wildcard: free.example.com tells you nothing about cdn.example.com.
   - Allowlists change without notice; re-test periodically.
   - Use a throwaway SIM/plan; some carriers flag anomalous SNI/IP patterns.
"""


def main():
    ap = argparse.ArgumentParser(description="Classify a host's usability as an SNI.")
    ap.add_argument("hosts", nargs="*", help="candidate SNI FQDNs")
    ap.add_argument("--file", help="file with one candidate FQDN per line")
    ap.add_argument("--endpoint", help="YOUR tunnel server IP[:port] for the decoupling test")
    ap.add_argument("--quota-guide", action="store_true", help="print the carrier zero-rating test procedure and exit")
    args = ap.parse_args()

    if args.quota_guide:
        print(QUOTA_GUIDE); return

    hosts = list(args.hosts)
    if args.file:
        with open(args.file) as f:
            hosts += [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
    if not hosts:
        ap.print_help(); return

    if not _HAVE_CRYPTO:
        print(dim("(cryptography not installed - cert subjects will be summarized briefly)"))

    for h in hosts:
        check_host(h, args.endpoint)

    print(head("\nLegend: [BASE]=domain's own server  [YOURS]=your endpoint  "
               "[ISP]=unverifiable by script"))
    print(dim("Run  python3 sni_check.py --quota-guide  for the carrier measurement steps."))


if __name__ == "__main__":
    main()
