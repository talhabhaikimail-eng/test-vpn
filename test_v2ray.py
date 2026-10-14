#!/usr/bin/env python3
"""
test_v2ray.py — High-precision Latency, Ping & Stability Benchmark for V2Ray (VLESS/VMess + WS + TLS).
Supports Cloudflare CDN Edge, Bug Host (SNI/Host) injection, and Concurrency Stress Testing.
"""

import sys
import os
import socket
import ssl
import time
import math
import base64
import statistics
import argparse
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

# ANSI Colors
CLR_RESET   = "\033[0m"
CLR_BOLD    = "\033[1m"
CLR_DIM     = "\033[2m"
CLR_RED     = "\033[91m"
CLR_GREEN   = "\033[92m"
CLR_YELLOW  = "\033[93m"
CLR_BLUE    = "\033[94m"
CLR_CYAN    = "\033[96m"
CLR_WHITE   = "\033[97m"

if sys.platform == "win32":
    os.system("")
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

def load_defaults():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    domain = os.environ.get("V2RAY_DOMAIN") or os.environ.get("CUSTOM_DOMAIN_V2RAY") or "v2ray.ufone-claim.site"
    domain_file = os.path.join(script_dir, "live_domain_v2ray.txt")
    if os.path.isfile(domain_file):
        try:
            with open(domain_file) as f:
                d = f.readline().strip()
                if d: domain = d
        except Exception:
            pass

    uuid = os.environ.get("V2RAY_UUID") or ""
    uuid_file = os.path.join(script_dir, ".v2ray_uuid")
    if os.path.isfile(uuid_file):
        try:
            with open(uuid_file) as f:
                u = f.readline().strip()
                if u: uuid = u
        except Exception:
            pass

    return domain, uuid

def probe_single(target_host, bug_host="jsbl.com", port=443, path="/vless", timeout=7.0, hold_seconds=0):
    metrics = {
        "dns_ms": 0.0,
        "tcp_ms": 0.0,
        "tls_ms": 0.0,
        "ws_ms": 0.0,
        "total_ms": 0.0,
        "status_code": "",
        "cf_ray": "",
        "error": None,
        "success": False,
        "hold_success": None,
    }

    t_start = time.perf_counter()

    # 1. DNS Resolution (resolve bug host IP)
    connect_host = bug_host if bug_host else target_host
    t0 = time.perf_counter()
    try:
        addr_info = socket.getaddrinfo(connect_host, port, socket.AF_INET, socket.SOCK_STREAM)
        ip_addr = addr_info[0][4][0]
        metrics["dns_ms"] = (time.perf_counter() - t0) * 1000.0
        metrics["ip"] = ip_addr
    except Exception as e:
        metrics["error"] = f"DNS Error ({connect_host}): {e}"
        metrics["total_ms"] = (time.perf_counter() - t_start) * 1000.0
        return metrics

    # 2. TCP Connection
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    t0 = time.perf_counter()
    try:
        s.connect((ip_addr, port))
        metrics["tcp_ms"] = (time.perf_counter() - t0) * 1000.0
    except Exception as e:
        metrics["error"] = f"TCP Connect Failed: {e}"
        s.close()
        metrics["total_ms"] = (time.perf_counter() - t_start) * 1000.0
        return metrics

    # 3. TLS Handshake (SNI set to target V2Ray domain)
    raw_socket = s
    if port == 443:
        t0 = time.perf_counter()
        try:
            ctx = ssl.create_default_context()
            s = ctx.wrap_socket(s, server_hostname=target_host)
            metrics["tls_ms"] = (time.perf_counter() - t0) * 1000.0
        except Exception as e:
            metrics["error"] = f"TLS Handshake Failed: {e}"
            raw_socket.close()
            metrics["total_ms"] = (time.perf_counter() - t_start) * 1000.0
            return metrics

    try:
        # 4. WebSocket Upgrade Handshake
        sec_key = base64.b64encode(os.urandom(16)).decode("ascii")
        req_lines = [
            f"GET {path} HTTP/1.1",
            f"Host: {target_host}",
            f"Upgrade: websocket",
            f"Connection: Upgrade",
            f"Sec-WebSocket-Key: {sec_key}",
            f"Sec-WebSocket-Version: 13",
            f"User-Agent: V2RayBench/1.0",
            "\r\n",
        ]
        payload = "\r\n".join(req_lines).encode("utf-8")

        t0 = time.perf_counter()
        s.sendall(payload)

        # Read response headers
        response_bytes = bytearray()
        s.settimeout(timeout)
        while b"\r\n\r\n" not in response_bytes:
            chunk = s.recv(1024)
            if not chunk:
                break
            response_bytes.extend(chunk)

        metrics["ws_ms"] = (time.perf_counter() - t0) * 1000.0

        if not response_bytes:
            metrics["error"] = "Empty response from server"
            return metrics

        header_part, _, _ = response_bytes.partition(b"\r\n\r\n")
        header_text = header_part.decode("utf-8", errors="replace")
        lines = header_text.splitlines()

        if lines:
            parts = lines[0].split(None, 2)
            if len(parts) >= 2:
                metrics["status_code"] = parts[1]

        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                k_lower = k.strip().lower()
                if k_lower == "cf-ray":
                    metrics["cf_ray"] = v.strip()
                elif k_lower == "x-server-info":
                    metrics["server_info"] = v.strip()

        # Check status code
        if metrics["status_code"] == "101":
            metrics["success"] = True
        elif metrics["status_code"] == "200":
            metrics["success"] = True
            metrics["server_info"] = "Health Check 200 OK"
        else:
            metrics["error"] = f"HTTP {metrics['status_code']} ({lines[0] if lines else 'unknown'})"

        # 5. Stability Hold Test
        if hold_seconds > 0 and metrics["success"]:
            time.sleep(hold_seconds)
            try:
                s.settimeout(0.5)
                s.sendall(b"")
                metrics["hold_success"] = True
            except Exception:
                metrics["hold_success"] = False

        metrics["total_ms"] = (time.perf_counter() - t_start) * 1000.0

    except socket.timeout:
        metrics["error"] = f"Timeout ({timeout}s)"
        metrics["total_ms"] = (time.perf_counter() - t_start) * 1000.0
    except Exception as e:
        metrics["error"] = f"Stream Error: {e}"
        metrics["total_ms"] = (time.perf_counter() - t_start) * 1000.0
    finally:
        try: s.close()
        except Exception: pass

    return metrics

def _ws_frame(payload):
    """Build a masked binary WebSocket frame (client -> server frames must be masked)."""
    mask = os.urandom(4)
    n = len(payload)
    if n < 126:
        hdr = bytes([0x82, 0x80 | n])
    elif n < 65536:
        hdr = bytes([0x82, 0x80 | 126]) + n.to_bytes(2, "big")
    else:
        hdr = bytes([0x82, 0x80 | 127]) + n.to_bytes(8, "big")
    return hdr + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(payload))

def _recv_exact(s, buf, n):
    while len(buf) < n:
        chunk = s.recv(65536)
        if not chunk:
            raise ConnectionError("connection closed")
        buf.extend(chunk)

def _read_ws_payload(s, buf):
    """Read one server WebSocket frame and return its payload (server frames are unmasked)."""
    _recv_exact(s, buf, 2)
    ln = buf[1] & 0x7F
    off = 2
    if ln == 126:
        _recv_exact(s, buf, 4)
        ln = int.from_bytes(buf[2:4], "big"); off = 4
    elif ln == 127:
        _recv_exact(s, buf, 10)
        ln = int.from_bytes(buf[2:10], "big"); off = 10
    _recv_exact(s, buf, off + ln)
    opcode = buf[0] & 0x0F
    payload = bytes(buf[off:off + ln])
    del buf[:off + ln]
    if opcode == 0x8:
        raise ConnectionError("server sent WS close")
    return payload

def probe_vless_data(target_host, uuid_str, bug_host="jsbl.com", port=443, path="/vless",
                     early_data=False, dest_host="www.gstatic.com", timeout=10.0):
    """
    Real end-to-end probe: WS upgrade + VLESS request to dest_host:80 + HTTP GET /generate_204.
    Measures time-to-first-byte through V2Ray, i.e. the latency a client actually feels when
    it opens a new proxied connection. With early_data=True the VLESS request rides inside the
    upgrade (Sec-WebSocket-Protocol), saving one full round trip.
    """
    import uuid as uuidlib
    m = {"tcp_ms": 0.0, "tls_ms": 0.0, "ws_ms": 0.0, "ttfb_ms": 0.0, "total_ms": 0.0,
         "status_code": "", "cf_ray": "", "error": None, "success": False}
    t_start = time.perf_counter()
    connect_host = bug_host or target_host
    try:
        ip_addr = socket.getaddrinfo(connect_host, port, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
    except Exception as e:
        m["error"] = f"DNS Error ({connect_host}): {e}"
        return m

    dest = dest_host.encode()
    http_req = f"GET /generate_204 HTTP/1.1\r\nHost: {dest_host}\r\nConnection: close\r\n\r\n".encode()
    vless_req = (b"\x00" + uuidlib.UUID(uuid_str).bytes + b"\x00" + b"\x01" + (80).to_bytes(2, "big")
                 + b"\x02" + bytes([len(dest)]) + dest + http_req)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    try:
        t0 = time.perf_counter()
        s.connect((ip_addr, port))
        m["tcp_ms"] = (time.perf_counter() - t0) * 1000.0
        if port == 443:
            t0 = time.perf_counter()
            s = ssl.create_default_context().wrap_socket(s, server_hostname=target_host)
            m["tls_ms"] = (time.perf_counter() - t0) * 1000.0

        sep = "&" if "?" in path else "?"
        req_path = f"{path}{sep}ed=2048" if early_data else path
        headers = [
            f"GET {req_path} HTTP/1.1",
            f"Host: {target_host}",
            "Upgrade: websocket",
            "Connection: Upgrade",
            f"Sec-WebSocket-Key: {base64.b64encode(os.urandom(16)).decode()}",
            "Sec-WebSocket-Version: 13",
            "User-Agent: V2RayBench/1.0",
        ]
        if early_data:
            # Xray/v2ray early-data convention: base64url (no padding) in Sec-WebSocket-Protocol
            headers.append("Sec-WebSocket-Protocol: " + base64.urlsafe_b64encode(vless_req).decode().rstrip("="))
        t_ws = time.perf_counter()
        s.sendall(("\r\n".join(headers) + "\r\n\r\n").encode())

        buf = bytearray()
        while b"\r\n\r\n" not in buf:
            chunk = s.recv(4096)
            if not chunk:
                raise ConnectionError("closed during WS upgrade")
            buf.extend(chunk)
        m["ws_ms"] = (time.perf_counter() - t_ws) * 1000.0
        head, _, rest = bytes(buf).partition(b"\r\n\r\n")
        lines = head.decode("utf-8", "replace").splitlines()
        m["status_code"] = lines[0].split()[1] if lines and len(lines[0].split()) > 1 else ""
        for line in lines[1:]:
            if line.lower().startswith("cf-ray:"):
                m["cf_ray"] = line.split(":", 1)[1].strip()
        if m["status_code"] != "101":
            m["error"] = f"HTTP {m['status_code']}"
            return m
        buf = bytearray(rest)

        if not early_data:
            s.sendall(_ws_frame(vless_req))

        # First frame: VLESS response header (ver, addons len, addons) possibly followed by data
        data = bytearray()
        payload = _read_ws_payload(s, buf)
        if not payload or payload[0] != 0:
            raise ConnectionError("bad VLESS response (wrong UUID?)")
        data.extend(payload[2 + payload[1]:])
        while not data:
            data.extend(_read_ws_payload(s, buf))
        m["ttfb_ms"] = (time.perf_counter() - t_ws) * 1000.0
        if b"204" not in data.split(b"\r\n", 1)[0]:
            m["error"] = f"Unexpected upstream reply: {bytes(data[:40])!r}"
            return m
        m["success"] = True
    except socket.timeout:
        m["error"] = f"Timeout ({timeout}s)"
    except Exception as e:
        m["error"] = f"{type(e).__name__}: {e}"
    finally:
        m["total_ms"] = (time.perf_counter() - t_start) * 1000.0
        try: s.close()
        except Exception: pass
    return m

def run_data_benchmark(target_host, uuid_str, bug_host, port, path, num_probes, early_data):
    default_d, default_u = load_defaults()
    target_host = target_host or default_d
    uuid_str = uuid_str or default_u
    if not uuid_str:
        print(f"{CLR_RED}--data needs a UUID: pass --uuid, set V2RAY_UUID, or create .v2ray_uuid{CLR_RESET}")
        return
    print(f"\n{CLR_BOLD}{CLR_CYAN}VLESS END-TO-END DATA PROBE{CLR_RESET}  {target_host}{path}  "
          f"bug-host={bug_host or 'direct'}  early-data={'ON' if early_data else 'off'}")
    print(f" {'Probe':<6} {'Status':<6} {'TLS':>9} {'WS 101':>9} {'TTFB':>9} {'Total':>9}  Info")
    results = []
    for i in range(1, num_probes + 1):
        r = probe_vless_data(target_host, uuid_str, bug_host, port, path, early_data)
        results.append(r)
        st = f"{CLR_GREEN}PASS{CLR_RESET}" if r["success"] else f"{CLR_RED}FAIL{CLR_RESET}"
        info = r["cf_ray"] if r["success"] else f"{CLR_RED}{r['error']}{CLR_RESET}"
        print(f" #{i:<5} {st}  {r['tls_ms']:>7.1f}ms {r['ws_ms']:>7.1f}ms {r['ttfb_ms']:>7.1f}ms {r['total_ms']:>7.1f}ms  {info}")
        time.sleep(0.15)
    ok = [r for r in results if r["success"]]
    print(f" Passed {len(ok)}/{len(results)}", end="")
    if ok:
        ttfb = [r["ttfb_ms"] for r in ok]
        jit = statistics.stdev(ttfb) if len(ttfb) > 1 else 0.0
        print(f" | TTFB median {statistics.median(ttfb):.1f} ms (min {min(ttfb):.1f}, max {max(ttfb):.1f}, jitter {jit:.1f})")
    else:
        print()

def run_benchmark(target_host, bug_host, port=443, path="/vless", num_probes=10, hold_seconds=0, concurrency=1):
    default_d, default_u = load_defaults()
    target_host = target_host or default_d

    print(f"\n{CLR_BOLD}{CLR_CYAN}======================================================================{CLR_RESET}")
    print(f"{CLR_BOLD}{CLR_WHITE} V2RAY CORE (VLESS/VMess + WS + TLS) BENCHMARK SUITE{CLR_RESET}")
    print(f"{CLR_BOLD}{CLR_CYAN}======================================================================{CLR_RESET}")
    print(f" {CLR_BOLD}Target Domain{CLR_RESET} : {CLR_YELLOW}{target_host}{CLR_RESET}")
    print(f" {CLR_BOLD}Bug Host (SNI){CLR_RESET}: {CLR_YELLOW}{bug_host or 'Direct'}{CLR_RESET}")
    print(f" {CLR_BOLD}Port & Scheme{CLR_RESET}: {CLR_GREEN}{port} ({'HTTPS / TLS' if port==443 else 'HTTP Plain'}){CLR_RESET}")
    print(f" {CLR_BOLD}Path{CLR_RESET}         : {CLR_GREEN}{path}{CLR_RESET}")
    print(f" {CLR_BOLD}Probes / Workers{CLR_RESET}: {num_probes} probes | Concurrency: {concurrency}")
    if hold_seconds > 0:
        print(f" {CLR_BOLD}Stability Hold{CLR_RESET} : {hold_seconds}s per probe")
    print(f"{CLR_CYAN}----------------------------------------------------------------------{CLR_RESET}")
    print(f" {'Probe':<6} {'Status':<10} {'TCP(Ping)':<11} {'TLS':<10} {'WS Upgrade':<12} {'Total':<10} {'CF-Ray / Info'}")
    print(f"{CLR_CYAN}----------------------------------------------------------------------{CLR_RESET}")

    results = []

    if concurrency > 1:
        with ThreadPoolExecutor(max_workers=concurrency) as executor:
            futures = [executor.submit(probe_single, target_host, bug_host, port, path, 7.0, hold_seconds) for _ in range(num_probes)]
            for i, fut in enumerate(as_completed(futures), 1):
                r = fut.result()
                results.append(r)
                print_probe_line(i, r)
    else:
        for i in range(1, num_probes + 1):
            r = probe_single(target_host, bug_host, port, path, 7.0, hold_seconds)
            results.append(r)
            print_probe_line(i, r)
            time.sleep(0.15)

    print_summary(results)

def print_probe_line(idx, r):
    if r["success"]:
        status_str = f"{CLR_GREEN}PASS 101{CLR_RESET}" if r["status_code"] == "101" else f"{CLR_GREEN}PASS {r['status_code']}{CLR_RESET}"
        ray_info = r.get("cf_ray") or r.get("server_info") or "OK"
        print(f" #{idx:<5} {status_str:<19} {r['tcp_ms']:>6.1f} ms   {r['tls_ms']:>6.1f} ms   {r['ws_ms']:>6.1f} ms    {r['total_ms']:>6.1f} ms   {CLR_DIM}{ray_info}{CLR_RESET}")
    else:
        status_str = f"{CLR_RED}FAIL{CLR_RESET}"
        err_msg = r.get("error") or "Unknown error"
        print(f" #{idx:<5} {status_str:<19} {r['tcp_ms']:>6.1f} ms   {r['tls_ms']:>6.1f} ms   {r['ws_ms']:>6.1f} ms    {r['total_ms']:>6.1f} ms   {CLR_RED}{err_msg}{CLR_RESET}")

def print_summary(results):
    total = len(results)
    successes = [r for r in results if r["success"]]
    failures = [r for r in results if not r["success"]]
    passed = len(successes)
    loss_pct = ((total - passed) / total) * 100.0

    print(f"\n{CLR_BOLD}{CLR_CYAN}======================================================================{CLR_RESET}")
    print(f"{CLR_BOLD}{CLR_WHITE} STATISTICAL BENCHMARK SUMMARY{CLR_RESET}")
    print(f"{CLR_BOLD}{CLR_CYAN}======================================================================{CLR_RESET}")

    status_color = CLR_GREEN if loss_pct == 0 else (CLR_YELLOW if loss_pct < 20 else CLR_RED)
    print(f" Probes Sent: {total} | Passed: {CLR_BOLD}{passed}{CLR_RESET} | Failed: {len(failures)} | Packet Loss: {status_color}{loss_pct:.1f}%{CLR_RESET}")

    if successes:
        tcp_times = [r["tcp_ms"] for r in successes]
        tls_times = [r["tls_ms"] for r in successes if r["tls_ms"] > 0]
        ws_times  = [r["ws_ms"] for r in successes if r["ws_ms"] > 0]
        tot_times = [r["total_ms"] for r in successes]

        tcp_avg = statistics.mean(tcp_times)
        tcp_med = statistics.median(tcp_times)
        tcp_std = statistics.stdev(tcp_times) if len(tcp_times) > 1 else 0.0

        ws_avg  = statistics.mean(ws_times) if ws_times else 0
        ws_med  = statistics.median(ws_times) if ws_times else 0
        ws_std  = statistics.stdev(ws_times) if len(ws_times) > 1 else 0.0

        tot_avg = statistics.mean(tot_times)
        tot_min = min(tot_times)
        tot_max = max(tot_times)
        tot_std = statistics.stdev(tot_times) if len(tot_times) > 1 else 0.0

        print(f"\n {CLR_BOLD}Layer Performance Breakdown (Medians & Jitter):{CLR_RESET}")
        print(f"   * {CLR_CYAN}Edge TCP Ping{CLR_RESET}     : {CLR_BOLD}{tcp_med:.1f} ms{CLR_RESET} (avg: {tcp_avg:.1f} ms, jitter: {tcp_std:.1f} ms)")
        if tls_times:
            tls_avg = statistics.mean(tls_times)
            tls_med = statistics.median(tls_times)
            print(f"   * {CLR_CYAN}TLS Handshake{CLR_RESET}     : {CLR_BOLD}{tls_med:.1f} ms{CLR_RESET} (avg: {tls_avg:.1f} ms)")
        print(f"   * {CLR_CYAN}WS 101 Handshake{CLR_RESET}  : {CLR_BOLD}{ws_med:.1f} ms{CLR_RESET} (avg: {ws_avg:.1f} ms, jitter: {ws_std:.1f} ms)")
        print(f"   * {CLR_CYAN}Total E2E Latency{CLR_RESET} : {CLR_BOLD}{tot_avg:.1f} ms{CLR_RESET} (min: {tot_min:.1f} ms, max: {tot_max:.1f} ms, jitter: {tot_std:.1f} ms)")

        # Stability rating
        if loss_pct == 0 and tot_std < 60:
            rating = f"{CLR_GREEN}[EXCELLENT] Rock Solid, Zero Loss, Low Jitter{CLR_RESET}"
        elif loss_pct == 0:
            rating = f"{CLR_GREEN}[STABLE] Zero Loss, Normal Jitter{CLR_RESET}"
        elif loss_pct < 10:
            rating = f"{CLR_YELLOW}[ACCEPTABLE] Minor Loss < 10%{CLR_RESET}"
        else:
            rating = f"{CLR_RED}[DEGRADED] Loss >= 10%{CLR_RESET}"
        print(f"\n {CLR_BOLD}Stability Rating{CLR_RESET}  : {rating}")
    else:
        print(f"\n {CLR_RED}All probes failed! Common causes:{CLR_RESET}")
        sample_err = failures[0]["error"] if failures else "Unknown"
        print(f"   * Last Error: {CLR_YELLOW}{sample_err}{CLR_RESET}")
        if "1016" in str(sample_err):
            print(f"   * {CLR_BOLD}Cloudflare Error 1016{CLR_RESET}: The hostname is not yet configured under Cloudflare Zero Trust 'Public Hostnames'.")
            print(f"     Add: Subdomain='v2ray', Domain='ufone-claim.site', Type='HTTP', URL='localhost:8080'")

    print(f"{CLR_BOLD}{CLR_CYAN}======================================================================{CLR_RESET}\n")

def main():
    parser = argparse.ArgumentParser(description="V2Ray WS + TLS Benchmark")
    parser.add_argument("--domain", default="", help="V2Ray public domain")
    parser.add_argument("--bug-host", default="jsbl.com", help="Bug Host / Carrier SNI (default: jsbl.com)")
    parser.add_argument("--port", type=int, default=443, help="Port (443 or 80)")
    parser.add_argument("--path", default="/vless", help="Path (/vless, /vmess, /)")
    parser.add_argument("-n", "--probes", type=int, default=10, help="Number of benchmark probes")
    parser.add_argument("-c", "--concurrency", type=int, default=1, help="Concurrent workers")
    parser.add_argument("--hold", type=int, default=0, help="Idle socket stability hold in seconds")
    parser.add_argument("--data", action="store_true", help="Real VLESS end-to-end probe (HTTP through the proxy, measures TTFB)")
    parser.add_argument("--ed", action="store_true", help="With --data: use WS early data (0-RTT VLESS request)")
    parser.add_argument("--uuid", default="", help="VLESS UUID for --data (default: V2RAY_UUID env or .v2ray_uuid)")
    args = parser.parse_args()

    if args.data:
        run_data_benchmark(args.domain, args.uuid, args.bug_host, args.port, args.path, args.probes, args.ed)
        return

    run_benchmark(args.domain, args.bug_host, args.port, args.path, args.probes, args.hold, args.concurrency)

if __name__ == "__main__":
    main()
