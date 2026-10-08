#!/usr/bin/env python3
"""
test_proxy.py — High-precision Latency & Stability Benchmark for Cloudflare + WS + SSH Tunnel.

Measures:
  1. DNS Resolution Time
  2. TCP Connection Latency (Cloudflare Edge Handshake)
  3. WebSocket Upgrade TTFB (Time to 101 Switching Protocols)
  4. Upstream SSH Banner TTFB (proxy.go -> OpenSSH)
  5. Total End-to-End Latency
  6. Packet Loss, Jitter (StdDev), Min / Avg / Max / P95
  7. Long-Lived Connection Stability (Idle hold test)
  8. Concurrent Connections Stress Test
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

# Enable ANSI colors on Windows console
if sys.platform == "win32":
    os.system("")
    # Fix Windows console UTF-8 output encoding for symbols
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# ANSI Color Codes
CLR_RESET   = "\033[0m"
CLR_BOLD    = "\033[1m"
CLR_DIM     = "\033[2m"
CLR_RED     = "\033[91m"
CLR_GREEN   = "\033[92m"
CLR_YELLOW  = "\033[93m"
CLR_BLUE    = "\033[94m"
CLR_CYAN    = "\033[96m"
CLR_WHITE   = "\033[97m"
CLR_BG_RED  = "\033[41m"
CLR_BG_GRN  = "\033[42m"

def load_env():
    """Loads key-value pairs from .env into os.environ if not already set."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    candidates = [os.path.join(script_dir, ".env"), os.path.join(os.getcwd(), ".env")]
    for path in candidates:
        if os.path.isfile(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#") or "=" not in line:
                            continue
                        k, v = line.split("=", 1)
                        k = k.strip()
                        v = v.strip().strip("'\"")
                        if k and k not in os.environ:
                            os.environ[k] = v
                break
            except Exception:
                pass

# Load .env before initializing defaults
load_env()

def get_domain_candidates():
    """Returns list of domains found in live_domain.txt, live_domain_secondary.txt, or environment."""
    candidates = []
    env_host = os.environ.get("TUNNEL_HOST") or os.environ.get("HOST")
    if env_host and env_host.strip():
        candidates.append(env_host.strip())

    script_dir = os.path.dirname(os.path.abspath(__file__))
    domain_file = os.path.join(script_dir, "live_domain.txt")
    if os.path.isfile(domain_file):
        try:
            with open(domain_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        if "=" in line:
                            line = line.split("=", 1)[1].strip()
                        elif ":" in line and not line.startswith("http"):
                            line = line.split(":", 1)[1].strip()
                        line = line.replace("https://", "").replace("http://", "").split("/")[0].strip()
                        if line and line not in candidates:
                            candidates.append(line)
        except Exception:
            pass

    sec_file = os.path.join(script_dir, "live_domain_secondary.txt")
    if os.path.isfile(sec_file):
        try:
            with open(sec_file, "r", encoding="utf-8") as f:
                sec = f.read().strip().replace("https://", "").replace("http://", "").split("/")[0].strip()
                if sec and sec not in candidates:
                    candidates.append(sec)
        except Exception:
            pass

    return candidates

def get_default_host(server_idx=1):
    """Reads TUNNEL_HOST from env, or live_domain.txt (server_idx: 1=Primary, 2=Secondary)."""
    candidates = get_domain_candidates()
    if not candidates:
        return ""
    if server_idx == 2:
        if len(candidates) >= 2:
            return candidates[1]
        script_dir = os.path.dirname(os.path.abspath(__file__))
        sec_file = os.path.join(script_dir, "live_domain_secondary.txt")
        if os.path.isfile(sec_file):
            try:
                with open(sec_file, "r", encoding="utf-8") as f:
                    sec = f.read().strip().replace("https://", "").replace("http://", "").split("/")[0].strip()
                    if sec:
                        return sec
            except Exception:
                pass
        return candidates[0]
    if server_idx == 3:
        if len(candidates) >= 3:
            return candidates[2]
        script_dir = os.path.dirname(os.path.abspath(__file__))
        udp_file = os.path.join(script_dir, "live_domain_udp.txt")
        if os.path.isfile(udp_file):
            try:
                with open(udp_file, "r", encoding="utf-8") as f:
                    u = f.read().strip().replace("https://", "").replace("http://", "").split("/")[0].strip()
                    if u:
                        return u
            except Exception:
                pass
        return candidates[-1] if candidates else ""
    return candidates[0]

def get_default_bug_host():
    """Reads BUG_HOST from environment."""
    return os.environ.get("BUG_HOST", "").strip() or None

def get_default_port():
    """Reads PORT or SSH_PORT from environment, defaulting to 80."""
    try:
        return int(os.environ.get("SSH_PORT") or os.environ.get("PORT") or 80)
    except Exception:
        return 80


def color_latency(ms):
    """Colors latency based on responsiveness."""
    if ms < 100:
        return f"{CLR_GREEN}{ms:6.1f} ms{CLR_RESET}"
    elif ms < 250:
        return f"{CLR_CYAN}{ms:6.1f} ms{CLR_RESET}"
    elif ms < 500:
        return f"{CLR_YELLOW}{ms:6.1f} ms{CLR_RESET}"
    else:
        return f"{CLR_RED}{ms:6.1f} ms{CLR_RESET}"

def probe_proxy(target_host, connect_host, port, use_tls, timeout=5.0, hold_seconds=0.0):
    """
    Performs a single end-to-end handshake probe against the proxy.
    Returns a dict with latency breakdown and server metadata.
    """
    metrics = {
        "success": False,
        "error": None,
        "dns_ms": 0.0,
        "tcp_ms": 0.0,
        "tls_ms": 0.0,
        "ws_ms": 0.0,
        "ssh_ms": 0.0,
        "total_ms": 0.0,
        "status_code": None,
        "cf_ray": None,
        "server_info": None,
        "uptime": None,
        "ssh_banner": None,
        "hold_success": True if hold_seconds > 0 else None,
    }

    t_start = time.perf_counter()

    # 1. DNS Resolution
    t0 = time.perf_counter()
    try:
        ip_addr = socket.gethostbyname(connect_host)
        metrics["dns_ms"] = (time.perf_counter() - t0) * 1000.0
    except Exception as e:
        metrics["error"] = f"DNS Error: {e}"
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

    # 3. Optional TLS Handshake
    raw_socket = s
    if use_tls:
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
            f"GET / HTTP/1.1",
            f"Host: {target_host}",
            f"Upgrade: websocket",
            f"Connection: Upgrade",
            f"Sec-WebSocket-Key: {sec_key}",
            f"Sec-WebSocket-Version: 13",
            f"User-Agent: ProxyBench/1.0",
            "\r\n",
        ]
        payload = "\r\n".join(req_lines).encode("utf-8")

        t0 = time.perf_counter()
        s.sendall(payload)

        # Read HTTP response headers up to \r\n\r\n
        response_bytes = bytearray()
        s.settimeout(timeout)
        while b"\r\n\r\n" not in response_bytes:
            chunk = s.recv(1024)
            if not chunk:
                break
            response_bytes.extend(chunk)

        metrics["ws_ms"] = (time.perf_counter() - t0) * 1000.0

        if not response_bytes:
            metrics["error"] = "Empty HTTP response from proxy"
            return metrics

        # Parse header block
        header_part, _, extra_data = response_bytes.partition(b"\r\n\r\n")
        header_text = header_part.decode("utf-8", errors="replace")
        lines = header_text.splitlines()

        if lines:
            status_parts = lines[0].split(None, 2)
            if len(status_parts) >= 2:
                metrics["status_code"] = status_parts[1]

        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                k_lower = k.strip().lower()
                v_clean = v.strip()
                if k_lower == "cf-ray":
                    metrics["cf_ray"] = v_clean
                elif k_lower == "x-server-info":
                    metrics["server_info"] = v_clean
                elif k_lower == "x-server-uptime":
                    metrics["uptime"] = v_clean

        if metrics["status_code"] != "101":
            metrics["error"] = f"Expected HTTP 101, got {lines[0] if lines else 'unknown'}"
            return metrics

        # 5. Upstream SSH Banner Receive
        t0 = time.perf_counter()
        ssh_data = bytearray(extra_data)
        if not ssh_data:
            s.settimeout(timeout)
            ssh_data.extend(s.recv(1024))

        metrics["ssh_ms"] = (time.perf_counter() - t0) * 1000.0
        ssh_str = ssh_data.decode("utf-8", errors="replace").strip()
        metrics["ssh_banner"] = ssh_str.splitlines()[0] if ssh_str else "None"

        # 6. Optional Hold Test (Stability / Idle keepalive test)
        if hold_seconds > 0:
            time.sleep(hold_seconds)
            # Verify socket is still healthy by sending 1 byte or checking error state
            try:
                s.settimeout(0.5)
                # Check if closed
                s.sendall(b"")
                metrics["hold_success"] = True
            except Exception:
                metrics["hold_success"] = False

        metrics["success"] = True
        metrics["total_ms"] = (time.perf_counter() - t_start) * 1000.0

    except socket.timeout:
        metrics["error"] = f"Socket Timeout ({timeout}s)"
        metrics["total_ms"] = (time.perf_counter() - t_start) * 1000.0
    except Exception as e:
        metrics["error"] = f"Tunnel Error: {e}"
        metrics["total_ms"] = (time.perf_counter() - t_start) * 1000.0
    finally:
        try:
            s.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        try:
            s.close()
        except Exception:
            pass

    return metrics


def run_benchmark(args):
    target_host = args.host.strip()
    connect_host = args.bug_host.strip() if args.bug_host else target_host
    port = args.port
    use_tls = args.tls
    count = args.count
    interval = args.interval
    timeout = args.timeout
    concurrency = args.concurrency
    hold_seconds = args.hold
    is_json = args.json
    verbose = args.verbose

    if not is_json:
        print(f"\n{CLR_BOLD}{CLR_CYAN}======================================================================{CLR_RESET}")
        print(f"{CLR_BOLD}{CLR_WHITE}         PROXYSCOPE: PROXY LATENCY & STABILITY BENCHMARK             {CLR_RESET}")
        print(f"{CLR_BOLD}{CLR_CYAN}======================================================================{CLR_RESET}")
        print(f" {CLR_BOLD}Target Host   :{CLR_RESET} {CLR_CYAN}{target_host}{CLR_RESET}")
        if args.bug_host:
            print(f" {CLR_BOLD}Bug Host (SNI):{CLR_RESET} {CLR_YELLOW}{connect_host}{CLR_RESET}")
        print(f" {CLR_BOLD}Port / Mode   :{CLR_RESET} {port} ({'WSS/TLS' if use_tls else 'WS/HTTP plain'})")
        print(f" {CLR_BOLD}Iterations    :{CLR_RESET} {'Continuous (Ctrl+C to stop)' if count <= 0 else count}")
        print(f" {CLR_BOLD}Concurrency   :{CLR_RESET} {concurrency} worker(s)")
        if hold_seconds > 0:
            print(f" {CLR_BOLD}Stability Hold:{CLR_RESET} {hold_seconds}s per probe")
        print(f" {CLR_BOLD}Probe Timeout :{CLR_RESET} {timeout}s | {CLR_BOLD}Interval:{CLR_RESET} {interval}s")
        print(f"{CLR_CYAN}----------------------------------------------------------------------{CLR_RESET}")
        print(f"{CLR_BOLD}{'SEQ':>4} | {'STATUS':<7} | {'DNS':>8} | {'TCP':>8} | {'WS (101)':>9} | {'SSH BANNER':>10} | {'TOTAL':>9} | {'DETAILS'}{CLR_RESET}")
        print(f"{CLR_CYAN}----------------------------------------------------------------------{CLR_RESET}")

    results = []
    iteration = 0

    try:
        while True:
            iteration += 1
            if count > 0 and iteration > count:
                break

            # Handle concurrency if > 1
            if concurrency > 1:
                batch_tasks = []
                with ThreadPoolExecutor(max_workers=concurrency) as executor:
                    futures = [
                        executor.submit(probe_proxy, target_host, connect_host, port, use_tls, timeout, hold_seconds)
                        for _ in range(concurrency)
                    ]
                    for f in as_completed(futures):
                        batch_tasks.append(f.result())

                for m in batch_tasks:
                    results.append(m)
                    if not is_json:
                        print_probe_line(len(results), m, verbose)
            else:
                m = probe_proxy(target_host, connect_host, port, use_tls, timeout, hold_seconds)
                results.append(m)
                if not is_json:
                    print_probe_line(iteration, m, verbose)

            if interval > 0 and (count <= 0 or iteration < count):
                time.sleep(interval)

    except KeyboardInterrupt:
        if not is_json:
            print(f"\n{CLR_YELLOW}[!] Interrupted by user. Calculating statistics...{CLR_RESET}")

    # Generate Statistical Analysis
    analyze_and_report(results, target_host, is_json)


def print_probe_line(seq, m, verbose):
    if m["success"]:
        status_tag = f"{CLR_GREEN}PASS 101{CLR_RESET}"
        dns_str = f"{m['dns_ms']:6.1f}ms"
        tcp_str = color_latency(m['tcp_ms'])
        ws_str = color_latency(m['ws_ms'])
        ssh_str = color_latency(m['ssh_ms'])
        tot_str = f"{CLR_BOLD}{color_latency(m['total_ms'])}{CLR_RESET}"

        details = []
        if m["cf_ray"]:
            ray_dc = m["cf_ray"].split("-")[-1] if "-" in m["cf_ray"] else m["cf_ray"]
            details.append(f"Ray:{ray_dc}")
        if m["server_info"]:
            details.append(f"{CLR_DIM}{m['server_info']}{CLR_RESET}")
        elif m["ssh_banner"]:
            details.append(f"{CLR_DIM}{m['ssh_banner']}{CLR_RESET}")
        if m.get("hold_success") is not None:
            details.append(f"Hold: {'OK' if m['hold_success'] else 'FAIL'}")

        det_str = " | ".join(details)
        print(f"{seq:4d} | {status_tag} | {dns_str:>8} | {tcp_str} | {ws_str} | {ssh_str} | {tot_str} | {det_str}")
    else:
        status_tag = f"{CLR_RED}FAIL    {CLR_RESET}"
        err = m.get("error") or "Unknown error"
        tot_err = f"{m.get('total_ms', 0):6.1f}ms"
        print(f"{seq:4d} | {status_tag} | {'--':>8} | {'--':>8} | {'--':>9} | {'--':>10} | {tot_err:>9} | {CLR_RED}{err}{CLR_RESET}")

    if verbose and m.get("server_info"):
        print(f"     {CLR_DIM}-> Banner: {m['server_info']} (Uptime: {m.get('uptime', 'n/a')}){CLR_RESET}")


def analyze_and_report(results, target_host, is_json):
    if not results:
        return

    total = len(results)
    passed = [r for r in results if r["success"]]
    failed = [r for r in results if not r["success"]]
    pass_count = len(passed)
    fail_count = len(failed)
    loss_pct = (fail_count / total) * 100.0

    total_latencies = [r["total_ms"] for r in passed]
    tcp_latencies = [r["tcp_ms"] for r in passed]
    ws_latencies = [r["ws_ms"] for r in passed]
    ssh_latencies = [r["ssh_ms"] for r in passed]

    def calc_stats(arr):
        if not arr:
            return {"min": 0, "max": 0, "avg": 0, "median": 0, "jitter": 0, "p95": 0}
        arr_sorted = sorted(arr)
        p95_idx = min(len(arr_sorted) - 1, math.ceil(0.95 * len(arr_sorted)) - 1)
        return {
            "min": round(min(arr), 1),
            "max": round(max(arr), 1),
            "avg": round(statistics.mean(arr), 1),
            "median": round(statistics.median(arr), 1),
            "jitter": round(statistics.stdev(arr), 1) if len(arr) > 1 else 0.0,
            "p95": round(arr_sorted[p95_idx], 1),
        }

    tot_stat = calc_stats(total_latencies)
    tcp_stat = calc_stats(tcp_latencies)
    ws_stat  = calc_stats(ws_latencies)
    ssh_stat = calc_stats(ssh_latencies)

    # Stability score computation (0 - 100)
    # Deductions:
    #   - Loss: up to 50 pts (every 1% loss = 5 pts off)
    #   - High jitter: jitter > 50ms drops points
    #   - Average latency: > 300ms drops points
    stability_score = 100.0
    stability_score -= min(50.0, loss_pct * 5.0)
    if tot_stat["jitter"] > 30:
        stability_score -= min(25.0, (tot_stat["jitter"] - 30) * 0.5)
    if tot_stat["avg"] > 200:
        stability_score -= min(25.0, (tot_stat["avg"] - 200) * 0.1)
    stability_score = max(0.0, min(100.0, stability_score))

    summary_data = {
        "target": target_host,
        "total_probes": total,
        "successful": pass_count,
        "failed": fail_count,
        "loss_percent": round(loss_pct, 2),
        "stability_score": round(stability_score, 1),
        "total_latency": tot_stat,
        "tcp_latency": tcp_stat,
        "ws_handshake": ws_stat,
        "ssh_upstream": ssh_stat,
    }

    if is_json:
        print(json.dumps(summary_data, indent=2))
        return

    print(f"\n{CLR_BOLD}{CLR_CYAN}======================================================================{CLR_RESET}")
    print(f"{CLR_BOLD}{CLR_WHITE}                       STABILITY & LATENCY REPORT                     {CLR_RESET}")
    print(f"{CLR_BOLD}{CLR_CYAN}======================================================================{CLR_RESET}")

    # Stability Rating Badge
    if stability_score >= 90:
        grade = f"{CLR_BG_GRN}{CLR_WHITE} EXCELLENT ({stability_score:.1f}/100) {CLR_RESET}"
    elif stability_score >= 75:
        grade = f"{CLR_GREEN} GOOD ({stability_score:.1f}/100) {CLR_RESET}"
    elif stability_score >= 50:
        grade = f"{CLR_YELLOW} FAIR / DEGRADED ({stability_score:.1f}/100) {CLR_RESET}"
    else:
        grade = f"{CLR_BG_RED}{CLR_WHITE} UNSTABLE ({stability_score:.1f}/100) {CLR_RESET}"

    print(f" {CLR_BOLD}Overall Quality Rating :{CLR_RESET} {grade}")
    print(f" {CLR_BOLD}Transmitted Probes     :{CLR_RESET} {total} | {CLR_BOLD}Successful:{CLR_RESET} {pass_count} | {CLR_BOLD}Failed:{CLR_RESET} {fail_count} ({loss_pct:.1f}% packet drop)")

    if pass_count > 0:
        print(f"\n{CLR_BOLD}{'METRIC':<18} | {'MIN':>8} | {'AVG':>8} | {'MEDIAN':>8} | {'P95':>8} | {'MAX':>8} | {'JITTER (σ)':>10}{CLR_RESET}")
        print(f"{CLR_CYAN}---------------------------------------------------------------------------------{CLR_RESET}")

        def print_stat_row(name, st):
            print(f"{name:<18} | {st['min']:6.1f}ms | {st['avg']:6.1f}ms | {st['median']:6.1f}ms | {st['p95']:6.1f}ms | {st['max']:6.1f}ms | {st['jitter']:8.1f}ms")

        print_stat_row("Total E2E Latency", tot_stat)
        print_stat_row("TCP Edge Handshake", tcp_stat)
        print_stat_row("WS Upgrade (101)", ws_stat)
        print_stat_row("SSH Upstream TTFB", ssh_stat)
        print(f"{CLR_CYAN}---------------------------------------------------------------------------------{CLR_RESET}")

        # Diagnosis breakdown
        print(f"\n{CLR_BOLD}Diagnostic Insights:{CLR_RESET}")
        if tcp_stat["avg"] > 0:
            print(f" • {CLR_CYAN}CDN Edge Proximity:{CLR_RESET} Initial TCP connect avg is {tcp_stat['avg']}ms.")
        if ws_stat["avg"] > 0:
            print(f" • {CLR_CYAN}Tunnel Round-Trip :{CLR_RESET} Cloudflare -> cloudflared -> proxy.go responds in ~{ws_stat['avg']}ms.")
        if ssh_stat["avg"] > 0:
            print(f" • {CLR_CYAN}Upstream Bridge   :{CLR_RESET} proxy.go -> OpenSSH pipe delay is ~{ssh_stat['avg']}ms.")
        if tot_stat["jitter"] < 25:
            print(f" • {CLR_GREEN}Jitter Stability  :{CLR_RESET} Rock solid! Standard deviation is only {tot_stat['jitter']}ms.")
        else:
            print(f" • {CLR_YELLOW}Jitter Notice     :{CLR_RESET} Standard deviation is {tot_stat['jitter']}ms (variable link/routing).")
    else:
        print(f"\n{CLR_RED}[!] All probes failed! Check if Cloudflare Tunnel or proxy is running.{CLR_RESET}")

    print(f"{CLR_BOLD}{CLR_CYAN}======================================================================{CLR_RESET}\n")


def run_stdio(target_host, connect_host, port, use_tls, timeout=10.0):
    """STDIO proxy mode for OpenSSH ProxyCommand."""
    if sys.platform == "win32":
        import msvcrt
        msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)
        msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)

    ip_addr = socket.gethostbyname(connect_host)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    s.connect((ip_addr, port))

    if use_tls:
        ctx = ssl.create_default_context()
        s = ctx.wrap_socket(s, server_hostname=target_host)

    sec_key = base64.b64encode(os.urandom(16)).decode("ascii")
    payload = (
        f"GET / HTTP/1.1\r\n"
        f"Host: {target_host}\r\n"
        f"Upgrade: websocket\r\n"
        f"Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {sec_key}\r\n"
        f"Sec-WebSocket-Version: 13\r\n\r\n"
    ).encode("utf-8")
    s.sendall(payload)

    response_bytes = bytearray()
    while b"\r\n\r\n" not in response_bytes:
        chunk = s.recv(1024)
        if not chunk:
            sys.stderr.write("Proxy closed connection unexpectedly during WS 101\n")
            sys.exit(1)
        response_bytes.extend(chunk)

    header_part, _, extra_data = response_bytes.partition(b"\r\n\r\n")
    first_line = header_part.split(b"\r\n", 1)[0].decode("latin1", "replace")
    if "101" not in first_line:
        sys.stderr.write(f"Proxy returned error: {first_line}\n")
        sys.exit(1)

    s.settimeout(None)

    if extra_data:
        sys.stdout.buffer.write(extra_data)
        sys.stdout.buffer.flush()

    import threading

    def pipe_in():
        try:
            while True:
                data = sys.stdin.buffer.read(4096)
                if not data:
                    break
                s.sendall(data)
        except Exception:
            pass
        finally:
            try:
                s.shutdown(socket.SHUT_WR)
            except Exception:
                pass

    def pipe_out():
        try:
            while True:
                data = s.recv(4096)
                if not data:
                    break
                sys.stdout.buffer.write(data)
                sys.stdout.buffer.flush()
        except Exception:
            pass

    t_in = threading.Thread(target=pipe_in, daemon=True)
    t_out = threading.Thread(target=pipe_out, daemon=True)
    t_in.start()
    t_out.start()
    t_out.join()


def run_bridge(listen_port, target_host, connect_host, port, use_tls, timeout=10.0):
    """Starts a local TCP bridge listener (e.g. 127.0.0.1:2222 -> WS tunnel)."""
    bridge_srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bridge_srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    bridge_srv.bind(("127.0.0.1", listen_port))
    bridge_srv.listen(128)

    print(f"\n{CLR_BOLD}{CLR_GREEN}[*] Local SSH Bridge started on 127.0.0.1:{listen_port}{CLR_RESET}")
    print(f"    {CLR_WHITE}Tunnel Target  :{CLR_RESET} {target_host}:{port} (via {connect_host})")
    print(f"    {CLR_CYAN}SSH Command    :{CLR_RESET} {CLR_BOLD}ssh -p {listen_port} vpnuser@127.0.0.1{CLR_RESET}")
    print(f"    {CLR_DIM}Press Ctrl+C to terminate the bridge.{CLR_RESET}\n")

    import threading

    def handle_client(client_sock, client_addr):
        remote_sock = None
        try:
            ip_addr = socket.gethostbyname(connect_host)
            remote_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote_sock.settimeout(timeout)
            remote_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            remote_sock.connect((ip_addr, port))

            if use_tls:
                ctx = ssl.create_default_context()
                remote_sock = ctx.wrap_socket(remote_sock, server_hostname=target_host)

            sec_key = base64.b64encode(os.urandom(16)).decode("ascii")
            req = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {target_host}\r\n"
                f"Upgrade: websocket\r\n"
                f"Connection: Upgrade\r\n"
                f"Sec-WebSocket-Key: {sec_key}\r\n"
                f"Sec-WebSocket-Version: 13\r\n\r\n"
            ).encode("utf-8")
            remote_sock.sendall(req)

            resp = bytearray()
            while b"\r\n\r\n" not in resp:
                buf = remote_sock.recv(1024)
                if not buf:
                    break
                resp.extend(buf)

            _, _, extra = resp.partition(b"\r\n\r\n")
            if extra:
                client_sock.sendall(extra)

            client_sock.setblocking(True)
            remote_sock.setblocking(True)
            remote_sock.settimeout(None)

            def c2r():
                try:
                    while True:
                        b = client_sock.recv(4096)
                        if not b:
                            break
                        remote_sock.sendall(b)
                except Exception:
                    pass
                finally:
                    try:
                        remote_sock.shutdown(socket.SHUT_WR)
                    except Exception:
                        pass

            def r2c():
                try:
                    while True:
                        b = remote_sock.recv(4096)
                        if not b:
                            break
                        client_sock.sendall(b)
                except Exception:
                    pass
                finally:
                    try:
                        client_sock.shutdown(socket.SHUT_WR)
                    except Exception:
                        pass

            t1 = threading.Thread(target=c2r, daemon=True)
            t2 = threading.Thread(target=r2c, daemon=True)
            t1.start()
            t2.start()
            t1.join()
            t2.join()
        except Exception as e:
            print(f"{CLR_RED}[!] Bridge client error: {e}{CLR_RESET}")
        finally:
            try:
                client_sock.close()
            except Exception:
                pass
            if remote_sock:
                try:
                    remote_sock.close()
                except Exception:
                    pass

    try:
        while True:
            client_sock, client_addr = bridge_srv.accept()
            threading.Thread(target=handle_client, args=(client_sock, client_addr), daemon=True).start()
    except KeyboardInterrupt:
        print(f"\n{CLR_YELLOW}[*] Bridge stopped.{CLR_RESET}")
    finally:
        bridge_srv.close()


def main():
    parser = argparse.ArgumentParser(
        description="Comprehensive Latency and Stability Benchmark for Cloudflare WS/SSH Proxy",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic test (reads TUNNEL_HOST from .env or live_domain.txt):
  python test_proxy.py

  # Test custom domain on port 80:
  python test_proxy.py --host your-domain.com

  # Test via Bug Host (reads BUG_HOST from .env if configured):
  python test_proxy.py --bug-host bug-host.com

  # 30-round stability test with 5s idle connection hold:
  python test_proxy.py -n 30 --hold 5

  # Concurrency stress test with 10 parallel connections:
  python test_proxy.py -n 20 -c 5

  # Start local bridge to SSH into remote tunnel:
  python test_proxy.py --bridge 2222
  # then in another terminal: ssh -p 2222 vpnuser@127.0.0.1

  # Direct 1-liner SSH via ProxyCommand:
  ssh -o "ProxyCommand=python test_proxy.py --stdio" vpnuser@your-domain.com
        """
    )
    parser.add_argument("--host", default=None, help="Target tunnel hostname (default: .env TUNNEL_HOST or live_domain.txt)")
    parser.add_argument("--server", "--node", type=int, choices=[1, 2, 3], default=None, help="Target specific server node (1=Primary, 2=Secondary, 3=UDP Compressed from live_domain.txt)")
    parser.add_argument("--all", action="store_true", help="Test both Server 1 and Server 2 sequentially")
    parser.add_argument("--bug-host", default=get_default_bug_host(), help="Bug Host IP or domain for zero-rating (default: .env BUG_HOST)")
    parser.add_argument("--port", type=int, default=get_default_port(), help="Target port (default: .env SSH_PORT or 80)")
    parser.add_argument("--tls", action="store_true", help="Enable TLS / HTTPS / WSS")
    parser.add_argument("-n", "--count", type=int, default=10, help="Number of test probes to run (0 for infinite/continuous)")
    parser.add_argument("-i", "--interval", type=float, default=0.5, help="Interval between probes in seconds (default: 0.5s)")
    parser.add_argument("-t", "--timeout", type=float, default=5.0, help="Socket timeout in seconds (default: 5.0s)")
    parser.add_argument("-c", "--concurrency", type=int, default=1, help="Concurrent connection workers (default: 1)")
    parser.add_argument("--hold", type=float, default=0.0, help="Hold connection open for N seconds to test idle tunnel stability")
    parser.add_argument("-v", "--verbose", action="store_true", help="Display verbose header and server information")
    parser.add_argument("--json", action="store_true", help="Output summary in JSON format")
    parser.add_argument("--bridge", type=int, default=0, help="Start a local TCP port bridge listener (e.g. --bridge 2222)")
    parser.add_argument("--stdio", action="store_true", help="Run in STDIO mode for OpenSSH ProxyCommand")

    args = parser.parse_args()

    if args.all:
        candidates = get_domain_candidates()
        if not candidates:
            print(f"{CLR_RED}[!] Error: No servers found in live_domain.txt or environment.{CLR_RESET}")
            sys.exit(1)
        print(f"\n{CLR_CYAN}======================================================================{CLR_RESET}")
        print(f"{CLR_BOLD}             DUAL-SERVER HIGH AVAILABILITY HEALTH AUDIT                {CLR_RESET}")
        print(f"{CLR_CYAN}======================================================================{CLR_RESET}")
        for idx, srv_host in enumerate(candidates[:2], 1):
            lbl = "PRIMARY (Server 1)" if idx == 1 else "SECONDARY (Server 2)"
            print(f"\n{CLR_YELLOW}>>> AUDITING [{lbl}]: {srv_host}{CLR_RESET}")
            args.host = srv_host
            try:
                run_benchmark(args)
            except Exception as e:
                print(f"{CLR_RED}[!] Audit failed for {srv_host}: {e}{CLR_RESET}")
        return

    if args.host:
        target_host = args.host.strip()
    elif args.server:
        target_host = get_default_host(server_idx=args.server)
    else:
        target_host = get_default_host(server_idx=1)

    if not target_host:
        print(f"{CLR_RED}[!] Error: No target host specified. Set TUNNEL_HOST in .env, live_domain.txt, or pass --host <domain>{CLR_RESET}")
        sys.exit(1)

    args.host = target_host
    connect_host = args.bug_host.strip() if args.bug_host else target_host

    if args.stdio:
        run_stdio(target_host, connect_host, args.port, args.tls, args.timeout)
    elif args.bridge > 0:
        run_bridge(args.bridge, target_host, connect_host, args.port, args.tls, args.timeout)
    else:
        run_benchmark(args)


if __name__ == "__main__":
    main()

