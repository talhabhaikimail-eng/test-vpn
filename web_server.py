#!/usr/bin/env python3
"""
web_server.py — ProxyScope: live packet-level monitor for the tunnel / V2Ray nodes.

Every node gets a *persistent* session that sends real packets through the tunnel
and times the replies, the same way a connected client experiences the link:

  ssh_ws   SSH over the raw WebSocket proxy (proxy.go)       -> echo through an SSH `cat` channel
  udp_ssh  SSH over the framed/deflate proxy (proxy_udp.go)  -> same echo, framed transport
  vless    VLESS over WS through Xray                         -> HTTP GET /ping to the runner, keep-alive
  vmess    VMess (AEAD) over WS through Xray                  -> HTTP GET /ping to the runner, keep-alive
  http     plain HTTPS to the V2Ray router (XHTTP route)      -> keep-alive GET /ping
  ws_ping  any WebSocket endpoint (custom nodes)              -> WebSocket ping → pong

Cold "handshake" probes (new connection each time) are a separate test: through
Cloudflare a fresh WebSocket upgrade is slow (~0.9 s, sometimes several seconds),
which says nothing about the RTT of an already-connected tunnel.

The browser holds one Server-Sent-Events stream (/api/events); live sessions,
probes and speed tests push their events into it. Credentials (.env SSH_USER /
SSH_PASS, .v2ray_uuid) stay on this machine; the server only binds 127.0.0.1.
"""

import base64
import hashlib
import hmac
import json
import os
import queue
import re
import socket
import ssl
import struct
import sys
import threading
import time
import uuid as uuidlib
import zlib
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from urllib.parse import parse_qs, urlparse

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PUBLIC_DIR = os.path.join(BASE_DIR, "public")

# Where VLESS/VMess pings go once inside Xray: the V2Ray router on the runner
# answers GET /ping itself, so the RTT is purely client → Cloudflare → runner.
RUNNER_PING = ("127.0.0.1", 8080, "/ping")
SPEED_HOST = "speed.cloudflare.com"


# ─────────────────────────────────────────────────────────────────────────────
# Environment
# ─────────────────────────────────────────────────────────────────────────────
def load_env():
    for path in (os.path.join(BASE_DIR, ".env"), os.path.join(os.getcwd(), ".env")):
        if not os.path.isfile(path):
            continue
        try:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        k, v = line.split("=", 1)
                        k, v = k.strip(), v.strip().strip("'\"")
                        if k and k not in os.environ:
                            os.environ[k] = v
        except OSError:
            pass
        break


load_env()


def read_first_line(filename):
    try:
        with open(os.path.join(BASE_DIR, filename), "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    return line.replace("https://", "").replace("http://", "").split("/")[0].strip()
    except OSError:
        pass
    return ""


def v2ray_uuid():
    u = os.environ.get("V2RAY_UUID", "").strip() or read_first_line(".v2ray_uuid")
    try:
        return uuidlib.UUID(u).bytes if u else None
    except ValueError:
        return None


def ssh_creds():
    return os.environ.get("SSH_USER", ""), os.environ.get("SSH_PASS", "")


# ─────────────────────────────────────────────────────────────────────────────
# Node catalogue (no secrets in here — this is what /api/nodes returns)
# ─────────────────────────────────────────────────────────────────────────────
CUSTOM_NODES = {}
CUSTOM_LOCK = threading.Lock()

METHOD_LABEL = {
    "ssh_ws": "SSH channel echo through `cat`",
    "udp_ssh": "SSH channel echo over framed transport",
    "vless": "VLESS request → runner /ping (keep-alive)",
    "vmess": "VMess AEAD request → runner /ping (keep-alive)",
    "http": "HTTPS keep-alive GET /ping",
    "ws_ping": "WebSocket ping → pong",
}


def get_nodes():
    bug = os.environ.get("BUG_HOST", "").strip() or "jsbl.com"
    t1 = os.environ.get("TUNNEL_HOST", "").strip() or read_first_line("live_domain_primary.txt") \
        or read_first_line("live_domain.txt") or "tunnel.ufone-claim.site"
    t2 = read_first_line("live_domain_secondary.txt") or "tunnel2.ufone-claim.site"
    v2 = os.environ.get("V2RAY_DOMAIN", "").strip() or read_first_line("live_domain_v2ray.txt") \
        or "v2ray.ufone-claim.site"
    udp = read_first_line("live_domain_udp.txt") or "tunnel-udp.ufone-claim.site"

    nodes = [
        dict(id="tunnel-primary", name="Primary Tunnel", group="ssh", method="ssh_ws",
             protocol="SSH · WebSocket", host=t1, front=bug, port=80, tls=False, path="/"),
        dict(id="tunnel-secondary", name="Secondary Tunnel", group="ssh", method="ssh_ws",
             protocol="SSH · WebSocket", host=t2, front=bug, port=80, tls=False, path="/"),
        dict(id="tunnel-udp", name="UDP Tunnel", group="ssh", method="udp_ssh",
             protocol="SSH · Framed / Deflate WS", host=udp, front=bug, port=80, tls=False, path="/"),
        dict(id="v2ray-vless", name="V2Ray VLESS", group="v2ray", method="vless",
             protocol="VLESS · WS · TLS", host=v2, front=bug, port=443, tls=True, path="/vless"),
        dict(id="v2ray-vmess", name="V2Ray VMess", group="v2ray", method="vmess",
             protocol="VMess AEAD · WS · TLS", host=v2, front=bug, port=443, tls=True, path="/vmess"),
        dict(id="v2ray-xhttp", name="V2Ray HTTP / XHTTP path", group="v2ray", method="http",
             protocol="HTTP/1.1 · TLS", host=v2, front=bug, port=443, tls=True, path="/ping"),
    ]
    with CUSTOM_LOCK:
        nodes.extend(dict(n) for n in CUSTOM_NODES.values())
    for n in nodes:
        n["method_label"] = METHOD_LABEL[n["method"]]
        n["speed"] = n["method"] in ("ssh_ws", "udp_ssh", "vless", "vmess")
    return nodes


def find_node(node_id):
    for n in get_nodes():
        if n["id"] == node_id:
            return n
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Transport building blocks
# ─────────────────────────────────────────────────────────────────────────────
class ProbeError(Exception):
    def __init__(self, stage, msg):
        super().__init__(f"{stage}: {msg}")
        self.stage = stage


class PacketLost(Exception):
    pass


def ms(t0):
    return round((time.perf_counter() - t0) * 1000.0, 1)


def xor_mask(data, mask):
    if not data:
        return data
    n = len(data)
    key = (mask * (n // 4 + 1))[:n]
    return (int.from_bytes(data, "big") ^ int.from_bytes(key, "big")).to_bytes(n, "big")


def connect_tcp(node, timeout, log, phases, info):
    connect_host = node.get("front") or node["host"]
    ip = node.get("front_ip")
    if ip:
        # bug-IP matrix: dial this IP directly, the Host header / SNI stay the node's
        info["ip"] = ip
        log(f"Pinned front IP {ip} (no DNS)")
    else:
        t0 = time.perf_counter()
        try:
            ip = socket.getaddrinfo(connect_host, node["port"], socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
        except OSError as e:
            raise ProbeError("dns", f"{connect_host}: {e}")
        phases["dns"] = ms(t0)
        info["ip"] = ip
        log(f"DNS {connect_host} → {ip} ({phases['dns']} ms)")

    t0 = time.perf_counter()
    try:
        s = socket.create_connection((ip, node["port"]), timeout=timeout)
    except OSError as e:
        raise ProbeError("tcp", f"{ip}:{node['port']} {e}")
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    phases["tcp"] = ms(t0)
    log(f"TCP connected {ip}:{node['port']} ({phases['tcp']} ms)")

    if node["tls"]:
        t0 = time.perf_counter()
        try:
            s = ssl.create_default_context().wrap_socket(s, server_hostname=node["host"])
        except (OSError, ssl.SSLError) as e:
            s.close()
            raise ProbeError("tls", str(e))
        phases["tls"] = ms(t0)
        info["tls"] = f"{s.version()} {s.cipher()[0]}"
        log(f"TLS {info['tls']} SNI={node['host']} ({phases['tls']} ms)")
    return s


def open_tunnel(node, timeout, log=None):
    """DNS → TCP → (TLS) → HTTP Upgrade. Returns (sock, leftover, phases, info)."""
    log = log or (lambda *a, **k: None)
    phases, info = {}, {}
    s = connect_tcp(node, timeout, log, phases, info)
    try:
        key = base64.b64encode(os.urandom(16)).decode()
        req = (f"GET {node['path']} HTTP/1.1\r\nHost: {node['host']}\r\nUpgrade: websocket\r\n"
               f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
               f"User-Agent: ProxyScope/3\r\n\r\n").encode()
        t0 = time.perf_counter()
        s.sendall(req)
        buf = bytearray()
        try:
            while b"\r\n\r\n" not in buf:
                chunk = s.recv(4096)
                if not chunk:
                    raise ProbeError("upgrade", "connection closed before response")
                buf.extend(chunk)
                if len(buf) > 65536:
                    raise ProbeError("upgrade", "oversized response header")
        except socket.timeout:
            raise ProbeError("upgrade", f"no 101 within {timeout:g}s (Cloudflare WS upgrade stalled)")
        phases["upgrade"] = ms(t0)
        head, _, rest = bytes(buf).partition(b"\r\n\r\n")
        lines = head.decode("utf-8", "replace").split("\r\n")
        status = lines[0].split(" ", 2)
        code = status[1] if len(status) > 1 else "?"
        for line in lines[1:]:
            k, _, v = line.partition(":")
            k = k.strip().lower()
            if k == "cf-ray":
                info["cf_ray"] = v.strip()
            elif k == "x-server-info":
                info["server"] = v.strip()
        info["status"] = code
        if code != "101":
            raise ProbeError("upgrade", f"HTTP {lines[0]}")
        log(f"WebSocket 101 ({phases['upgrade']} ms)" + (f" cf-ray {info['cf_ray']}" if "cf_ray" in info else ""))
        return s, rest, phases, info
    except BaseException:
        s.close()
        raise


class WsConn:
    """Minimal RFC 6455 client over an upgraded socket."""

    def __init__(self, sock, leftover=b""):
        self.sock = sock
        self.buf = bytearray(leftover)

    def send(self, opcode, payload):
        n = len(payload)
        if n < 126:
            hdr = bytes([0x80 | opcode, 0x80 | n])
        elif n < 65536:
            hdr = bytes([0x80 | opcode, 0x80 | 126]) + struct.pack(">H", n)
        else:
            hdr = bytes([0x80 | opcode, 0x80 | 127]) + struct.pack(">Q", n)
        mask = os.urandom(4)
        self.sock.sendall(hdr + mask + xor_mask(payload, mask))

    def _need(self, n):
        while len(self.buf) < n:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ConnectionError("tunnel closed by remote")
            self.buf.extend(chunk)

    def recv(self):
        self._need(2)
        b0, b1 = self.buf[0], self.buf[1]
        n, off = b1 & 0x7F, 2
        if n == 126:
            self._need(4)
            n, off = struct.unpack(">H", self.buf[2:4])[0], 4
        elif n == 127:
            self._need(10)
            n, off = struct.unpack(">Q", self.buf[2:10])[0], 10
        if b1 & 0x80:
            off += 4
        self._need(off + n)
        payload = bytes(self.buf[off:off + n])
        if b1 & 0x80:
            payload = xor_mask(payload, bytes(self.buf[off - 4:off]))
        del self.buf[:off + n]
        return b0 & 0x0F, payload

    def recv_data(self):
        """Next data-frame payload; answers pings, raises on close."""
        while True:
            op, data = self.recv()
            if op == 0x8:
                raise ConnectionError("server sent WebSocket close")
            if op == 0x9:
                self.send(0xA, data)
            elif op in (0x0, 0x1, 0x2):
                return data

    def close(self):
        try:
            self.send(0x8, struct.pack(">H", 1000))
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass


class PrefixedSock:
    """Socket that yields `prefix` before reading the real socket (for paramiko)."""

    def __init__(self, sock, prefix=b""):
        self.sock, self.prefix = sock, bytearray(prefix)

    def recv(self, n):
        if self.prefix:
            out = bytes(self.prefix[:n])
            del self.prefix[:n]
            return out
        return self.sock.recv(n)

    def send(self, data):
        return self.sock.send(data)

    def sendall(self, data):
        return self.sock.sendall(data)

    def settimeout(self, t):
        self.sock.settimeout(t)

    def gettimeout(self):
        return self.sock.gettimeout()

    def fileno(self):
        return self.sock.fileno()

    def close(self):
        self.sock.close()


class FramedSock(PrefixedSock):
    """proxy_udp.go framing: [flag:1][len:2][payload]; flag 0 raw, 1 raw-deflate, 2 heartbeat."""

    def __init__(self, sock, prefix=b""):
        super().__init__(sock, b"")
        self.raw = bytearray(prefix)
        self.out = bytearray()

    def _fill(self, n):
        while len(self.raw) < n:
            chunk = self.sock.recv(65536)
            if not chunk:
                return False
            self.raw.extend(chunk)
        return True

    def recv(self, n):
        while not self.out:
            if not self._fill(3):
                return b""
            flag, length = self.raw[0], struct.unpack(">H", self.raw[1:3])[0]
            if not self._fill(3 + length):
                return b""
            payload = bytes(self.raw[3:3 + length])
            del self.raw[:3 + length]
            if flag == 0x01:
                payload = zlib.decompressobj(-15).decompress(payload)
            elif flag == 0x02:
                continue
            self.out.extend(payload)
        out = bytes(self.out[:n])
        del self.out[:n]
        return out

    def send(self, data):
        self.sendall(data)
        return len(data)

    def sendall(self, data):
        mv = memoryview(data)
        frames = bytearray()
        for i in range(0, len(mv), 60000):
            part = mv[i:i + 60000]
            frames += bytes([0x00]) + struct.pack(">H", len(part)) + part
        self.sock.sendall(bytes(frames))


def open_ssh(node, timeout, log):
    import paramiko

    user, pw = ssh_creds()
    if not user or not pw:
        raise ProbeError("auth", "SSH_USER / SSH_PASS missing in .env")
    sock, rest, phases, info = open_tunnel(node, timeout, log)
    wrapped = FramedSock(sock, rest) if node["method"] == "udp_ssh" else PrefixedSock(sock, rest)
    t0 = time.perf_counter()
    try:
        tr = paramiko.Transport(wrapped)
        tr.banner_timeout = timeout
        tr.auth_timeout = timeout
        tr.handshake_timeout = timeout + 5
        tr.connect(username=user, password=pw)
    except Exception as e:
        sock.close()
        raise ProbeError("ssh", f"{type(e).__name__}: {e}")
    phases["ssh"] = ms(t0)
    info["server"] = tr.remote_version
    log(f"SSH {tr.remote_version}, kex + auth as {user} ({phases['ssh']} ms)")
    return tr, phases, info


# ─────────────────────────────────────────────────────────────────────────────
# Byte streams: raw TLS socket, VLESS over WS, VMess (AEAD) over WS
# Each has send(bytes), recv() -> bytes (raises ConnectionError on EOF), .sock, close().
# ─────────────────────────────────────────────────────────────────────────────
class RawStream:
    def __init__(self, sock):
        self.sock = sock

    def send(self, data):
        self.sock.sendall(data)

    def recv(self):
        d = self.sock.recv(65536)
        if not d:
            raise ConnectionError("server closed the connection")
        return d

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


class VlessStream:
    def __init__(self, node, target, port, timeout, log):
        uid = v2ray_uuid()
        if not uid:
            raise ProbeError("vless", "no UUID (.v2ray_uuid or V2RAY_UUID)")
        tnode = dict(node, path=node["path"] if node["method"] == "vless" else "/vless")
        self.sock, rest, self.phases, self.info = open_tunnel(tnode, timeout, log)
        self.ws = WsConn(self.sock, rest)
        dom = target.encode()
        self.pending = bytes([0]) + uid + bytes([0, 1]) + struct.pack(">H", port) + bytes([2, len(dom)]) + dom
        self.head = bytearray()
        self.head_done = False
        log(f"VLESS request → {target}:{port}")

    def send(self, data):
        if self.pending:
            data, self.pending = self.pending + data, b""
        self.ws.send(0x2, data)

    def recv(self):
        while True:
            d = self.ws.recv_data()
            if self.head_done:
                if d:
                    return d
                continue
            self.head.extend(d)
            if len(self.head) >= 2 and len(self.head) >= 2 + self.head[1]:
                rest = bytes(self.head[2 + self.head[1]:])
                self.head_done = True
                if rest:
                    return rest

    def close(self):
        self.ws.close()


def _kdf_hasher(path):
    if not path:
        return lambda d=b"": hmac.new(b"VMess AEAD KDF", d, hashlib.sha256)
    parent = _kdf_hasher(path[:-1])
    return lambda d=b"": hmac.new(path[-1], d, parent)


def vmess_kdf(key, *path):
    h = _kdf_hasher([p.encode() if isinstance(p, str) else p for p in path])()
    h.update(key)
    return h.digest()


def fnv1a32(data):
    h = 0x811C9DC5
    for b in data:
        h = ((h ^ b) * 0x01000193) & 0xFFFFFFFF
    return h


class VmessStream:
    """VMess AEAD client (alterId 0), security 'none', chunk-stream option."""

    def __init__(self, node, target, port, timeout, log):
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        self.AESGCM = AESGCM
        uid = v2ray_uuid()
        if not uid:
            raise ProbeError("vmess", "no UUID (.v2ray_uuid or V2RAY_UUID)")
        tnode = dict(node, path=node["path"] if node["method"] == "vmess" else "/vmess")
        self.sock, rest, self.phases, self.info = open_tunnel(tnode, timeout, log)
        self.ws = WsConn(self.sock, rest)

        cmd_key = hashlib.md5(uid + b"c48619fe-8f02-49e0-b9e9-edf763e17e21").digest()
        iv, key = os.urandom(16), os.urandom(16)
        self.resp_v = os.urandom(1)[0]
        pad = os.urandom(1)[0] % 16
        dom = target.encode()
        hdr = bytes([1]) + iv + key + bytes([self.resp_v, 0x01, (pad << 4) | 0x05, 0, 0x01]) \
            + struct.pack(">H", port) + bytes([2, len(dom)]) + dom + os.urandom(pad)
        hdr += struct.pack(">I", fnv1a32(hdr))
        auth = struct.pack(">q", int(time.time())) + os.urandom(4)
        auth += struct.pack(">I", zlib.crc32(auth))
        enc = Cipher(algorithms.AES(vmess_kdf(cmd_key, "AES Auth ID Encryption")[:16]), modes.ECB()).encryptor()
        auth = enc.update(auth) + enc.finalize()
        nonce = os.urandom(8)

        def seal(kname, nname, data):
            k = vmess_kdf(cmd_key, kname, auth, nonce)[:16]
            n = vmess_kdf(cmd_key, nname, auth, nonce)[:12]
            return AESGCM(k).encrypt(n, data, auth)

        self.pending = auth + seal("VMess Header AEAD Key_Length", "VMess Header AEAD Nonce_Length",
                                   struct.pack(">H", len(hdr))) \
            + nonce + seal("VMess Header AEAD Key", "VMess Header AEAD Nonce", hdr)
        self.rkey = hashlib.sha256(key).digest()[:16]
        self.riv = hashlib.sha256(iv).digest()[:16]
        self.raw = bytearray()
        self.head_done = False
        log(f"VMess AEAD request → {target}:{port}")

    def send(self, data):
        out = bytearray(self.pending)
        self.pending = b""
        mv = memoryview(data)
        for i in range(0, len(mv), 8192):
            part = mv[i:i + 8192]
            out += struct.pack(">H", len(part)) + part
        self.ws.send(0x2, bytes(out))

    def _need(self, n):
        while len(self.raw) < n:
            self.raw.extend(self.ws.recv_data())

    def recv(self):
        if not self.head_done:
            self._need(18)
            g = self.AESGCM(vmess_kdf(self.rkey, "AEAD Resp Header Len Key")[:16])
            ln = struct.unpack(">H", g.decrypt(vmess_kdf(self.riv, "AEAD Resp Header Len IV")[:12],
                                               bytes(self.raw[:18]), None))[0]
            self._need(18 + ln + 16)
            g = self.AESGCM(vmess_kdf(self.rkey, "AEAD Resp Header Key")[:16])
            h = g.decrypt(vmess_kdf(self.riv, "AEAD Resp Header IV")[:12], bytes(self.raw[18:18 + ln + 16]), None)
            if h[0] != self.resp_v:
                raise ConnectionError("VMess response header mismatch")
            del self.raw[:18 + ln + 16]
            self.head_done = True
        self._need(2)
        n = struct.unpack(">H", self.raw[:2])[0]
        if n == 0:
            raise ConnectionError("VMess stream ended")
        self._need(2 + n)
        out = bytes(self.raw[2:2 + n])
        del self.raw[:2 + n]
        return out

    def close(self):
        self.ws.close()


def open_stream(node, target, port, timeout, log):
    """Proxy stream for a V2Ray node; HTTP/XHTTP nodes test through VLESS (same Xray)."""
    if node["method"] == "vmess":
        return VmessStream(node, target, port, timeout, log)
    return VlessStream(node, target, port, timeout, log)


class HttpOverStream:
    def __init__(self, stream):
        self.stream, self.buf = stream, bytearray()

    def _fill(self):
        self.buf.extend(self.stream.recv())

    def request(self, raw, timeout, body_cb=None):
        """Send raw request, read one response. Returns (code, headers, tx, rx)."""
        self.stream.sock.settimeout(timeout)
        try:
            self.stream.send(raw)
            while b"\r\n\r\n" not in self.buf:
                self._fill()
            head, _, rest = bytes(self.buf).partition(b"\r\n\r\n")
            self.buf = bytearray(rest)
            lines = head.decode("utf-8", "replace").split("\r\n")
            hdrs = {}
            for line in lines[1:]:
                k, _, v = line.partition(":")
                hdrs[k.strip().lower()] = v.strip()
            clen = int(hdrs.get("content-length", "-1"))
            if clen >= 0:
                # stream the body (it can be many MB for speed tests) without buffering it
                take = min(len(self.buf), clen)
                del self.buf[:take]
                if body_cb and take:
                    body_cb(take)
                remaining = clen - take
                while remaining > 0:
                    d = self.stream.recv()
                    take = min(len(d), remaining)
                    remaining -= take
                    if body_cb:
                        body_cb(take)
                    if take < len(d):
                        self.buf.extend(d[take:])
            elif hdrs.get("connection", "").lower() == "close":
                total = len(self.buf)
                if body_cb:
                    body_cb(total)
                self.buf.clear()
                while True:
                    try:
                        d = self.stream.recv()
                    except ConnectionError:
                        break
                    total += len(d)
                    if body_cb:
                        body_cb(len(d))
                clen = total
        except socket.timeout:
            raise PacketLost(f"no reply within {timeout:g}s")
        parts = lines[0].split(" ")
        return (parts[1] if len(parts) > 1 else "?"), hdrs, len(raw), len(head) + 4 + max(clen, 0)


# ─────────────────────────────────────────────────────────────────────────────
# Persistent ping sessions
# ─────────────────────────────────────────────────────────────────────────────
class SshEchoPinger:
    reconnect_on_loss = True

    def __init__(self, node, timeout, log):
        self.tr, self.phases, self.info = open_ssh(node, timeout, log)
        t0 = time.perf_counter()
        self.chan = self.tr.open_session(timeout=timeout)
        self.chan.exec_command("cat")
        self.phases["channel"] = ms(t0)
        log(f"Echo channel `cat` open ({self.phases['channel']} ms)")

    def ping(self, seq, size, timeout):
        size = max(16, min(size, 4096))
        payload = struct.pack(">Id", seq, time.time()) + os.urandom(size - 12)
        self.chan.settimeout(timeout)
        t0 = time.perf_counter()
        self.chan.sendall(payload)
        got = bytearray()
        try:
            while len(got) < size:
                d = self.chan.recv(size - len(got))
                if not d:
                    raise ConnectionError("echo channel closed")
                got.extend(d)
        except socket.timeout:
            raise PacketLost(f"no echo within {timeout:g}s")
        rtt = (time.perf_counter() - t0) * 1000.0
        if bytes(got) != payload:
            raise ConnectionError("echo payload mismatch")
        return rtt, size, size

    def close(self):
        try:
            self.tr.close()
        except Exception:
            pass


class WsPinger:
    reconnect_on_loss = False

    def __init__(self, node, timeout, log):
        self.sock, rest, self.phases, self.info = open_tunnel(node, timeout, log)
        self.ws = WsConn(self.sock, rest)

    def ping(self, seq, size, timeout):
        size = max(12, min(size, 125))
        payload = struct.pack(">Id", seq, time.time()) + os.urandom(size - 12)
        deadline = time.perf_counter() + timeout
        t0 = time.perf_counter()
        self.ws.send(0x9, payload)
        while True:
            left = deadline - time.perf_counter()
            if left <= 0:
                raise PacketLost(f"no pong within {timeout:g}s")
            self.sock.settimeout(left)
            try:
                op, data = self.ws.recv()
            except socket.timeout:
                raise PacketLost(f"no pong within {timeout:g}s")
            if op == 0x8:
                raise ConnectionError("server sent WebSocket close")
            if op == 0x9:
                self.ws.send(0xA, data)
            elif op == 0xA and data[:4] == payload[:4]:
                return (time.perf_counter() - t0) * 1000.0, size + 6, len(data) + 2

    def close(self):
        self.ws.close()


class HttpPinger:
    """Keep-alive GETs: straight over TLS (method http) or inside VLESS/VMess."""
    reconnect_on_loss = True

    def __init__(self, node, timeout, log):
        self.node = node
        if node["method"] in ("vless", "vmess"):
            host, port, self.path = RUNNER_PING
            self.host = host
            self.stream = open_stream(node, host, port, timeout, log)
            self.phases, self.info = self.stream.phases, self.stream.info
        else:
            self.phases, self.info = {}, {}
            self.host, self.path = node["host"], node["path"]
            self.stream = RawStream(connect_tcp(node, timeout, log, self.phases, self.info))
        self.http = HttpOverStream(self.stream)
        t0 = time.perf_counter()
        try:
            code, hdrs, _, _ = self.http.request(self._req(0), timeout)
        except PacketLost as e:
            self.close()
            raise ProbeError("first request", str(e))
        except Exception:
            self.close()
            raise
        self.phases["first_req"] = ms(t0)
        self._note(hdrs, code)
        log(f"First GET {self.path} → HTTP {code} ({self.phases['first_req']} ms)")

    def _req(self, seq):
        return (f"GET {self.path}?seq={seq} HTTP/1.1\r\nHost: {self.host}\r\nCache-Control: no-cache\r\n"
                f"User-Agent: ProxyScope/3\r\nConnection: keep-alive\r\n\r\n").encode()

    def _note(self, hdrs, code):
        self.info["status"] = code
        if "x-server-info" in hdrs:
            self.info["server"] = hdrs["x-server-info"]
        if "cf-ray" in hdrs:
            self.info["cf_ray"] = hdrs["cf-ray"]

    def ping(self, seq, size, timeout):
        t0 = time.perf_counter()
        code, hdrs, tx, rx = self.http.request(self._req(seq), timeout)
        rtt = (time.perf_counter() - t0) * 1000.0
        self._note(hdrs, code)
        if code.startswith("5"):
            raise ConnectionError(f"HTTP {code}")
        if hdrs.get("connection", "").lower() == "close":
            raise ConnectionError("server closed keep-alive")
        return rtt, tx, rx

    def close(self):
        self.stream.close()


PINGERS = {"ssh_ws": SshEchoPinger, "udp_ssh": SshEchoPinger, "ws_ping": WsPinger,
           "http": HttpPinger, "vless": HttpPinger, "vmess": HttpPinger}


# ─────────────────────────────────────────────────────────────────────────────
# Event hub: one SSE stream per browser tab
# ─────────────────────────────────────────────────────────────────────────────
class Client:
    def __init__(self, cid):
        self.cid = cid
        self.q = queue.Queue(maxsize=20000)
        self.sessions = {}
        self.lock = threading.Lock()
        self.streams = 0
        self.matrix_stop = threading.Event()
        self.matrix_thread = None

    def emit(self, etype, **data):
        data["type"] = etype
        data.setdefault("ts", time.time() * 1000.0)
        try:
            self.q.put_nowait(data)
        except queue.Full:
            pass

    def stop_all(self):
        with self.lock:
            sessions = list(self.sessions.values())
            self.sessions.clear()
        self.matrix_stop.set()
        for s in sessions:
            s.stop()


CLIENTS = {}
CLIENTS_LOCK = threading.Lock()


def get_client(cid):
    with CLIENTS_LOCK:
        c = CLIENTS.get(cid)
        if c is None:
            c = CLIENTS[cid] = Client(cid)
        return c


class LiveSession(threading.Thread):
    def __init__(self, client, node, opts):
        super().__init__(daemon=True)
        self.client, self.node = client, node
        self.interval = max(0.2, float(opts.get("interval", 1000)) / 1000.0)
        self.timeout = max(1.0, float(opts.get("timeout", 5000)) / 1000.0)
        self.size = int(opts.get("size", 64))
        self.stop_evt = threading.Event()
        self.pinger = None
        self.seq = 0

    def emit(self, etype, **data):
        self.client.emit(etype, node=self.node["id"], **data)

    def log(self, msg, level="info"):
        self.emit("log", level=level, msg=msg)

    def stop(self):
        self.stop_evt.set()
        p = self.pinger
        if p:
            p.close()

    def _connect(self):
        self.emit("session", state="connecting")
        t0 = time.perf_counter()
        try:
            p = PINGERS[self.node["method"]](self.node, max(self.timeout, 10.0), self.log)
        except ProbeError as e:
            self.emit("session", state="failed", stage=e.stage, error=str(e), total=ms(t0))
            self.log(f"Connect failed — {e}", "error")
            return None
        except Exception as e:
            self.emit("session", state="failed", stage="connect", error=f"{type(e).__name__}: {e}", total=ms(t0))
            self.log(f"Connect failed — {type(e).__name__}: {e}", "error")
            return None
        if self.stop_evt.is_set():
            p.close()
            return None
        self.emit("session", state="connected", phases=p.phases, info=p.info, total=ms(t0))
        return p

    def run(self):
        backoff = 1.0
        self.log(f"Session start: {self.node['method_label']}, every {self.interval * 1000:.0f} ms, "
                 f"timeout {self.timeout * 1000:.0f} ms")
        while not self.stop_evt.is_set():
            if self.pinger is None:
                self.pinger = self._connect()
                if self.pinger is None:
                    if self.stop_evt.wait(backoff):
                        break
                    backoff = min(backoff * 2, 15.0)
                    continue
                backoff = 1.0
            self.seq += 1
            seq = self.seq
            t_start = time.perf_counter()
            self.emit("tx", seq=seq, size=self.size)
            try:
                rtt, tx, rx = self.pinger.ping(seq, self.size, self.timeout)
                self.emit("rx", seq=seq, rtt=round(rtt, 2), tx=tx, rx=rx)
            except PacketLost as e:
                self.emit("lost", seq=seq, reason=str(e))
                if self.pinger.reconnect_on_loss:
                    self._drop("stream stalled; reconnecting")
            except Exception as e:
                if self.stop_evt.is_set():
                    break
                self.emit("lost", seq=seq, reason=f"{type(e).__name__}: {e}")
                self._drop(f"{type(e).__name__}: {e}")
            wait = self.interval - (time.perf_counter() - t_start)
            if wait > 0 and self.stop_evt.wait(wait):
                break
        if self.pinger:
            self.pinger.close()
        self.emit("session", state="stopped")

    def _drop(self, why):
        self.log(f"Tunnel dropped — {why}", "warn")
        self.emit("session", state="reconnecting", reason=why)
        p, self.pinger = self.pinger, None
        if p:
            p.close()


# ─────────────────────────────────────────────────────────────────────────────
# Cold handshake probes
# ─────────────────────────────────────────────────────────────────────────────
def cold_probe(node, timeout):
    t0 = time.perf_counter()
    res = {"ok": False, "phases": {}, "info": {}, "error": None, "stage": None}
    try:
        if node["method"] == "http":
            p = HttpPinger(node, timeout, lambda *a, **k: None)
            res["phases"], res["info"] = p.phases, p.info
            p.close()
        else:
            sock, rest, res["phases"], res["info"] = open_tunnel(node, timeout)
            try:
                if node["method"] in ("ssh_ws", "udp_ssh"):
                    # first byte from the origin = SSH banner relayed from sshd on the runner
                    t1 = time.perf_counter()
                    sock.settimeout(timeout)
                    first = rest or sock.recv(256)
                    if node["method"] == "udp_ssh" and len(first) >= 3:
                        first = first[3:]
                    res["phases"]["origin"] = ms(t1)
                    res["info"]["banner"] = first.split(b"\r\n")[0].decode("latin-1", "replace")[:80]
            finally:
                sock.close()
        res["ok"] = True
    except ProbeError as e:
        res["error"], res["stage"] = str(e), e.stage
    except socket.timeout:
        res["error"], res["stage"] = f"origin: no data within {timeout:g}s", "origin"
    except Exception as e:
        res["error"], res["stage"] = f"{type(e).__name__}: {e}", "connect"
    res["total"] = ms(t0)
    return res


def run_probes(client, node, count, timeout):
    nid = node["id"]
    client.emit("probe_start", node=nid, count=count)
    for i in range(count):
        r = cold_probe(node, timeout)
        client.emit("probe", node=nid, index=i, **r)
        time.sleep(0.2)
    client.emit("probe_done", node=nid)


# ─────────────────────────────────────────────────────────────────────────────
# Bug-IP matrix: every node dialled through every candidate front IP
# ─────────────────────────────────────────────────────────────────────────────
def matrix_cell(client, run, node, ip, pings, timeout, stop_evt):
    """Open a session to `node` via `ip`, send `pings` packets, emit one result."""
    nid = node["id"]
    client.emit("matrix_cell", run=run, node=nid, ip=ip, state="running")
    res = {"ok": False, "phases": {}, "info": {}, "rtts": [], "lost": 0, "error": None, "stage": None}
    t0 = time.perf_counter()
    p = None
    try:
        p = PINGERS[node["method"]](dict(node, front_ip=ip), timeout, lambda *a, **k: None)
        res["phases"], res["info"] = dict(p.phases), dict(p.info)
        res["connect"] = ms(t0)
        for seq in range(1, pings + 1):
            if stop_evt.is_set():
                break
            t_start = time.perf_counter()
            try:
                rtt, _, _ = p.ping(seq, 64, min(timeout, 5.0))
                res["rtts"].append(round(rtt, 2))
            except PacketLost:
                res["lost"] += 1
                res["rtts"].append(None)
            except Exception as e:
                res["lost"] += pings - seq + 1
                res["rtts"].extend([None] * (pings - seq + 1))
                res["error"], res["stage"] = f"session dropped: {type(e).__name__}: {e}", "ping"
                break
            wait = 0.25 - (time.perf_counter() - t_start)
            if wait > 0:
                time.sleep(wait)
        res["ok"] = any(r is not None for r in res["rtts"])
        if not res["ok"] and not res["error"]:
            res["error"], res["stage"] = "connected but every packet was lost", "ping"
    except ProbeError as e:
        res["error"], res["stage"] = str(e), e.stage
    except Exception as e:
        res["error"], res["stage"] = f"{type(e).__name__}: {e}", "connect"
    finally:
        if p:
            p.close()
    res["total"] = ms(t0)
    client.emit("matrix_cell", run=run, node=nid, ip=ip, state="done", **res)


def run_matrix(client, run, nodes, ips, pings, timeout, workers):
    client.emit("matrix_start", run=run, nodes=[n["id"] for n in nodes], ips=ips, pings=pings)
    jobs = queue.Queue()
    # interleave by node so parallel workers hit different servers, not one node ×N
    for ip in ips:
        for n in nodes:
            jobs.put((n, ip))
    stop_evt = client.matrix_stop

    def worker():
        while not stop_evt.is_set():
            try:
                n, ip = jobs.get_nowait()
            except queue.Empty:
                return
            matrix_cell(client, run, n, ip, pings, timeout, stop_evt)

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(workers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    client.emit("matrix_done", run=run, stopped=stop_evt.is_set())


# ─────────────────────────────────────────────────────────────────────────────
# Speed tests (real payload through the tunnel)
# ─────────────────────────────────────────────────────────────────────────────
class Meter:
    def __init__(self, client, nid, direction, total):
        self.client, self.nid, self.dir, self.total = client, nid, direction, total
        self.bytes, self.t0, self.last = 0, time.perf_counter(), 0.0
        self.ttfb = None

    def start(self):
        self.t0 = time.perf_counter()

    def add(self, n):
        if self.ttfb is None:
            self.ttfb = ms(self.t0)
        self.bytes += n
        now = time.perf_counter()
        if now - self.last > 0.2:
            self.last = now
            self.client.emit("speed_progress", node=self.nid, dir=self.dir, bytes=self.bytes,
                             total=self.total, elapsed=round((now - self.t0) * 1000), mbps=self.mbps())

    def mbps(self):
        dt = time.perf_counter() - self.t0
        return round(self.bytes * 8 / dt / 1e6, 2) if dt > 0 else 0.0

    def result(self):
        return {"mbps": self.mbps(), "bytes": self.bytes, "ttfb": self.ttfb,
                "ms": round((time.perf_counter() - self.t0) * 1000)}


def speed_test(client, node, nbytes, max_secs=20.0):
    nid = node["id"]

    def log(m, level="info"):
        client.emit("log", node=nid, level=level, msg=m)

    client.emit("speed_start", node=nid, bytes=nbytes)
    results = {}
    try:
        if node["method"] in ("ssh_ws", "udp_ssh"):
            tr, _, _ = open_ssh(node, 15.0, log)
            try:
                m = Meter(client, nid, "down", nbytes)
                log(f"Download: {nbytes // 1024} KiB of /dev/urandom streamed over SSH")
                ch = tr.open_session(timeout=10)
                ch.settimeout(10)
                ch.exec_command(f"head -c {nbytes} /dev/urandom")
                m.start()
                deadline = time.perf_counter() + max_secs
                while time.perf_counter() < deadline:
                    d = ch.recv(65536)
                    if not d:
                        break
                    m.add(len(d))
                ch.close()
                results["down"] = m.result()

                m = Meter(client, nid, "up", nbytes)
                log(f"Upload: {nbytes // 1024} KiB pushed into `cat > /dev/null`")
                ch = tr.open_session(timeout=10)
                ch.settimeout(10)
                ch.exec_command("cat > /dev/null")
                chunk = os.urandom(32768)
                m.start()
                deadline = time.perf_counter() + max_secs
                while m.bytes < nbytes and time.perf_counter() < deadline:
                    m.add(ch.send(chunk[:min(len(chunk), nbytes - m.bytes)]))
                ch.shutdown_write()
                ch.recv_exit_status()  # sshd has drained everything we sent
                ch.close()
                results["up"] = m.result()
            finally:
                tr.close()
        else:
            proto = "VMess" if node["method"] == "vmess" else "VLESS"
            m = Meter(client, nid, "down", nbytes)
            log(f"Download via {proto} → http://{SPEED_HOST}/__down ({nbytes // 1024} KiB)")
            st = open_stream(node, SPEED_HOST, 80, 15.0, log)
            try:
                m.start()
                req = (f"GET /__down?bytes={nbytes} HTTP/1.1\r\nHost: {SPEED_HOST}\r\n"
                       f"Connection: close\r\n\r\n").encode()
                HttpOverStream(st).request(req, 15.0, body_cb=m.add)
            finally:
                st.close()
            results["down"] = m.result()

            m = Meter(client, nid, "up", nbytes)
            log(f"Upload via {proto} → http://{SPEED_HOST}/__up ({nbytes // 1024} KiB)")
            st = open_stream(node, SPEED_HOST, 80, 15.0, log)
            try:
                st.sock.settimeout(15.0)
                st.send((f"POST /__up HTTP/1.1\r\nHost: {SPEED_HOST}\r\nContent-Type: application/octet-stream\r\n"
                         f"Content-Length: {nbytes}\r\nConnection: close\r\n\r\n").encode())
                chunk = os.urandom(32768)
                m.start()
                deadline = time.perf_counter() + max_secs
                while m.bytes < nbytes and time.perf_counter() < deadline:
                    part = chunk[:min(len(chunk), nbytes - m.bytes)]
                    st.send(part)
                    m.add(len(part))
                try:
                    st.recv()  # the HTTP response proves the bytes were delivered
                except (OSError, ConnectionError):
                    pass
            finally:
                st.close()
            results["up"] = m.result()
        client.emit("speed_done", node=nid, ok=True, results=results)
    except Exception as e:
        log(f"Speed test failed — {e}", "error")
        client.emit("speed_done", node=nid, ok=False, error=str(e), results=results)


# ─────────────────────────────────────────────────────────────────────────────
# HTTP server
# ─────────────────────────────────────────────────────────────────────────────
class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


STATIC = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
    "/app.js": ("app.js", "application/javascript; charset=utf-8"),
}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        return

    def send_json(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        url = urlparse(self.path)
        if url.path in STATIC:
            name, ctype = STATIC[url.path]
            try:
                with open(os.path.join(PUBLIC_DIR, name), "rb") as f:
                    body = f.read()
            except OSError:
                return self.send_json({"error": f"{name} missing"}, 404)
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            self.wfile.write(body)
        elif url.path == "/api/nodes":
            user, pw = ssh_creds()
            self.send_json({"nodes": get_nodes(),
                            "creds": {"ssh": bool(user and pw), "uuid": v2ray_uuid() is not None}})
        elif url.path == "/api/events":
            cid = (parse_qs(url.query).get("client") or [""])[0]
            if not cid:
                return self.send_json({"error": "client required"}, 400)
            self.stream_events(get_client(cid))
        else:
            self.send_json({"error": "not found"}, 404)

    def stream_events(self, client):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        self.close_connection = True
        with client.lock:
            client.streams += 1
        try:
            self.wfile.write(b"retry: 2000\n\n")
            self.wfile.flush()
            while True:
                try:
                    batch = [client.q.get(timeout=10)]
                    while len(batch) < 200:
                        try:
                            batch.append(client.q.get_nowait())
                        except queue.Empty:
                            break
                    self.wfile.write(b"data: " + json.dumps(batch).encode() + b"\n\n")
                except queue.Empty:
                    self.wfile.write(b": keepalive\n\n")
                self.wfile.flush()
        except OSError:
            pass
        finally:
            with client.lock:
                client.streams -= 1

            # tab closed: give EventSource a few seconds to reconnect before tearing sessions down
            def reap():
                time.sleep(8)
                with client.lock:
                    orphaned = client.streams == 0
                if orphaned:
                    client.stop_all()
                    with CLIENTS_LOCK:
                        CLIENTS.pop(client.cid, None)
            threading.Thread(target=reap, daemon=True).start()

    def do_POST(self):
        url = urlparse(self.path)
        try:
            n = int(self.headers.get("Content-Length", 0))
            payload = json.loads(self.rfile.read(n) or b"{}") if n else {}
        except (ValueError, json.JSONDecodeError):
            return self.send_json({"error": "bad json"}, 400)

        if url.path == "/api/custom":
            return self.add_custom(payload)
        if url.path == "/api/matrix":
            return self.start_matrix(get_client(str(payload.get("client", ""))), payload)

        client = get_client(str(payload.get("client", "")))
        node = find_node(payload.get("id", ""))
        if node is None:
            return self.send_json({"error": "unknown node"}, 404)

        if url.path == "/api/live":
            with client.lock:
                old = client.sessions.pop(node["id"], None)
            if old:
                old.stop()
            if payload.get("action", "start") == "start":
                s = LiveSession(client, node, payload)
                with client.lock:
                    client.sessions[node["id"]] = s
                s.start()
            return self.send_json({"ok": True})

        if url.path == "/api/probe":
            count = max(1, min(int(payload.get("count", 5)), 30))
            timeout = max(2.0, min(float(payload.get("timeout", 15000)) / 1000.0, 30.0))
            threading.Thread(target=run_probes, args=(client, node, count, timeout), daemon=True).start()
            return self.send_json({"ok": True})

        if url.path == "/api/speed":
            if not node["speed"]:
                return self.send_json({"error": "speed test not supported for this node"}, 400)
            nbytes = max(64 * 1024, min(int(payload.get("bytes", 4 * 1024 * 1024)), 100 * 1024 * 1024))
            threading.Thread(target=speed_test, args=(client, node, nbytes), daemon=True).start()
            return self.send_json({"ok": True})

        self.send_json({"error": "not found"}, 404)

    def start_matrix(self, client, p):
        old = client.matrix_thread
        client.matrix_stop.set()
        if p.get("action") == "stop":
            return self.send_json({"ok": True})
        if old:
            old.join(timeout=15)
        ips, seen = [], set()
        for raw in p.get("ips", []):
            ip = str(raw).strip()
            if ip and ip not in seen and re.fullmatch(r"[A-Za-z0-9.:-]{1,253}", ip):
                seen.add(ip)
                ips.append(ip)
        wanted = set(p.get("nodes") or [])
        nodes = [n for n in get_nodes() if not wanted or n["id"] in wanted]
        if not ips or not nodes:
            return self.send_json({"error": "need at least one IP and one node"}, 400)
        if len(ips) > 64:
            return self.send_json({"error": "at most 64 IPs per run"}, 400)
        pings = max(1, min(int(p.get("pings", 10)), 100))
        timeout = max(2.0, min(float(p.get("timeout", 10000)) / 1000.0, 30.0))
        workers = max(1, min(int(p.get("workers", 6)), 16))
        run = uuidlib.uuid4().hex[:8]
        client.matrix_stop = threading.Event()
        t = threading.Thread(target=run_matrix, args=(client, run, nodes, ips, pings, timeout, workers), daemon=True)
        client.matrix_thread = t
        t.start()
        self.send_json({"ok": True, "run": run, "cells": len(ips) * len(nodes)})

    def add_custom(self, p):
        host = str(p.get("host", "")).strip().replace("https://", "").replace("http://", "").split("/")[0]
        method = p.get("method", "ws_ping")
        if not host or method not in PINGERS:
            return self.send_json({"error": "host and a valid method are required"}, 400)
        tls = bool(p.get("tls", False))
        path = str(p.get("path", "/")).strip() or "/"
        if not path.startswith("/"):
            path = "/" + path
        try:
            port = int(p.get("port") or (443 if tls else 80))
        except ValueError:
            return self.send_json({"error": "bad port"}, 400)
        nid = "custom-" + uuidlib.uuid5(uuidlib.NAMESPACE_DNS, f"{host}|{method}|{path}|{tls}|{port}").hex[:8]
        node = dict(id=nid, name=host, group="custom", method=method,
                    protocol=f"Custom · {METHOD_LABEL[method]}", host=host,
                    front=str(p.get("front", "")).strip(), port=port, tls=tls, path=path)
        with CUSTOM_LOCK:
            CUSTOM_NODES[nid] = node
        self.send_json({"ok": True, "id": nid})


def run_server(port=5050):
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    server = ThreadedHTTPServer(("127.0.0.1", port), Handler)
    user, pw = ssh_creds()
    print("=" * 60)
    print(f"  ProxyScope live monitor  →  http://127.0.0.1:{port}")
    print(f"  nodes: {len(get_nodes())}   ssh creds: {'yes' if user and pw else 'MISSING'}"
          f"   v2ray uuid: {'yes' if v2ray_uuid() else 'MISSING'}")
    print("=" * 60)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nshutting down")
        server.server_close()


if __name__ == "__main__":
    run_server(int(sys.argv[1]) if len(sys.argv) > 1 and sys.argv[1].isdigit() else 5050)
