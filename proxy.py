#!/usr/bin/env python3
"""
High-Performance SSH over WebSocket (WS-ePRO / 101 Switching Protocols) Proxy Server.
Optimized for ultra-low latency, zero bufferbloat, and high throughput.
Bridges incoming HTTP/WebSocket connections to local OpenSSH daemon (127.0.0.1:22).
"""

import sys
import os
import socket
import threading
import hashlib
import base64

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 80
TARGET_HOST = "127.0.0.1"
TARGET_PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 22

# Buffer size increased to 64KB for maximum throughput and minimum syscall overhead
BUFFER_SIZE = 65536

def tune_socket(sock: socket.socket):
    """Apply low-latency TCP socket options while allowing Linux dynamic window scaling."""
    try:
        # Disable Nagle's algorithm - eliminates 40ms to 200ms ACK delay penalty
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except Exception:
        pass

    # Enable TCP QuickACK on Linux (disables delayed ACKs)
    if hasattr(socket, "TCP_QUICKACK"):
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_QUICKACK, 1)
        except Exception:
            pass

def compute_accept_key(sec_key: str) -> str:
    guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
    combined = sec_key.strip() + guid
    hashed = hashlib.sha1(combined.encode("ascii")).digest()
    return base64.b64encode(hashed).decode("ascii")

def bidirectional_pipe(source: socket.socket, destination: socket.socket):
    """
    Direct blocking pipe that releases Python GIL and streams at kernel wire speed.
    """
    try:
        while True:
            data = source.recv(BUFFER_SIZE)
            if not data:
                break
            destination.sendall(data)
    except Exception:
        pass
    finally:
        try:
            destination.shutdown(socket.SHUT_WR)
        except Exception:
            pass

def handle_client(client_sock: socket.socket, client_addr):
    ssh_sock = None
    try:
        tune_socket(client_sock)

        # 1. Read HTTP request / payload from client
        request_data = b""
        while b"\r\n\r\n" not in request_data:
            chunk = client_sock.recv(BUFFER_SIZE)
            if not chunk:
                return
            request_data += chunk
            if len(request_data) > 65536:
                break

        header_bytes, _, leftover = request_data.partition(b"\r\n\r\n")
        header_text = header_bytes.decode(errors="ignore")

        # 2. Extract Sec-WebSocket-Key if present
        sec_key = None
        for line in header_text.split("\r\n"):
            if line.lower().startswith("sec-websocket-key:"):
                sec_key = line.split(":", 1)[1].strip()
                break

        # 3. Respond with HTTP 101 Switching Protocols immediately
        response = (
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
        )
        if sec_key:
            response += f"Sec-WebSocket-Accept: {compute_accept_key(sec_key)}\r\n"
        response += "\r\n"
        client_sock.sendall(response.encode("ascii"))

        # 4. Connect to local OpenSSH server
        ssh_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tune_socket(ssh_sock)
        ssh_sock.connect((TARGET_HOST, TARGET_PORT))

        # Send any leftover bytes from initial handshake immediately to OpenSSH
        if leftover:
            ssh_sock.sendall(leftover)

        # 5. Full-duplex concurrent forwarding (no select serialization or lock contention)
        t_c2s = threading.Thread(target=bidirectional_pipe, args=(client_sock, ssh_sock), daemon=True)
        t_s2c = threading.Thread(target=bidirectional_pipe, args=(ssh_sock, client_sock), daemon=True)
        t_c2s.start()
        t_s2c.start()
        t_c2s.join()
        t_s2c.join()

    except Exception:
        pass
    finally:
        if client_sock:
            try: client_sock.close()
            except Exception: pass
        if ssh_sock:
            try: ssh_sock.close()
            except Exception: pass

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tune_socket(server)

    # Enable TCP FastOpen on server listener if available
    if hasattr(socket, "TCP_FASTOPEN"):
        try:
            server.setsockopt(socket.SOL_TCP, socket.TCP_FASTOPEN, 128)
        except Exception:
            pass

    server.bind((LISTEN_HOST, LISTEN_PORT))
    server.listen(256)
    print(f"[WS-ePRO Proxy] Listening on {LISTEN_HOST}:{LISTEN_PORT} -> {TARGET_HOST}:{TARGET_PORT} (Optimized Low-Latency Mode)")

    while True:
        try:
            client_sock, client_addr = server.accept()
            t = threading.Thread(target=handle_client, args=(client_sock, client_addr), daemon=True)
            t.start()
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"[WS-ePRO Proxy] Error accepting connection: {e}")

    server.close()

if __name__ == "__main__":
    main()

