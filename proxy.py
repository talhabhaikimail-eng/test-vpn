#!/usr/bin/env python3
"""
Custom SSH over WebSocket (WS-ePRO / 101 Switching Protocols) Proxy Server.
Designed for clients like NetMod, HTTP Custom, and SSH-WS payload injectors.
Bridges incoming HTTP/WebSocket connections to local OpenSSH daemon (127.0.0.1:22).
"""

import sys
import socket
import threading
import select
import hashlib
import base64

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 80
TARGET_HOST = "127.0.0.1"
TARGET_PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 22
BUFFER_SIZE = 8192

def compute_accept_key(sec_key: str) -> str:
    guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
    combined = sec_key.strip() + guid
    hashed = hashlib.sha1(combined.encode("ascii")).digest()
    return base64.b64encode(hashed).decode("ascii")

def handle_client(client_sock: socket.socket, client_addr):
    ssh_sock = None
    try:
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

        # 3. Respond with HTTP 101 Switching Protocols
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
        ssh_sock.connect((TARGET_HOST, TARGET_PORT))

        # Send any data that came after the HTTP header (initial SSH bytes)
        if leftover:
            ssh_sock.sendall(leftover)

        # 5. Raw bidirectional relay between client and OpenSSH
        sockets = [client_sock, ssh_sock]
        while True:
            readable, _, exceptional = select.select(sockets, [], sockets, 60)
            if exceptional:
                break
            if not readable:
                continue

            for s in readable:
                other = ssh_sock if s is client_sock else client_sock
                data = s.recv(BUFFER_SIZE)
                if not data:
                    return
                other.sendall(data)

    except Exception as e:
        pass
    finally:
        if client_sock:
            try: client_sock.close()
            except: pass
        if ssh_sock:
            try: ssh_sock.close()
            except: pass

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((LISTEN_HOST, LISTEN_PORT))
    server.listen(128)
    print(f"[WS-ePRO Proxy] Listening on {LISTEN_HOST}:{LISTEN_PORT} -> {TARGET_HOST}:{TARGET_PORT}")

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
