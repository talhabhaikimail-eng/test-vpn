#!/bin/bash
# ==============================================================================
# setup_v2ray.sh - Install & Configure Xray-core (WS + XHTTP) + Go routing proxy
# ==============================================================================
set -euo pipefail

echo "=========================================================="
echo " Starting Xray-core (VLESS/VMess WS + VLESS XHTTP) Setup"
echo "=========================================================="

# 1. Install prerequisites if missing
if ! command -v unzip &>/dev/null; then
  sudo apt-get update -qq && sudo apt-get install -y unzip -qq
fi

# 2. Install Xray-core if not present.
#    Xray replaces v2fly core so we can serve XHTTP (plain HTTP transport, no WebSocket
#    upgrade). /usr/local/bin/v2ray stays as a symlink so existing watchdogs that run
#    "v2ray run -c ... -format json" keep working unchanged.
XRAY_FALLBACK_VERSION="v26.3.27"
if [ ! -f /usr/local/bin/xray ]; then
  echo "[+] Downloading Xray-core (XTLS/Xray-core)..."
  TMP_DIR=$(mktemp -d)
  DOWNLOAD_URL="https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip"

  if ! curl -sSL --connect-timeout 10 --max-time 120 "$DOWNLOAD_URL" -o "$TMP_DIR/xray.zip"; then
    echo "[!] Latest release download failed, trying $XRAY_FALLBACK_VERSION fallback..."
    curl -sSL --connect-timeout 10 --max-time 120 "https://github.com/XTLS/Xray-core/releases/download/$XRAY_FALLBACK_VERSION/Xray-linux-64.zip" -o "$TMP_DIR/xray.zip"
  fi

  unzip -q -o "$TMP_DIR/xray.zip" xray -d "$TMP_DIR/extract"
  sudo mv "$TMP_DIR/extract/xray" /usr/local/bin/xray
  sudo chmod +x /usr/local/bin/xray
  rm -rf "$TMP_DIR"
  echo "[+] Xray-core installed at /usr/local/bin/xray ($(/usr/local/bin/xray version | head -n1))"
fi
sudo ln -sfn /usr/local/bin/xray /usr/local/bin/v2ray

# 3. Dynamic UUID Resolution (Zero Hardcoded Secrets)
UUID="${V2RAY_UUID:-}"
if [ -z "$UUID" ]; then
  if [ -f /proc/sys/kernel/random/uuid ]; then
    UUID=$(cat /proc/sys/kernel/random/uuid)
  else
    UUID=$(python3 -c "import uuid; print(uuid.uuid4())")
  fi
fi

sudo mkdir -p /etc/v2ray
echo "$UUID" | sudo tee /etc/v2ray/uuid.txt > /dev/null
sudo chmod 644 /etc/v2ray/uuid.txt
echo "$UUID" > .v2ray_uuid

# 4. Generate /etc/v2ray/config.json (Xray)
#    - VLESS + VMess over WS on 10085/10086: existing clients (NetMod, NapsternetV, ...).
#      Early data (?ed=2048) needs no server config in Xray.
#    - VLESS over XHTTP on 10087: plain HTTP requests instead of a WebSocket upgrade.
#      Through Cloudflare Tunnel a WS upgrade costs ~3 round trips (fresh inter-colo
#      connection per socket); plain requests reuse warm ones, so new sessions open
#      ~3x faster. Server mode "auto" accepts packet-up, stream-up and stream-one.
sudo tee /etc/v2ray/config.json > /dev/null <<EOF
{
  "log": {
    "loglevel": "warning"
  },
  "dns": {
    "servers": ["localhost"],
    "queryStrategy": "UseIPv4"
  },
  "policy": {
    "levels": {
      "0": {
        "handshake": 4,
        "connIdle": 300
      }
    }
  },
  "inbounds": [
    {
      "tag": "vless-ws",
      "port": 10085,
      "listen": "127.0.0.1",
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "$UUID",
            "level": 0
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "/"
        }
      }
    },
    {
      "tag": "vmess-ws",
      "port": 10086,
      "listen": "127.0.0.1",
      "protocol": "vmess",
      "settings": {
        "clients": [
          {
            "id": "$UUID",
            "level": 0
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "/"
        }
      }
    },
    {
      "tag": "vless-xhttp",
      "port": 10087,
      "listen": "127.0.0.1",
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "$UUID",
            "level": 0
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "xhttp",
        "xhttpSettings": {
          "path": "/xh",
          "mode": "auto"
        }
      }
    }
  ],
  "outbounds": [
    {
      "tag": "direct",
      "protocol": "freedom",
      "settings": {
        "domainStrategy": "UseIPv4"
      },
      "streamSettings": {
        "sockopt": {
          "tcpFastOpen": true
        }
      }
    },
    {
      "tag": "blocked",
      "protocol": "blackhole",
      "settings": {}
    }
  ]
}
EOF
echo "[+] Xray config written to /etc/v2ray/config.json"
if ! sudo /usr/local/bin/xray run -test -c /etc/v2ray/config.json -format json; then
  echo "[!] Xray config failed validation"; exit 1
fi

# 5. Build proxy_v2ray (Go router & TCP optimizer)
if command -v go &>/dev/null && [ -f proxy_v2ray.go ]; then
  echo "[+] Compiling proxy_v2ray Go binary..."
  if [ -f quickack_linux.go ]; then
    go build -o proxy_v2ray_bin proxy_v2ray.go quickack_linux.go
  else
    go build -o proxy_v2ray_bin proxy_v2ray.go
  fi
fi

# 6. Start Xray (via the v2ray symlink so "pgrep -f \"v2ray run\"" watchdogs match)
echo "[+] Starting Xray-core..."
sudo pkill -f "v2ray run" 2>/dev/null || true
sudo nohup /usr/local/bin/v2ray run -c /etc/v2ray/config.json -format json > /var/log/v2ray.log 2>&1 &
sleep 2

# 7. Start proxy_v2ray_bin on 0.0.0.0:8080
echo "[+] Starting V2Ray Proxy Bridge on port 8080..."
sudo pkill -f "proxy_v2ray_bin" 2>/dev/null || true
NODE_LABEL="${1:-V2Ray Node 1}"
if [ -f proxy_v2ray_bin ]; then
  sudo nohup ./proxy_v2ray_bin --listen 0.0.0.0:8080 --vless 127.0.0.1:10085 --vmess 127.0.0.1:10086 --xhttp 127.0.0.1:10087 --name "$NODE_LABEL" > /var/log/proxy_v2ray.log 2>&1 &
fi
sleep 2

# 8. Check listening ports
echo "[+] Active ports check:"
sudo ss -tulpn | grep -E ':8080|:10085|:10086|:10087' || true
if ! pgrep -f "v2ray run" > /dev/null; then
  echo "[!] Xray failed to start! Log:"
  sudo cat /var/log/v2ray.log 2>/dev/null || true
fi

echo "=========================================================="
echo " Xray-core & Proxy Bridge successfully started!"
echo " Reverse Proxy Port: 8080 (Cloudflare points to localhost:8080)"
echo "=========================================================="
