#!/bin/bash
# ==============================================================================
# setup_v2ray.sh - Install & Configure Official V2Ray Core + High-Throughput Proxy
# ==============================================================================
set -euo pipefail

echo "=========================================================="
echo " Starting V2Ray Core (VLESS + VMess over WS) Setup"
echo "=========================================================="

# 1. Install prerequisites if missing
if ! command -v unzip &>/dev/null; then
  sudo apt-get update -qq && sudo apt-get install -y unzip -qq
fi

# 2. Install official V2Ray Core if not present
if [ ! -f /usr/local/bin/v2ray ]; then
  echo "[+] Downloading official V2Ray Core (v2fly/v2ray-core)..."
  TMP_DIR=$(mktemp -d)
  DOWNLOAD_URL="https://github.com/v2fly/v2ray-core/releases/latest/download/v2ray-linux-64.zip"
  
  if ! curl -sSL --connect-timeout 10 --max-time 120 "$DOWNLOAD_URL" -o "$TMP_DIR/v2ray.zip"; then
    echo "[!] Latest release download failed, trying v5.53.0 fallback..."
    curl -sSL --connect-timeout 10 --max-time 120 "https://github.com/v2fly/v2ray-core/releases/download/v5.53.0/v2ray-linux-64.zip" -o "$TMP_DIR/v2ray.zip"
  fi

  unzip -q -o "$TMP_DIR/v2ray.zip" -d "$TMP_DIR/extract"
  sudo mv "$TMP_DIR/extract/v2ray" /usr/local/bin/v2ray
  sudo chmod +x /usr/local/bin/v2ray
  rm -rf "$TMP_DIR"
  echo "[+] V2Ray Core installed at /usr/local/bin/v2ray"
fi

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

# 4. Generate /etc/v2ray/config.json
sudo tee /etc/v2ray/config.json > /dev/null <<EOF
{
  "log": {
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "tag": "vless-in",
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
      "tag": "vmess-in",
      "port": 10086,
      "listen": "127.0.0.1",
      "protocol": "vmess",
      "settings": {
        "clients": [
          {
            "id": "$UUID",
            "alterId": 0
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "/"
        }
      }
    }
  ],
  "outbounds": [
    {
      "tag": "direct",
      "protocol": "freedom",
      "settings": {
        "domainStrategy": "UseIP"
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
echo "[+] V2Ray config written to /etc/v2ray/config.json"

# 5. Build proxy_v2ray (Go router & TCP optimizer)
if command -v go &>/dev/null && [ -f proxy_v2ray.go ]; then
  echo "[+] Compiling proxy_v2ray Go binary..."
  if [ -f quickack_linux.go ]; then
    go build -o proxy_v2ray_bin proxy_v2ray.go quickack_linux.go
  else
    go build -o proxy_v2ray_bin proxy_v2ray.go
  fi
fi

# 6. Start V2Ray Core
echo "[+] Starting V2Ray Core..."
sudo pkill -f "v2ray run" 2>/dev/null || true
sudo nohup /usr/local/bin/v2ray run -c /etc/v2ray/config.json -format jsonv4 > /var/log/v2ray.log 2>&1 &
sleep 2

# 7. Start proxy_v2ray_bin on 0.0.0.0:8080
echo "[+] Starting V2Ray Proxy Bridge on port 8080..."
sudo pkill -f "proxy_v2ray_bin" 2>/dev/null || true
NODE_LABEL="${1:-V2Ray Node 1}"
if [ -f proxy_v2ray_bin ]; then
  sudo nohup ./proxy_v2ray_bin --listen 0.0.0.0:8080 --vless 127.0.0.1:10085 --vmess 127.0.0.1:10086 --name "$NODE_LABEL" > /var/log/proxy_v2ray.log 2>&1 &
fi
sleep 2

# 8. Check listening ports
echo "[+] Active ports check:"
sudo ss -tulpn | grep -E ':8080|:10085|:10086' || true

echo "=========================================================="
echo " V2Ray Core & Proxy Bridge successfully started!"
echo " Reverse Proxy Port: 8080 (Cloudflare points to localhost:8080)"
echo "=========================================================="
