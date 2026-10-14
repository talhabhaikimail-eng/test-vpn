#!/bin/bash
set -e

# ==============================================================================
# Ultra-Low Resource SlowDNS (DNSTT) Server Setup for 1 vCPU / 1GB RAM VPS
# Memory Envelope: Max 128MB RAM | CPU Cap: 75% of 1 vCPU
# ==============================================================================

DOMAIN="dns.ufone-claim.site"
TARGET="127.0.0.1:22"
INSTALL_DIR="/opt/dnstt"

echo "[1/6] Checking and creating swap (protects 1GB RAM from OOM)..."
if [ $(swapon --show | wc -l) -le 1 ]; then
    echo "Creating 1GB swapfile..."
    sudo fallocate -l 1G /swapfile 2>/dev/null || sudo dd if=/dev/zero of=/swapfile bs=1M count=1024
    sudo chmod 600 /swapfile
    sudo mkswap /swapfile
    sudo swapon /swapfile
    echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
fi

echo "[2/6] Freeing Port 53 from systemd-resolved safely..."
sudo systemctl stop systemd-resolved 2>/dev/null || true
sudo systemctl disable systemd-resolved 2>/dev/null || true
sudo rm -f /etc/resolv.conf
echo "nameserver 1.1.1.1" | sudo tee /etc/resolv.conf
echo "nameserver 8.8.8.8" | sudo tee -a /etc/resolv.conf

echo "[3/6] Installing dependencies and Go compiler..."
sudo apt-get update -qq
sudo apt-get install -y git golang-go ufw iptables

echo "[4/6] Building dnstt-server with binary size optimization..."
sudo mkdir -p "$INSTALL_DIR"
cd /tmp
rm -rf dnstt
git clone https://www.bamsoftware.com/git/dnstt.git
cd dnstt/dnstt-server
go build -ldflags="-s -w" -o "$INSTALL_DIR/dnstt-server"

echo "[5/6] Generating cryptographic key pair..."
cd "$INSTALL_DIR"
if [ ! -f server.key ] || [ ! -f server.pub ]; then
    ./dnstt-server -gen-key -privkey-file server.key -pubkey-file server.pub
fi
PUB_KEY=$(cat server.pub)

echo "[6/6] Creating systemd service with strict 128MB RAM and 75% CPU guardrails..."
sudo tee /etc/systemd/system/dnstt-server.service > /dev/null <<EOF
[Unit]
Description=DNSTT SlowDNS Server (Low-Memory Protected)
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
Environment="GOMEMLIMIT=128MiB"
Environment="GOGC=50"
ExecStart=$INSTALL_DIR/dnstt-server -udp :53 -privkey-file $INSTALL_DIR/server.key $DOMAIN $TARGET
Restart=always
RestartSec=5

# Strict resource boundaries for 1 vCPU / 1GB RAM VPS
MemoryMax=150M
MemoryHigh=120M
CPUQuota=75%
Nice=5

[Install]
WantedBy=multi-user.target
EOF

# Open firewall for UDP 53
if command -v ufw >/dev/null 2>&1; then
    sudo ufw allow 53/udp 2>/dev/null || true
    sudo ufw allow 22/tcp 2>/dev/null || true
fi

# Oracle Cloud iptables rule (Oracle Linux / Ubuntu often has strict iptables on eth0)
sudo iptables -I INPUT -p udp --dport 53 -j ACCEPT 2>/dev/null || true
if command -v netfilter-persistent >/dev/null 2>&1; then
    sudo netfilter-persistent save 2>/dev/null || true
fi

# Reload and start
sudo systemctl daemon-reload
sudo systemctl enable dnstt-server
sudo systemctl restart dnstt-server

echo "=============================================================================="
echo "  ✓ SLOWDNS (DNSTT) SERVER IS NOW RUNNING AND PROTECTED!"
echo "=============================================================================="
echo "  • Name Server (NS) Domain : $DOMAIN"
echo "  • Server Public Key (Hex) : $PUB_KEY"
echo "  • Upstream Target         : $TARGET (OpenSSH)"
echo "  • Max Memory Consumption : Capped at 128 MB (Leaves >850MB free)"
echo "  • Max CPU Consumption    : Capped at 75% of 1 vCPU"
echo "=============================================================================="
echo ""
echo "Save your Public Key above! You will paste it into your SlowDNS / DNSTT client app."
