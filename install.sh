#!/bin/bash

# KG-Proxy One-Click Installer for Ubuntu/Debian
# Usage: sudo ./install.sh

set -e

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}== KG-Proxy Installer ==${NC}"

# 1. Check Root
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}Error: Please run as root (sudo ./install.sh)${NC}"
  exit 1
fi

# 2. Check Files
if [ ! -f "kg-proxy-backend" ]; then
    echo -e "${RED}Error: 'kg-proxy-backend' binary not found in current directory.${NC}"
    echo "Please build the backend first and place it here."
    exit 1
fi

if [ ! -d "frontend/dist" ]; then
    echo -e "${RED}Error: 'frontend/dist' directory not found in current directory.${NC}"
    echo "Please build the frontend first and place it inside 'frontend'."
    exit 1
fi

# 3. Install Dependencies
echo -e "${GREEN}[1/5] Installing system dependencies...${NC}"
apt-get update -qq
apt-get install -y -qq wireguard iptables ipset wireguard-tools

# 4. Setup Directories & Copy Files
echo -e "${GREEN}[2/5] Deploying files to /opt/kg-proxy...${NC}"
mkdir -p /opt/kg-proxy/frontend
cp kg-proxy-backend /opt/kg-proxy/
cp -r frontend/dist/* /opt/kg-proxy/frontend/

chmod +x /opt/kg-proxy/kg-proxy-backend

# 5. Create Systemd Service
echo -e "${GREEN}[3/5] Configuring systemd service...${NC}"
cat > /etc/systemd/system/kg-proxy.service <<EOF
[Unit]
Description=KG-Proxy Web GUI Backend
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/kg-proxy
ExecStart=/opt/kg-proxy/kg-proxy-backend
Restart=always
RestartSec=5
User=root
Environment=GIN_MODE=release

[Install]
WantedBy=multi-user.target
EOF

# 6. Enable Service
echo -e "${GREEN}[4/5] Enabling and starting service...${NC}"
systemctl daemon-reload
systemctl enable kg-proxy
systemctl stop kg-proxy 2>/dev/null || true
systemctl start kg-proxy

# 7. Open Firewall Ports
echo -e "${GREEN}[5/5] Configuring firewall (iptables)...${NC}"
# Allow Web GUI
iptables -A INPUT -p tcp --dport 8080 -j ACCEPT
# Allow WireGuard
iptables -A INPUT -p udp --dport 51820 -j ACCEPT

# Attempt to save if persistent package is installed, otherwise warn
if dpkg -l | grep -q iptables-persistent; then
    netfilter-persistent save
else
    echo "Note: 'iptables-persistent' not found. Rules might reset on reboot."
    echo "To save permanently: apt install iptables-persistent && netfilter-persistent save"
fi

echo -e "${GREEN}== Installation Complete! ==${NC}"
echo "Dashboard is running at: http://$(hostname -I | awk '{print $1}'):8080"
echo "Check status: systemctl status kg-proxy"
