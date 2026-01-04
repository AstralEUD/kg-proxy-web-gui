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

# 2. Check Files & Unpack if needed
if [ ! -f "kg-proxy-backend" ]; then
    if [ -f "release.tar.gz" ]; then
        echo -e "${GREEN}[*] Found release package. Unpacking...${NC}"
        # Unpack to current directory
        tar -xzf release.tar.gz
    else
        echo -e "${RED}Error: 'kg-proxy-backend' and 'release.tar.gz' not found.${NC}"
        echo "Please place the installer next to the release package."
        exit 1
    fi
fi

# Verify again after unpacking
if [ ! -f "kg-proxy-backend" ]; then
    echo -e "${RED}Error: 'kg-proxy-backend' binary not found after unpacking.${NC}"
    exit 1
fi

if [ ! -d "frontend" ]; then
    echo -e "${RED}Error: 'frontend' directory not found in current directory.${NC}"
    echo "Please build the frontend first and place it inside 'frontend'."
    exit 1
fi

# 3. Stop Service if running
echo -e "${GREEN}[1/7] Stopping existing service...${NC}"
systemctl stop kg-proxy 2>/dev/null || true

# 4. Install Dependencies
echo -e "${GREEN}[2/7] Installing system dependencies...${NC}"
apt-get update -qq
# Ensure GCC and Make make avail for eBPF 
apt-get install -y -qq wireguard iptables ipset wireguard-tools clang llvm libbpf-dev linux-headers-$(uname -r) make gcc gcc-multilib

# 5. Build eBPF
echo -e "${GREEN}[3/7] Building eBPF XDP filter...${NC}"
if [ -f "backend/ebpf/xdp_filter.c" ]; then
    if [ -f "build-ebpf.sh" ]; then
        chmod +x build-ebpf.sh
        ./build-ebpf.sh || echo -e "${RED}Warning: eBPF build failed. Simulation mode will be used.${NC}"
    else
        echo "build-ebpf.sh not found, skipping build."
    fi
else
    echo "Note: eBPF source not found. Assuming pre-compiled or simulation mode."
fi

# 6. Setup Directories & Copy Files
echo -e "${GREEN}[4/7] Deploying files...${NC}"
INSTALL_DIR="/opt/kg-proxy"
DATA_DIR="/var/lib/kg-proxy"

mkdir -p $INSTALL_DIR/frontend
mkdir -p $INSTALL_DIR/ebpf
mkdir -p $DATA_DIR

# Copy main binaries and assets
cp kg-proxy-backend $INSTALL_DIR/
cp -r frontend/* $INSTALL_DIR/frontend/

# Copy eBPF objects if they exist
if [ -d "backend/ebpf" ]; then
    cp -r backend/ebpf/* $INSTALL_DIR/ebpf/ 2>/dev/null || true
fi

chmod +x $INSTALL_DIR/kg-proxy-backend

# 6. Configure System Hardening (Sysctl)
echo -e "${GREEN}[4/7] Applying system hardening defaults...${NC}"
# We append to a custom sysctl file to persist across reboots
cat > /etc/sysctl.d/99-kg-proxy-hardening.conf <<EOF
# KG-Proxy Base Hardening
net.ipv4.ip_forward = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.core.bpf_jit_enable = 1
EOF
sysctl --system > /dev/null 2>&1 || true

# 7. Create Systemd Service
echo -e "${GREEN}[5/7] Configuring systemd service...${NC}"
cat > /etc/systemd/system/kg-proxy.service <<EOF
[Unit]
Description=KG-Proxy Web GUI Backend
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/kg-proxy-backend
Restart=always
RestartSec=5
User=root
Environment=GIN_MODE=release
Environment=KG_DATA_DIR=$DATA_DIR
LimitNOFILE=65535
StartLimitInterval=0

[Install]
WantedBy=multi-user.target
EOF

# 8. Install Management Script (kgctl)
echo -e "${GREEN}[6/7] Installing management tool (kgctl)...${NC}"
cat > /usr/local/bin/kgctl <<'EOF'
#!/bin/bash
# KG-Proxy Control Script

CMD=$1
SERVICE="kg-proxy"

case "$CMD" in
    start)
        systemctl start $SERVICE
        echo "Started $SERVICE"
        ;;
    stop)
        systemctl stop $SERVICE
        echo "Stopped $SERVICE"
        ;;
    restart)
        systemctl restart $SERVICE
        echo "Restarted $SERVICE"
        ;;
    status)
        systemctl status $SERVICE
        ;;
    logs)
        journalctl -u $SERVICE -f
        ;;
    update)
        echo "Pulling latest code and reinstalling..."
        git pull
        ./install.sh
        ;;
    *)
        echo "Usage: kgctl {start|stop|restart|status|logs|update}"
        exit 1
        ;;
esac
EOF
chmod +x /usr/local/bin/kgctl

# 9. Enable & Start
echo -e "${GREEN}[7/7] Enabling and starting service...${NC}"
systemctl daemon-reload
systemctl enable kg-proxy
systemctl stop kg-proxy 2>/dev/null || true
systemctl start kg-proxy

echo -e "${GREEN}== Installation Complete! ==${NC}"
echo -e "Dashboard: http://$(hostname -I | awk '{print $1}'):8080"
echo -e "Manage app using: ${GREEN}kgctl <command>${NC}"
echo -e "Example: ${GREEN}kgctl logs${NC} to see realtime logs"
