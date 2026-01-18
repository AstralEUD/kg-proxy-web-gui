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
if [ "$(id -u)" -ne 0 ]; then
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

# Define directories early so cleanup can use them
INSTALL_DIR="/opt/kg-proxy"
DATA_DIR="/var/lib/kg-proxy"

# 3. Aggressive Cleanup
echo -e "${GREEN}[1/7] Cleaning up old installation...${NC}"

# Stop service
systemctl stop kg-proxy 2>/dev/null || true
systemctl disable kg-proxy 2>/dev/null || true

# Kill processes aggressively
pkill -9 kg-proxy-backend 2>/dev/null || true
pkill -9 kg-proxy 2>/dev/null || true

# Wait for process death
sleep 2

# Force remove OLD directories (Clean slate)
rm -rf $INSTALL_DIR/frontend
rm -rf $INSTALL_DIR/ebpf
rm -f $INSTALL_DIR/kg-proxy-backend

# Clean eBPF maps (Important for re-loading) - BOTH old (hyphen) and new (underscore) paths
echo "Cleaning eBPF maps..."
rm -rf /sys/fs/bpf/kg-proxy
rm -rf /sys/fs/bpf/kg_proxy
rm -rf /sys/fs/bpf/xdp_filter

# Aggressively unload XDP from ALL interfaces to prevent "Can't replace active BPF XDP link" error
echo "Unloading existing XDP programs..."
for iface in $(ip -o link show | awk -F': ' '{print $2}'); do
    ip link set dev $iface xdp off 2>/dev/null || true
    ip link set dev $iface xdpgeneric off 2>/dev/null || true
    ip link set dev $iface xdpdrv off 2>/dev/null || true
done

# 4. Install Dependencies
echo -e "${GREEN}[2/7] Installing system dependencies...${NC}"
apt-get update -qq
# Ensure GCC and Make make avail for eBPF 
apt-get install -y -qq wireguard iptables ipset wireguard-tools clang llvm libbpf-dev linux-headers-$(uname -r) make gcc gcc-multilib

# 5. Build eBPF (Try to build, fallback to pre-compiled if present)
echo -e "${GREEN}[3/7] Building eBPF XDP filter...${NC}"
if [ -f "backend/ebpf/xdp_filter.c" ]; then
    if [ -f "build-ebpf.sh" ]; then
        chmod +x build-ebpf.sh
        # If build fails, we exit because we removed simulation mode
        ./build-ebpf.sh || { echo -e "${RED}eBPF Build Failed! Stopping install.${NC}"; exit 1; }
    else
        echo "build-ebpf.sh not found, skipping build."
    fi
else
    echo "Note: eBPF source not found. Assuming pre-compiled objects exist."
fi

# 6. Setup Directories & Copy Files
echo -e "${GREEN}[4/7] Deploying files...${NC}"
# INSTALL_DIR and DATA_DIR already defined at script start

mkdir -p $INSTALL_DIR/frontend
mkdir -p $INSTALL_DIR/ebpf
mkdir -p $DATA_DIR

# Copy main binaries and assets
cp kg-proxy-backend $INSTALL_DIR/
cp -r frontend/* $INSTALL_DIR/frontend/

# Copy eBPF objects if they exist
if [ -f "backend/ebpf/build/xdp_filter.o" ]; then
    cp backend/ebpf/build/xdp_filter.o $INSTALL_DIR/ebpf/
    # Also copy tc_egress.o if exists
    if [ -f "backend/ebpf/build/tc_egress.o" ]; then
        cp backend/ebpf/build/tc_egress.o $INSTALL_DIR/ebpf/
    else
        echo -e "${YELLOW}Warning: tc_egress.o not found. Outbound connection tracking will be disabled.${NC}"
    fi
elif [ -d "backend/ebpf" ]; then # Fallback to copy all if specific build files not found
    cp -r backend/ebpf/* $INSTALL_DIR/ebpf/ 2>/dev/null || true
fi

chmod +x $INSTALL_DIR/kg-proxy-backend

# Fix permissions for sudo user (if exists) so they can fix things later
if [ -n "$SUDO_USER" ]; then
    echo "Setting ownership for user '$SUDO_USER' to allow easier management..."
    chown -R $SUDO_USER:$(id -gn $SUDO_USER) $INSTALL_DIR
    chown -R $SUDO_USER:$(id -gn $SUDO_USER) $DATA_DIR
fi

# 6. Configure System Hardening (Sysctl)
echo -e "${GREEN}[4/7] Applying system hardening defaults...${NC}"
# We append to a custom sysctl file to persist across reboots
cat > /etc/sysctl.d/99-kg-proxy-hardening.conf <<EOF
# KG-Proxy Base Hardening
net.ipv4.ip_forward = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2
net.ipv4.conf.all.log_martians = 0
net.ipv4.conf.default.log_martians = 0
net.core.bpf_jit_enable = 1

# TCP Optimization (SACK enabled for better loss recovery)
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_mtu_probing = 1

# Conntrack Optimization (Critical for preventing lockout under load)
net.netfilter.nf_conntrack_max = 2000000
net.netfilter.nf_conntrack_udp_timeout = 10
net.netfilter.nf_conntrack_udp_timeout_stream = 60
net.netfilter.nf_conntrack_tcp_timeout_established = 600
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 30
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
# Network Optimization: Increase Ring Buffers for Burst Tolerance (Ignore failure if unsupported)
ExecStartPre=/bin/sh -c 'ethtool -G $(ip route | grep default | awk "{print \$5}" | head -n1) rx 4096 tx 4096 2>/dev/null || true'
ExecStart=$INSTALL_DIR/kg-proxy-backend
Restart=always
RestartSec=5
User=root
Environment=GIN_MODE=release
Environment=KG_DATA_DIR=$DATA_DIR
Environment=GOGC=50
Environment=GOMEMLIMIT=3500MiB
# Optional: Set your MaxMind license key for accurate GeoIP filtering
# Get a free key at: https://www.maxmind.com/en/geolite2/signup
# Environment=MAXMIND_LICENSE_KEY=your_license_key_here
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

# 10. Restore Ownership (Fix for SFTP/Uploads)
if [ -n "$SUDO_USER" ]; then
    echo -e "${GREEN}[Post-Install] Restoring directory ownership to $SUDO_USER...${NC}"
    chown -R $SUDO_USER:$(id -gn $SUDO_USER) .
fi

echo -e "${GREEN}== Installation Complete! ==${NC}"
echo -e "Dashboard: http://$(hostname -I | awk '{print $1}'):8080"
echo -e "Manage app using: ${GREEN}kgctl <command>${NC}"
echo -e "Example: ${GREEN}kgctl logs${NC} to see realtime logs"
