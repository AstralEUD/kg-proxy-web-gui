# KG-Proxy Build & Package Script for Windows
# Creates release.tar.gz for Linux deployment

Write-Host "🚀 Starting Build Process..." -ForegroundColor Cyan

# 0. Sync eBPF (Optional, requires Linux/WSL/Docker with clang)
# Write-Host "`n[0/4] Regenerating eBPF Bindings (Optional)..." -ForegroundColor Yellow
# Write-Host "Note: This requires clang and linux-headers. Skip if already synced." -ForegroundColor Gray
# Check-Location "backend" {
#     # go generate ./...
# }

# 1. Build Backend (Linux Target)
Write-Host "`n[1/4] Building Backend (Go)..." -ForegroundColor Yellow
$env:GOOS = "linux"
$env:GOARCH = "amd64"
Check-Location "backend" {
    # Ensure dependencies are tidy
    go mod tidy
    go build -v -o ../kg-proxy-backend .
}
if ($LASTEXITCODE -ne 0) { Write-Error "Backend build failed"; exit 1 }

# 2. Build Frontend
Write-Host "`n[2/4] Building Frontend (npm)..." -ForegroundColor Yellow
Check-Location "frontend" {
    if (!(Test-Path "node_modules")) { npm install --legacy-peer-deps }
    npm run build
}
if ($LASTEXITCODE -ne 0) { Write-Error "Frontend build failed"; exit 1 }

# 3. Create install.sh (Embedded content to ensure it's always sync)
Write-Host "`n[3/4] Generating install.sh..." -ForegroundColor Yellow
$installScriptContent = @"
#!/bin/bash
# KG-Proxy Installer
# Usage: sudo ./install.sh

set -e

# Colors & Formatting
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

# Banner
clear
echo -e "\${CYAN}\${BOLD}"
echo "  _  __  ____      ____                      "
echo " | |/ / / ___|    |  _ \ _ __ _____  ___   _ "
echo " | ' / | |  _ ____| |_) | '__/ _ \ \/ / | | |"
echo " | . \ | |_| |____|  __/| | | (_) >  <| |_| |"
echo " |_|\_\ \____|    |_|   |_|  \___/_/\_\\__, |"
echo "                                       |___/ "
echo -e "\${NC}"
echo -e "\${BLUE}:: One-Click Deployment System ::\${NC}"
echo ""

# Progress Bar Function
show_progress() {
    local width=40
    local percent=\$1
    local info="\$2"
    local filled=\$((\$width * \$percent / 100))
    local empty=\$((\$width - \$filled))
    
    printf "\r\${CYAN}[\${NC}"
    printf "%0.s#" \$(seq 1 \$filled)
    printf "%0.s-" \$(seq 1 \$empty)
    printf "\${CYAN}]\${NC} \${percent}%% - \$info"
}

# Root Check
if [ "\$EUID" -ne 0 ]; then
  echo -e "\${RED}❌ Error: Must run as root (try: sudo ./install.sh)\${NC}"
  exit 1
fi

echo -e "\${YELLOW}⚠️  Starting installation in 3 seconds...\${NC}"
sleep 3
echo ""

# 1. Check Artifacts
show_progress 10 "Checking files..."
if [ ! -f "release.tar.gz" ]; then
    echo -e "\n\${RED}❌ Error: 'release.tar.gz' not found!\${NC}"
    exit 1
fi
sleep 1

# 2. Aggressive Cleanup
show_progress 20 "Cleaning up old installation..."

# Stop service
systemctl stop kg-proxy 2>/dev/null || true
systemctl disable kg-proxy 2>/dev/null || true

# Kill processes aggressively
pkill -9 kg-proxy-backend 2>/dev/null || true
pkill -9 kg-proxy 2>/dev/null || true

# Wait for process death
sleep 2

# Force remove OLD directories (Clean slate)
rm -rf /opt/kg-proxy/frontend
rm -rf /opt/kg-proxy/ebpf
rm -f /opt/kg-proxy/kg-proxy-backend

# Clean eBPF maps (Important for re-loading)
# Use underscores as defined in backend/services/ebpf.go
echo "Cleaning eBPF maps..."
rm -rf /sys/fs/bpf/kg_proxy
rm -rf /sys/fs/bpf/xdp_filter

# Auto-detect interface
IFACE=\$(ip route show default | awk '/default/ {print \$5}')
if [ -n "\$IFACE" ]; then
    echo "Detaching XDP from \$IFACE..."
    ip link set dev \$IFACE xdp off 2>/dev/null || true
fi

# 3. Install Dependencies
show_progress 40 "Installing dependencies(apt)..."
apt-get update -qq >/dev/null 2>&1
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq wireguard iptables ipset wireguard-tools curl clang llvm libbpf-dev linux-headers-\$(uname -r) make gcc gcc-multilib >/dev/null 2>&1

# 4. Build eBPF (Optional, if source is provided)
show_progress 50 "Configuring eBPF..."
if [ -d "backend/ebpf" ]; then
    if [ -f "build-ebpf.sh" ]; then
        chmod +x build-ebpf.sh
        echo "Building eBPF from source..."
        # If build fails, we exit
        ./build-ebpf.sh || { echo -e "\${RED}eBPF Build Failed! Stopping install.\${NC}"; exit 1; }
    fi
else
    echo "Note: eBPF source not found. Relying on embedded objects in backend binary."
fi

# 5. Setup Directories & Copy Files
show_progress 60 "Deploying files..."
INSTALL_DIR="/opt/kg-proxy"
DATA_DIR="/var/lib/kg-proxy"

mkdir -p \$INSTALL_DIR/frontend
mkdir -p \$INSTALL_DIR/ebpf
mkdir -p \$DATA_DIR

# Extract
show_progress 70 "Extracting build artifacts..."
tar -xzf release.tar.gz -C /opt/kg-proxy/

# Ensure permissions
chmod +x \$INSTALL_DIR/kg-proxy-backend

# Fix permissions for astral user so they can fix things later
if id "astral" &>/dev/null; then
    echo "Setting ownership for user 'astral' to allow easier management..."
    chown -R astral:astral \$INSTALL_DIR
    chown -R astral:astral \$DATA_DIR
fi

# 6. Configure System Hardening (Sysctl)
show_progress 80 "Applying system hardening..."
cat > /etc/sysctl.d/99-kg-proxy-hardening.conf <<EOF
# KG-Proxy Base Hardening
net.ipv4.ip_forward = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2
net.core.bpf_jit_enable = 1
net.netfilter.nf_conntrack_max = 2000000
EOF
sysctl --system > /dev/null 2>&1 || true

# 7. Create Systemd Service
show_progress 85 "Configuring systemd service..."
cat > /etc/systemd/system/kg-proxy.service <<EOF
[Unit]
Description=KG-Proxy Web GUI Backend
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=\$INSTALL_DIR
ExecStart=\$INSTALL_DIR/kg-proxy-backend
Restart=always
RestartSec=5
User=root
Environment=GIN_MODE=release
Environment=KG_DATA_DIR=\$DATA_DIR
LimitNOFILE=65535
StartLimitInterval=0

[Install]
WantedBy=multi-user.target
EOF

# 8. Enable & Start
systemctl daemon-reload
systemctl enable kg-proxy >/dev/null 2>&1
systemctl stop kg-proxy 2>/dev/null || true
systemctl start kg-proxy

show_progress 95 "Opening Dashboard ports..."
iptables -A INPUT -p tcp --dport 8080 -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
iptables -A INPUT -p udp --dport 51820 -j ACCEPT
if dpkg -l | grep -q iptables-persistent; then
    netfilter-persistent save >/dev/null 2>&1
fi

# 9. Restore Ownership (Fix for SFTP/Uploads)
if [ -n "\$SUDO_USER" ]; then
    echo -e "\${GREEN}[Post-Install] Restoring directory ownership to \$SUDO_USER...\${NC}"
    chown -R \$SUDO_USER:\$(id -gn \$SUDO_USER) .
fi

show_progress 100 "Done!"
echo ""
echo ""

# Summary
IP=\$(hostname -I | awk '{print \$1}')
echo -e "\${GREEN}✔ Installation Successful!\${NC}"
echo -e "------------------------------------------------"
echo -e "📡 Dashboard : \${BOLD}http://\$IP:8080\${NC}"
echo -e "📂 Directory : /opt/kg-proxy"
echo -e "⚙️  Service   : systemctl status kg-proxy"
echo -e "------------------------------------------------"
"@
$installScriptContent | Out-File -Encoding utf8 "install.sh"
# Convert to LF for Linux compatibility
(Get-Content "install.sh") -join "`n" | Set-Content -NoNewline "install.sh"

# 4. Create Tarball
Write-Host "`n[4/4] Packaging release.tar.gz..." -ForegroundColor Yellow

# Use tar to pack specific files. backend binary + frontend dist + ebpf source
if (Test-Path "release.tar.gz") { Remove-Item "release.tar.gz" }

# Check if tar exists
if (Get-Command "tar" -ErrorAction SilentlyContinue) {
    # Include backend/ebpf source and build script so the VPS can re-compile if needed
    tar -czf release.tar.gz kg-proxy-backend frontend/dist backend/ebpf build-ebpf.sh
}
else {
    Write-Error "tar command not found. Please install git-bash or enable WSL."
    exit 1
}

Write-Host "`n✅ Build Complete!" -ForegroundColor Green
Write-Host "Files to upload:"
Write-Host "  - install.sh"
Write-Host "  - release.tar.gz"

# Helper function
function Check-Location {
    param($path, $scriptblock)
    Push-Location $path
    try { & $scriptblock } finally { Pop-Location }
}
