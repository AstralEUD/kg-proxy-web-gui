# KG-Proxy Build & Package Script for Windows
# Creates release.tar.gz for Linux deployment

Write-Host "🚀 Starting Build Process..." -ForegroundColor Cyan

# 1. Build Backend (Linux Target)
Write-Host "`n[1/4] Building Backend (Go)..." -ForegroundColor Yellow
$env:GOOS = "linux"
$env:GOARCH = "amd64"
Check-Location "backend" {
    go build -o ../kg-proxy-backend .
}
if ($LASTEXITCODE -ne 0) { Write-Error "Backend build failed"; exit 1 }

# 2. Build Frontend
Write-Host "`n[2/4] Building Frontend (npm)..." -ForegroundColor Yellow
Check-Location "frontend" {
    if (!(Test-Path "node_modules")) { npm install }
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

# 2. Install Dependencies
show_progress 30 "Installing dependencies(apt)..."
# Suppress output unless error
apt-get update -qq >/dev/null 2>&1
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq wireguard iptables ipset wireguard-tools curl >/dev/null 2>&1

# 3. Setup Directories
show_progress 50 "Configuring directories..."
# Cleanup old version
systemctl stop kg-proxy 2>/dev/null || true
rm -rf /opt/kg-proxy
mkdir -p /opt/kg-proxy/frontend

# 4. Extract Files
show_progress 70 "Extracting build artifacts..."
tar -xzf release.tar.gz -C /opt/kg-proxy/

# Move binary to root of /opt/kg-proxy if it was inside a structure
# (Handling the case if tar structure varies, but package.ps1 keeps it flat-ish)
# Ensure binary is executable
chmod +x /opt/kg-proxy/kg-proxy-backend

# 5. Service Setup
show_progress 85 "Registering Systemd service..."
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

systemctl daemon-reload
systemctl enable kg-proxy >/dev/null 2>&1
systemctl start kg-proxy

# 6. Firewall
show_progress 95 "Opening Firewall ports..."
iptables -A INPUT -p tcp --dport 8080 -j ACCEPT
iptables -A INPUT -p udp --dport 51820 -j ACCEPT
if dpkg -l | grep -q iptables-persistent; then
    netfilter-persistent save >/dev/null 2>&1
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

# Use tar to pack specific files. backend binary + frontend dist
# We need to make sure directory structure inside tar is clean.
# /kg-proxy-backend
# /frontend/dist/...

if (Test-Path "release.tar.gz") { Remove-Item "release.tar.gz" }

# We will use the system tar (available in Win10+)
# Check if tar exists
if (Get-Command "tar" -ErrorAction SilentlyContinue) {
    tar -czf release.tar.gz kg-proxy-backend frontend/dist
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
