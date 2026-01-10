#!/bin/bash
echo "============================================"
echo " KG-Proxy Connectivity Debug Script"
echo "============================================"

echo -e "\n[1] Network Interfaces & IPs"
ip addr show

echo -e "\n[2] Routing Table"
ip route show

echo -e "\n[3] Kernel Forwarding & Security Settings"
sysctl net.ipv4.ip_forward
sysctl net.ipv4.conf.all.rp_filter
sysctl net.ipv4.conf.default.rp_filter
sysctl net.ipv4.conf.wg0.rp_filter 2>/dev/null

echo -e "\n[4] WireGuard Status"
if command -v wg &> /dev/null; then
    wg show
else
    echo "WireGuard command (wg) not found."
fi

echo -e "\n[5] Firewall Rules (NAT Table - Critical for Connectivity)"
iptables -t nat -L -n -v

echo -e "\n[6] Firewall Rules (Filter Table - Forwarding)"
iptables -L FORWARD -n -v

echo -e "\n[7] Firewall Rules (Mangle Table - Dropping)"
iptables -t mangle -L -n -v

echo -e "\n============================================"
echo "Please copy the output above and share it."
echo "============================================"
