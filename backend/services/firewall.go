package services

import (
	"fmt"
	"kg-proxy-web-gui/backend/models"
	"kg-proxy-web-gui/backend/system"
	"os"
	"strings"

	"gorm.io/gorm"
)

type FirewallService struct {
	DB           *gorm.DB
	Executor     system.CommandExecutor
	GeoIP        *GeoIPService
	FloodProtect *FloodProtection
}

func NewFirewallService(db *gorm.DB, exec system.CommandExecutor, geoip *GeoIPService, flood *FloodProtection) *FirewallService {
	return &FirewallService{
		DB:           db,
		Executor:     exec,
		GeoIP:        geoip,
		FloodProtect: flood,
	}
}

func (s *FirewallService) ApplyRules() error {
	// Get security settings
	var settings models.SecuritySettings
	if err := s.DB.First(&settings, 1).Error; err != nil {
		system.Warn("No security settings found, using defaults")
		settings = models.SecuritySettings{
			GlobalProtection:  true,
			ProtectionLevel:   2,
			GeoAllowCountries: "KR",
			SYNCookies:        true,
		}
	}

	// Update flood protection level
	if s.FloodProtect != nil {
		s.FloodProtect.SetLevel(settings.ProtectionLevel)
	}

	// 1. Apply Kernel Hardening (Sysctl)
	if err := s.ApplyHardening(settings.ProtectionLevel); err != nil {
		system.Warn("Failed to apply kernel hardening: %v", err)
	}

	// 2. Generate ipset.rules
	ipsetRules, err := s.generateIPSetRules(&settings)
	if err != nil {
		return err
	}

	// 3. Generate iptables.rules.v4
	iptablesRules, err := s.generateIPTablesRules(&settings)
	if err != nil {
		return err
	}

	// 4. Apply via Executor (Linux only)
	system.Info("Applying firewall rules...")

	// Save rules to files (mock path for Windows, real logic would write to file)
	if err := s.saveRulesToFile("/tmp/ipset.rules", ipsetRules); err != nil {
		system.Warn("Failed to save ipset rules: %v", err)
	}

	if err := s.saveRulesToFile("/tmp/iptables.rules.v4", iptablesRules); err != nil {
		system.Warn("Failed to save iptables rules: %v", err)
	}

	// Apply ipset
	if _, err := s.Executor.Execute("ipset", "restore", "-f", "/tmp/ipset.rules"); err != nil {
		system.Warn("Error applying ipset (may not be on Linux): %v", err)
	} else {
		system.Info("IPSet rules applied successfully")
	}

	// Apply iptables
	if _, err := s.Executor.Execute("iptables-restore", "/tmp/iptables.rules.v4"); err != nil {
		system.Warn("Error applying iptables (may not be on Linux): %v", err)
	} else {
		system.Info("IPTables rules applied successfully")
	}

	// Enable SYN cookies if requested (backup check)
	if settings.SYNCookies && s.FloodProtect != nil {
		s.FloodProtect.EnableSYNCookies()
		s.FloodProtect.SetConntrackLimits()
	}

	return nil
}

func (s *FirewallService) generateIPSetRules(settings *models.SecuritySettings) (string, error) {
	var sb strings.Builder

	// Create ipsets
	sb.WriteString("create geo_allowed hash:net family inet hashsize 4096 maxelem 1000000 -exist\n")
	sb.WriteString("create vpn_proxy hash:net family inet hashsize 1024 maxelem 100000 -exist\n")
	sb.WriteString("create tor_exits hash:ip family inet hashsize 1024 maxelem 10000 -exist\n")
	sb.WriteString("create allow_foreign hash:ip family inet -exist\n")
	sb.WriteString("create ban hash:ip family inet -exist\n")
	sb.WriteString("create flood_blocked hash:ip family inet timeout 1800 -exist\n")
	sb.WriteString("create white_list hash:ip family inet -exist\n")

	// Flush existing entries
	sb.WriteString("flush geo_allowed\n")
	sb.WriteString("flush vpn_proxy\n")
	sb.WriteString("flush tor_exits\n")
	sb.WriteString("flush allow_foreign\n")
	sb.WriteString("flush ban\n")
	sb.WriteString("flush flood_blocked\n")
	sb.WriteString("flush white_list\n")

	// Add GeoIP allowed countries
	if s.GeoIP != nil {
		allowedCountries := strings.Split(settings.GeoAllowCountries, ",")
		for _, country := range allowedCountries {
			country = strings.TrimSpace(country)
			if country == "" {
				continue
			}

			// Get IP ranges for this country
			if ranges, ok := s.GeoIP.countryRanges[country]; ok {
				for _, ipRange := range ranges {
					sb.WriteString(fmt.Sprintf("add geo_allowed %s\n", ipRange.String()))
				}
			}
		}
	}

	// Add VPN/Proxy ranges if blocking enabled
	if settings.BlockVPN && s.GeoIP != nil {
		for _, vpnRange := range s.GeoIP.vpnRanges {
			sb.WriteString(fmt.Sprintf("add vpn_proxy %s\n", vpnRange.String()))
		}
	}

	// Add TOR exit nodes if blocking enabled
	if settings.BlockTOR && s.GeoIP != nil {
		for _, torIP := range s.GeoIP.torExitNodes {
			sb.WriteString(fmt.Sprintf("add tor_exits %s\n", torIP.String()))
		}
	}

	// Add manually allowed IP rules (white_list)
	var allowIPs []models.AllowIP
	s.DB.Find(&allowIPs)
	for _, a := range allowIPs {
		sb.WriteString(fmt.Sprintf("add white_list %s\n", a.IP))
	}

	// Add manually allowed foreign IPs
	var allowed []models.AllowForeign
	s.DB.Find(&allowed)
	for _, a := range allowed {
		sb.WriteString(fmt.Sprintf("add allow_foreign %s\n", a.IP))
	}

	// Add manually banned IPs
	var banned []models.BanIP
	s.DB.Find(&banned)
	for _, b := range banned {
		sb.WriteString(fmt.Sprintf("add ban %s\n", b.IP))
	}

	// Add flood-blocked IPs
	if s.FloodProtect != nil {
		blockedIPs := s.FloodProtect.GetBlockedIPs()
		for _, ip := range blockedIPs {
			sb.WriteString(fmt.Sprintf("add flood_blocked %s\n", ip))
		}
	}

	return sb.String(), nil
}

func (s *FirewallService) generateIPTablesRules(settings *models.SecuritySettings) (string, error) {
	var sb strings.Builder

	// ==========================================
	// 1. Mangle Table (Advanced Packet Filter)
	// ==========================================
	sb.WriteString("*mangle\n")
	sb.WriteString(":PREROUTING ACCEPT [0:0]\n")
	sb.WriteString(":INPUT ACCEPT [0:0]\n")
	sb.WriteString(":FORWARD ACCEPT [0:0]\n")
	sb.WriteString(":OUTPUT ACCEPT [0:0]\n")
	sb.WriteString(":POSTROUTING ACCEPT [0:0]\n")
	sb.WriteString(":DDOS_PRE - [0:0]\n")
	sb.WriteString(":GEO_GUARD - [0:0]\n")

	if settings.GlobalProtection {
		// 1-1. Early Drop: Invalid Packets
		sb.WriteString("-A PREROUTING -m conntrack --ctstate INVALID -j DROP\n")

		// 1-2. TCP Flag Validation (Block abnormal flags)
		sb.WriteString("-A PREROUTING -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP\n")
		sb.WriteString("-A PREROUTING -p tcp --tcp-flags SYN,RST SYN,RST -j DROP\n")
		sb.WriteString("-A PREROUTING -p tcp --tcp-flags FIN,RST FIN,RST -j DROP\n")
		sb.WriteString("-A PREROUTING -p tcp --tcp-flags ALL NONE -j DROP\n")
		sb.WriteString("-A PREROUTING -p tcp --tcp-flags FIN,PSH,URG FIN,PSH,URG -j DROP\n")

		// 1-3. Block New non-SYN packets
		sb.WriteString("-A PREROUTING -p tcp ! --syn -m conntrack --ctstate NEW -j DROP\n")

		// 1-4. Block Abnormal MSS
		sb.WriteString("-A PREROUTING -p tcp -m conntrack --ctstate NEW -m tcpmss ! --mss 536:65535 -j DROP\n")

		// 1-5. Block Fragments - REMOVED for Arma 3 Compatibility
		// Arma 3 uses fragmented UDP packets for server details. Blocking this breaks server browser listings.
		// sb.WriteString("-A PREROUTING -f -j DROP\n")

		// 1-5a. Block UDP Reflection Attacks - MOVED/REMOVED
		// ERROR: This blocked DNS responses (Source Port 53) because the server acts as a client.
		// To fix: We only allow these if state is ESTABLISHED (handled by conntrack usually),
		// but since this is Mangle/PreRouting, it hits before standard Input allow.
		// Safest approach for now: Remove blind blocking of sport 53/123.
		sb.WriteString("-A PREROUTING -p udp -m multiport --sports 1900,11211 -j DROP\n")

		// 1-5b. Block Bogon IPs (Spoofed IPs from local/reserved ranges) on WAN interface
		sb.WriteString("-A PREROUTING -i eth0 -s 127.0.0.0/8 -j DROP\n")
		sb.WriteString("-A PREROUTING -i eth0 -s 169.254.0.0/16 -j DROP\n")
		sb.WriteString("-A PREROUTING -i eth0 -s 224.0.0.0/4 -j DROP\n")
		// Extended Bogon (Private ranges that shouldn't appear on public internet/eth0)
		// sb.WriteString("-A PREROUTING -i eth0 -s 192.168.0.0/16 -j DROP\n")
		// sb.WriteString("-A PREROUTING -i eth0 -s 172.16.0.0/12 -j DROP\n")
		// Note: We keep private ranges allowed for now to prevent accidental lockout if behind NAT/VPC.

		// 1-5g. Block Database Ports (No reason for external access)
		sb.WriteString("-A PREROUTING -p tcp -m multiport --dports 1433,1521,3306,5432 -j DROP\n")
		sb.WriteString("-A PREROUTING -p udp -m multiport --dports 1433,1521,3306,5432 -j DROP\n")

		// 1-5c. Limit ICMP (Ping) to prevent flood
		sb.WriteString("-A PREROUTING -p icmp --icmp-type echo-request -m limit --limit 2/second -j ACCEPT\n")
		sb.WriteString("-A PREROUTING -p icmp --icmp-type echo-request -j DROP\n")

		// 1-5d. Block empty UDP packets (Length check)
		// IP Header (20) + UDP Header (8) = 28 bytes. Anything <= 28 means no payload.
		// Game packets always have payload.
		sb.WriteString("-A PREROUTING -p udp -m length --length 0:28 -j DROP\n")

		// 1-5e. TCP RST Flood Protection
		sb.WriteString("-A PREROUTING -p tcp --tcp-flags RST RST -m limit --limit 2/second --limit-burst 2 -j ACCEPT\n")
		sb.WriteString("-A PREROUTING -p tcp --tcp-flags RST RST -j DROP\n")

		// 1-5f. Block SYN-ACK Flood (Packets with SYN+ACK but no established connection)
		sb.WriteString("-A PREROUTING -p tcp --tcp-flags SYN,ACK SYN,ACK -m conntrack --ctstate NEW -j DROP\n")

		// 1-5h. UDP Flood Protection (Per-IP Rate Limit)
		// Limit each source IP to 120,000 packets/sec (approx 100Mbps for small packets).
		// This is extremely high for a game but ensures no legitimate traffic is dropped.
		sb.WriteString("-A PREROUTING -p udp -m hashlimit --hashlimit-name udp_flood --hashlimit-mode srcip --hashlimit-upto 120000/sec --hashlimit-burst 240000 -j ACCEPT\n")
		sb.WriteString("-A PREROUTING -p udp -j DROP\n")

		// 1-5i. ICMP Flood Protection (Per-IP)
		sb.WriteString("-A PREROUTING -p icmp --icmp-type echo-request -m hashlimit --hashlimit-name icmp_flood --hashlimit-mode srcip --hashlimit-upto 5/sec --hashlimit-burst 10 -j ACCEPT\n")
		sb.WriteString("-A PREROUTING -p icmp --icmp-type echo-request -j DROP\n")
	}

	// 1-6. Apply GEO_GUARD logic (Drop if not allowed)
	// We removed strict hashlimit/rate-limiting rules here to avoid blocking legitimate game traffic spikes.
	// Game traffic patterns vary wildly (e.g. initial connection burst, large map download),
	// so generic rate limiting at kernel level is risky.
	// We rely on:
	// 1. Vultr's upstream DDoS protection (L3/L4)
	// 2. Protocol validation (Invalid packets, TCP flags) above
	// 3. GeoIP & Blacklist filtering below
	// 4. eBPF/Application level monitoring (Traffic Analysis)

	sb.WriteString("-A PREROUTING -j GEO_GUARD\n")
	sb.WriteString("-A GEO_GUARD -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN\n")

	// Exempt management ports from GEO_GUARD to prevent lockout
	sb.WriteString("-A GEO_GUARD -p tcp -m multiport --dports 22,80,443,8080 -j RETURN\n")

	// Steam Query Bypass (A2S_INFO, A2S_PLAYER, A2S_RULES)
	// Signatures: T (54), U (55), V (56). Payload start around byte 28 (20 IP + 8 UDP).
	// We use direct hex matching for safety.
	if settings.SteamQueryBypass {
		// A2S_INFO (Source Engine Query) - 'T'
		sb.WriteString("-A GEO_GUARD -p udp -m string --algo bm --hex-string \"|ffffffff54|\" --from 28 --to 40 -j RETURN\n")
		// A2S_PLAYER - 'U'
		sb.WriteString("-A GEO_GUARD -p udp -m string --algo bm --hex-string \"|ffffffff55|\" --from 28 --to 40 -j RETURN\n")
		// A2S_RULES - 'V'
		sb.WriteString("-A GEO_GUARD -p udp -m string --algo bm --hex-string \"|ffffffff56|\" --from 28 --to 40 -j RETURN\n")
		// Challenge Response (Simple 'q' or legacy A2S_PLAYER challenge) - 'W' (57)
		sb.WriteString("-A GEO_GUARD -p udp -m string --algo bm --hex-string \"|ffffffff57|\" --from 28 --to 40 -j RETURN\n")
	}

	// Always allow private ranges (SSH, Internal Network)
	sb.WriteString("-A GEO_GUARD -s 10.0.0.0/8 -j RETURN\n")
	sb.WriteString("-A GEO_GUARD -s 192.168.0.0/16 -j RETURN\n")
	sb.WriteString("-A GEO_GUARD -s 172.16.0.0/12 -j RETURN\n")
	sb.WriteString("-A GEO_GUARD -s 127.0.0.0/8 -j RETURN\n")

	sb.WriteString("-A GEO_GUARD -m set --match-set white_list src -j RETURN\n")
	sb.WriteString("-A GEO_GUARD -m set --match-set ban src -j DROP\n")
	sb.WriteString("-A GEO_GUARD -m set --match-set geo_allowed src -j RETURN\n")
	sb.WriteString("-A GEO_GUARD -m set --match-set allow_foreign src -j RETURN\n")
	// Drop everything else that didn't match ALLOW sets
	sb.WriteString("-A GEO_GUARD -j DROP\n")

	sb.WriteString("COMMIT\n")

	// ==========================================
	// 2. NAT Table (Port Forwarding)
	// ==========================================
	sb.WriteString("*nat\n")
	sb.WriteString(":PREROUTING ACCEPT [0:0]\n")
	sb.WriteString(":INPUT ACCEPT [0:0]\n")
	sb.WriteString(":OUTPUT ACCEPT [0:0]\n")
	sb.WriteString(":POSTROUTING ACCEPT [0:0]\n")

	// Get services from DB for DNAT rules
	var services []models.Service
	s.DB.Preload("Origin").Preload("Ports").Find(&services)

	for _, svc := range services {
		if svc.Origin.WgIP == "" {
			continue
		}

		// DNAT rules for dynamic service ports
		// Pre-routing DNAT happens here.
		// Note: Traffic has already passed Mangle PREROUTING checks.
		for _, port := range svc.Ports {
			if port.PublicPort > 0 && port.PrivatePort > 0 {
				protocol := strings.ToLower(port.Protocol) // tcp or udp
				sb.WriteString(fmt.Sprintf("-A PREROUTING -p %s --dport %d -j DNAT --to-destination %s:%d\n",
					protocol, port.PublicPort, svc.Origin.WgIP, port.PrivatePort))
			}
		}
	}

	// Masquerade for WireGuard outbound
	sb.WriteString("-A POSTROUTING -s 10.200.0.0/24 -o eth0 -j MASQUERADE\n")
	sb.WriteString("COMMIT\n")

	// ==========================================
	// 3. Filter Table (Host Protection)
	// ==========================================
	sb.WriteString("*filter\n")
	sb.WriteString(":INPUT DROP [0:0]\n")
	sb.WriteString(":FORWARD DROP [0:0]\n")
	sb.WriteString(":OUTPUT ACCEPT [0:0]\n")

	// Allow loopback
	sb.WriteString("-A INPUT -i lo -j ACCEPT\n")
	sb.WriteString("-A OUTPUT -o lo -j ACCEPT\n")

	// Allow established connections
	sb.WriteString("-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n")

	// 1. SSH Brute-force Protection (Max 3 attempts per 60s)
	sb.WriteString("-A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --set\n")
	sb.WriteString("-A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 4 -j DROP\n")
	sb.WriteString("-A INPUT -p tcp --dport 22 -j ACCEPT\n")

	// 2. Global TCP Connection Limit per IP (Max 50)
	sb.WriteString("-A INPUT -p tcp -m connlimit --connlimit-above 50 --connlimit-mask 32 -j DROP\n")

	// Allow WireGuard (port 51820)
	sb.WriteString("-A INPUT -p udp --dport 51820 -j ACCEPT\n")

	// Allow HTTP/HTTPS for Web GUI
	sb.WriteString("-A INPUT -p tcp --dport 80 -j ACCEPT\n")
	sb.WriteString("-A INPUT -p tcp --dport 443 -j ACCEPT\n")
	sb.WriteString("-A INPUT -p tcp --dport 8080 -j ACCEPT\n")

	// Forwarding rules (Critical for NAT)
	// Allow forwarded traffic that passed Mangle checks
	// Allow NEW connections from wg0 (Origin) to eth0 (Internet) for updates/APIs
	sb.WriteString("-A FORWARD -i eth0 -o wg0 -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT\n")
	sb.WriteString("-A FORWARD -i wg0 -o eth0 -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT\n")

	sb.WriteString("COMMIT\n")

	return sb.String(), nil
}

func (s *FirewallService) saveRulesToFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0644)
}
