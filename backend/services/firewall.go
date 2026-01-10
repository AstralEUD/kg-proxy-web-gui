package services

import (
	"fmt"
	"kg-proxy-web-gui/backend/models"
	"kg-proxy-web-gui/backend/system"
	"os"
	"strings"
	"time"

	"gorm.io/gorm"
)

type FirewallService struct {
	DB           *gorm.DB
	Executor     system.CommandExecutor
	GeoIP        *GeoIPService
	FloodProtect *FloodProtection

	inMaintenance bool // internal state to track if we're currently in maintenance mode
}

func NewFirewallService(db *gorm.DB, exec system.CommandExecutor, geoip *GeoIPService, flood *FloodProtection) *FirewallService {
	return &FirewallService{
		DB:            db,
		Executor:      exec,
		GeoIP:         geoip,
		FloodProtect:  flood,
		inMaintenance: false,
	}
}

// StartMaintenanceWatcher starts a background loop to check for maintenance expiration
func (s *FirewallService) StartMaintenanceWatcher() {
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			var settings models.SecuritySettings
			if err := s.DB.First(&settings, 1).Error; err != nil {
				continue
			}

			// If we are in maintenance mode but the time has expired
			if settings.MaintenanceUntil != nil && time.Now().After(*settings.MaintenanceUntil) {
				system.Info("🕒 Maintenance mode expired. Automatically restoring firewall...")

				// Clear the expiration time in DB so we don't repeat this
				s.DB.Model(&settings).Update("maintenance_until", nil)

				// Re-apply normal rules
				s.inMaintenance = false
				s.ApplyRules()
			}
		}
	}()
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

	// Check Maintenance Mode: If active, bypass all blocking
	if settings.MaintenanceUntil != nil && settings.MaintenanceUntil.After(time.Now()) {
		system.Warn("🔧 Maintenance Mode Active until %s - Bypassing all blocking rules", settings.MaintenanceUntil.Format("15:04:05"))
		s.inMaintenance = true
		// Apply minimal rules (ACCEPT all)
		return s.applyMaintenanceMode()
	}
	s.inMaintenance = false

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
	sb.WriteString("create geo_allowed hash:net family inet hashsize 65536 maxelem 1000000 -exist\n")
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

		// Download country CIDRs if needed
		s.GeoIP.DownloadCountryCIDRs(allowedCountries)

		for _, country := range allowedCountries {
			country = strings.TrimSpace(country)
			if country == "" {
				continue
			}

			// Get IP ranges for this country
			cidrs := s.GeoIP.GetCountryCIDRs(country)
			for _, cidr := range cidrs {
				sb.WriteString(fmt.Sprintf("add geo_allowed %s\n", cidr))
			}
		}
	}

	// Add VPN/Proxy ranges if blocking enabled
	if settings.BlockVPN && s.GeoIP != nil {
		for _, vpnRange := range s.GeoIP.GetVPNRanges() {
			sb.WriteString(fmt.Sprintf("add vpn_proxy %s\n", vpnRange.String()))
		}
	}

	// Add TOR exit nodes if blocking enabled
	if settings.BlockTOR && s.GeoIP != nil {
		for _, torIP := range s.GeoIP.GetTORExitNodes() {
			sb.WriteString(fmt.Sprintf("add tor_exits %s\n", torIP.String()))
		}
	}

	// Add manually allowed IP rules (white_list)
	var allowIPs []models.AllowIP
	s.DB.Find(&allowIPs)
	for _, a := range allowIPs {
		sb.WriteString(fmt.Sprintf("add white_list %s\n", a.IP))
	}

	// Add Critical DNS (Always Allowed)
	criticalDNS := []string{
		"108.61.10.10", "9.9.9.9", "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1",
	}
	for _, dns := range criticalDNS {
		sb.WriteString(fmt.Sprintf("add white_list %s\n", dns))
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

	// Detect primary interface
	sysInfo := NewSysInfoService()
	eth := sysInfo.GetPrimaryInterface()

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
		// 0. Unconditional Bypass for WireGuard (Internal & External)
		// Allow all traffic from WireGuard interfaces (VPN internal traffic)
		sb.WriteString("-A PREROUTING -i wg+ -j ACCEPT\n")
		// Allow all WireGuard handshake/tunnel packets from Any IP (Public Peers)
		sb.WriteString("-A PREROUTING -p udp --dport 51820 -j ACCEPT\n")

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

		// 1-5a. Block UDP Reflection Attacks
		sb.WriteString("-A PREROUTING -p udp -m multiport --sports 1900,11211 -j DROP\n")

		// 1-5b. Block Bogon IPs (Spoofed IPs from local/reserved ranges) on WAN interface
		sb.WriteString(fmt.Sprintf("-A PREROUTING -i %s -s 127.0.0.0/8 -j DROP\n", eth))
		sb.WriteString(fmt.Sprintf("-A PREROUTING -i %s -s 169.254.0.0/16 -j DROP\n", eth))
		sb.WriteString(fmt.Sprintf("-A PREROUTING -i %s -s 224.0.0.0/4 -j DROP\n", eth))

		// 1-5g. Block Database Ports (No reason for external access)
		sb.WriteString("-A PREROUTING -p tcp -m multiport --dports 1433,1521,3306,5432 -j DROP\n")
		sb.WriteString("-A PREROUTING -p udp -m multiport --dports 1433,1521,3306,5432 -j DROP\n")

		// 1-5c. Limit ICMP (Ping) to prevent flood
		sb.WriteString("-A PREROUTING -p icmp --icmp-type echo-request -m limit --limit 2/second -j ACCEPT\n")
		sb.WriteString("-A PREROUTING -p icmp --icmp-type echo-request -j DROP\n")

		// 1-5d. Block empty UDP packets (Length check)
		sb.WriteString("-A PREROUTING -p udp -m length --length 0:28 -j DROP\n")

		// 1-5e. TCP RST Flood Protection
		sb.WriteString("-A PREROUTING -p tcp --tcp-flags RST RST -m limit --limit 2/second --limit-burst 2 -j ACCEPT\n")
		sb.WriteString("-A PREROUTING -p tcp --tcp-flags RST RST -j DROP\n")

		// 1-5f. Block SYN-ACK Flood
		sb.WriteString("-A PREROUTING -p tcp --tcp-flags SYN,ACK SYN,ACK -m conntrack --ctstate NEW -j DROP\n")

		// 1-5h. UDP Flood Protection (Per-IP Rate Limit)
		sb.WriteString("-A PREROUTING -p udp -m hashlimit --hashlimit-name udp_flood --hashlimit-mode srcip --hashlimit-upto 90000/sec --hashlimit-burst 180000 -j ACCEPT\n")
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

	// Exempt management ports and WireGuard from GEO_GUARD to prevent lockout and allow VPN entry
	sb.WriteString("-A GEO_GUARD -p tcp -m multiport --dports 22,80,443,8080 -j RETURN\n")
	sb.WriteString("-A GEO_GUARD -p udp --dport 51820 -j RETURN\n")

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
	sb.WriteString("-A GEO_GUARD -m set --match-set vpn_proxy src -j DROP\n")
	sb.WriteString("-A GEO_GUARD -m set --match-set tor_exits src -j DROP\n")
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

	// Dynamic Port Forwarding Rules
	var services []models.Service
	s.DB.Preload("Origin").Preload("Ports").Find(&services)

	for _, svc := range services {
		// Only forward if Origin has WireGuard IP
		if svc.Origin.WgIP == "" {
			continue
		}

		for _, port := range svc.Ports {
			protocol := strings.ToLower(port.Protocol)

			// Logic for Port Ranges
			var dport, toDest string
			if port.PublicPortEnd > port.PublicPort {
				// Range (e.g. 27015:27030)
				dport = fmt.Sprintf("%d:%d", port.PublicPort, port.PublicPortEnd)
				// Target range matches source range if PrivatePortEnd is set,
				// or we map to a starting private port?
				// Usually user wants 27015-27030 -> 27015-27030
				// iptables handles range mapping automatically if size matches.
				toDest = fmt.Sprintf("%s:%d-%d", svc.Origin.WgIP, port.PrivatePort, port.PrivatePortEnd)

				// Fallback if PrivatePortEnd is 0 (should prevent this in validation but handle here safe)
				if port.PrivatePortEnd == 0 {
					// Map range to single port? No, map range to range starting at PrivatePort
					// Calculate end: PrivatePort + (PublicEnd - PublicStart)
					diff := port.PublicPortEnd - port.PublicPort
					toDest = fmt.Sprintf("%s:%d-%d", svc.Origin.WgIP, port.PrivatePort, port.PrivatePort+diff)
				}
			} else {
				// Single Port
				dport = fmt.Sprintf("%d", port.PublicPort)
				toDest = fmt.Sprintf("%s:%d", svc.Origin.WgIP, port.PrivatePort)
			}

			// DNAT Rule
			// -p udp --dport 2302 -j DNAT --to-destination 10.200.0.2:2302
			sb.WriteString(fmt.Sprintf("-A PREROUTING -p %s --dport %s -j DNAT --to-destination %s\n", protocol, dport, toDest))
		}
	}

	// Masquerade for WireGuard outbound
	sb.WriteString(fmt.Sprintf("-A POSTROUTING -s 10.200.0.0/24 -o %s -j MASQUERADE\n", eth))
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

	// 1. SSH Brute-force Protection (Max 10 attempts per 60s)
	sb.WriteString("-A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --set\n")
	sb.WriteString("-A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 10 -j DROP\n")
	sb.WriteString("-A INPUT -p tcp --dport 22 -j ACCEPT\n")

	// 2. Global TCP Connection Limit per IP (Max 200)
	sb.WriteString("-A INPUT -p tcp -m connlimit --connlimit-above 200 --connlimit-mask 32 -j DROP\n")

	// Allow WireGuard (port 51820)
	sb.WriteString("-A INPUT -p udp --dport 51820 -j ACCEPT\n")

	// Allow HTTP/HTTPS for Web GUI
	sb.WriteString("-A INPUT -p tcp --dport 80 -j ACCEPT\n")
	sb.WriteString("-A INPUT -p tcp --dport 443 -j ACCEPT\n")
	sb.WriteString("-A INPUT -p tcp --dport 8080 -j ACCEPT\n")

	// Forwarding rules (Critical for NAT)
	// Allow forwarded traffic that passed Mangle checks
	// Allow NEW connections from wg0 (Origin) to eth0 (Internet) for updates/APIs
	sb.WriteString(fmt.Sprintf("-A FORWARD -i %s -o wg0 -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT\n", eth))
	sb.WriteString(fmt.Sprintf("-A FORWARD -i wg0 -o %s -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT\n", eth))

	sb.WriteString("COMMIT\n")

	return sb.String(), nil
}

func (s *FirewallService) saveRulesToFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0644)
}

// applyMaintenanceMode disables all blocking and allows all traffic
func (s *FirewallService) applyMaintenanceMode() error {
	system.Info("Applying Maintenance Mode - All blocking disabled")

	// Flush all iptables rules
	s.Executor.Execute("iptables", "-F")
	s.Executor.Execute("iptables", "-t", "mangle", "-F")
	s.Executor.Execute("iptables", "-t", "nat", "-F")

	// Set default ACCEPT policies
	s.Executor.Execute("iptables", "-P", "INPUT", "ACCEPT")
	s.Executor.Execute("iptables", "-P", "FORWARD", "ACCEPT")
	s.Executor.Execute("iptables", "-P", "OUTPUT", "ACCEPT")

	// Keep basic NAT for WireGuard forwarding
	eth := system.GetDefaultInterface()
	if eth != "" {
		s.Executor.Execute("iptables", "-t", "nat", "-A", "POSTROUTING", "-o", eth, "-j", "MASQUERADE")
	}

	system.Warn("⚠️ Maintenance Mode: Firewall is DISABLED - All traffic allowed")
	return nil
}
