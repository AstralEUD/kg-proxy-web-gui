package services

import (
	"fmt"
	"kg-proxy-web-gui/backend/system"
)

// ApplyHardening applies kernel-level tuning for DDoS protection
// Reference: ddos-advanced-rules.md
func (s *FirewallService) ApplyHardening(level int) error {
	system.Info("Applying kernel hardening (Sysctl)...")

	// 1. Define Sysctl Rules based on documentation
	sysctlRules := map[string]string{
		// === SYN Flood Protection ===
		"net.ipv4.tcp_syncookies":      "1",
		"net.ipv4.tcp_max_syn_backlog": "4096",
		"net.ipv4.tcp_syn_retries":     "2",
		"net.ipv4.tcp_synack_retries":  "2",
		"net.ipv4.tcp_timestamps":      "1",

		// === Conntrack Optimization ===
		"net.netfilter.nf_conntrack_max":                     "2000000",
		"net.netfilter.nf_conntrack_tcp_timeout_established": "600",
		"net.netfilter.nf_conntrack_tcp_timeout_time_wait":   "60",
		"net.netfilter.nf_conntrack_tcp_timeout_close_wait":  "60",
		"net.netfilter.nf_conntrack_tcp_timeout_fin_wait":    "60",

		// === TCP Tuning ===
		"net.ipv4.tcp_window_scaling":   "1",
		"net.ipv4.tcp_sack":             "0", // Disable SACK to prevent SACK panic attacks
		"net.ipv4.tcp_fin_timeout":      "30",
		"net.ipv4.tcp_keepalive_time":   "600",
		"net.ipv4.tcp_keepalive_probes": "3",
		"net.ipv4.tcp_keepalive_intvl":  "15",

		// === Security & Anti-Spoofing ===
		"net.ipv4.conf.all.rp_filter":        "1", // Reverse Path Filtering
		"net.ipv4.conf.default.rp_filter":    "1",
		"net.ipv4.conf.all.log_martians":     "1",
		"net.ipv4.conf.default.log_martians": "1",

		// === ICMP Flood Protection ===
		"net.ipv4.icmp_echo_ignore_broadcasts":       "1",
		"net.ipv4.icmp_ignore_bogus_error_responses": "1",
	}

	// 2. Tune based on protection level
	if level >= 2 { // High protection
		sysctlRules["net.ipv4.tcp_max_syn_backlog"] = "8192"
		sysctlRules["net.netfilter.nf_conntrack_max"] = "3000000"
	}

	// 3. Apply Rules
	for k, v := range sysctlRules {
		// Ignore errors as some keys might not exist on all systems (e.g. non-Linux, or container)
		if _, err := s.Executor.Execute("sysctl", "-w", fmt.Sprintf("%s=%s", k, v)); err != nil {
			system.Debug("Failed to set sysctl %s: %v", k, err)
		}
	}

	system.Info("Kernel hardening applied successfully")
	return nil
}
