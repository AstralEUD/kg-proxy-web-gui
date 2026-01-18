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
		// === SYN Flood Protection & High Throughput ===
		"net.ipv4.ip_forward":          "1", // Enable Forwarding (Critical for VPN/Proxy)
		"net.ipv4.tcp_syncookies":      "1",
		"net.ipv4.tcp_max_syn_backlog": "65535", // Aggressive for 10Gbps
		"net.ipv4.tcp_syn_retries":     "2",
		"net.ipv4.tcp_synack_retries":  "2",
		"net.ipv4.tcp_timestamps":      "1",
		"net.core.somaxconn":           "65535", // Max listener backlog

		// === Read/Write Buffer Tuning (16MB for UDP absorption) ===
		"net.core.rmem_max":   "16777216",
		"net.core.wmem_max":   "16777216",
		"net.core.optmem_max": "65536",
		"net.ipv4.udp_mem":    "3145728 4194304 8388608", // Tuned for 8GB RAM

		// === High Throughput Backlog ===
		"net.core.netdev_max_backlog": "30000", // Handle 10Gbps bursts

		// === Conntrack Optimization (8GB RAM Target) ===
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

		// === UDP Tuning (Aggressive Conntrack Drain) ===
		"net.netfilter.nf_conntrack_udp_timeout":        "10", // Default 30s -> 10s (Clear unreplied quickly)
		"net.netfilter.nf_conntrack_udp_timeout_stream": "60", // Default 120s -> 60s (Clear finished sessions)

		// === Security & Anti-Spoofing ===
		"net.ipv4.conf.all.rp_filter":        "2", // Loose Reverse Path Filtering (Essential for WireGuard/NAT)
		"net.ipv4.conf.default.rp_filter":    "2",
		"net.ipv4.conf.all.log_martians":     "0", // Disable logging to prevent dmesg flood
		"net.ipv4.conf.default.log_martians": "0",

		// === ICMP Flood Protection ===
		"net.ipv4.icmp_echo_ignore_broadcasts":       "1",
		"net.ipv4.icmp_ignore_bogus_error_responses": "1",
	}

	// 2. Tune based on protection level (Refined logic: Always apply base high-performance rules above)
	if level >= 2 {
		// Extra aggressive for High Protection Mode (if needed, but defaults above are already high)
		// We keep this block for future dynamic adjustments
		sysctlRules["net.netfilter.nf_conntrack_max"] = "2000000"
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
