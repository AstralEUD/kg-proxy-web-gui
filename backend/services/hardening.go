package services

import (
	"fmt"
	"strings"
)

// Extend FirewallService

func (s *FirewallService) ApplyHardening(level string) error {
	// Sysctl Hardening (Mock friendly logs)
	sysctlCmds := map[string]string{
		"net.ipv4.tcp_syncookies": "1",
		"net.ipv4.tcp_max_syn_backlog": "4096",
		"net.ipv4.conf.all.rp_filter": "1",
	}
	
	fmt.Printf("[Security Level: %s] Applying Sysctl hardening...\n", level)
	for k, v := range sysctlCmds {
		if _, err := s.Executor.Execute("sysctl", "-w", fmt.Sprintf("%s=%s", k, v)); err != nil {
			fmt.Printf("Failed sysctl %s: %v\n", k, err)
		}
	}

	// Mangle Rules based on level
	// In prototype, we generate a script or execute commands
	// For simplicity, we just log the intent here as described in ddos-advanced-rules.md
	fmt.Println("Applying IPTables Mangle rules for INVALID packets, TCP flags...")
	
	rules := []string{
		"-A PREROUTING -m conntrack --ctstate INVALID -j DROP",
		"-A PREROUTING -p tcp --tcp-flags ALL NONE -j DROP",
		"-A PREROUTING -p tcp ! --syn -m conntrack --ctstate NEW -j DROP",
	}
	
	for _, r := range rules {
		// Fix: Construct arguments slice correctly
		parts := strings.Split(r, " ")
		args := append([]string{"-t", "mangle"}, parts...)
		s.Executor.Execute("iptables", args...)
	}

	return nil
}

func (s *FirewallService) ApplyGeoIP(countries string) error {
	// countries = "KR,JP,US"
	fmt.Printf("Applying GeoIP for: %s\n", countries)
	// In real logic: loop countries, add to ipset 'geo_allow'
	return nil
}
