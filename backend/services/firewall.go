package services

import (
	"fmt"
	"strings"
	"kg-proxy-web-gui/backend/models"
	"kg-proxy-web-gui/backend/system"
	"gorm.io/gorm"
)

type FirewallService struct {
	DB       *gorm.DB
	Executor system.CommandExecutor
}

func NewFirewallService(db *gorm.DB, exec system.CommandExecutor) *FirewallService {
	return &FirewallService{DB: db, Executor: exec}
}

func (s *FirewallService) ApplyRules() error {
	// 1. Generate ipset.rules
	ipsetRules, err := s.generateIPSetRules()
	if err != nil {
		return err
	}

	// 2. Generate iptables.rules.v4
	iptablesRules, err := s.generateIPTablesRules()
	if err != nil {
		return err
	}

	// 3. Apply via Executor
	// Save to tmp files or pipe? For mock, we just execute "restore" commands.
	
	fmt.Println("Applying IPSet Rules:\n", ipsetRules)
	if _, err := s.Executor.Execute("ipset", "restore", "<", "ipset.rules"); err != nil {
		fmt.Println("Error applying ipset (expected on Windows):", err)
	}

	fmt.Println("Applying IPTables Rules:\n", iptablesRules)
	if _, err := s.Executor.Execute("iptables-restore", "iptables.rules.v4"); err != nil {
		fmt.Println("Error applying iptables (expected on Windows):", err)
	}

	return nil
}

func (s *FirewallService) generateIPSetRules() (string, error) {
	var sb strings.Builder
	sb.WriteString("create geo_kr hash:net family inet -exist\n")
	sb.WriteString("create allow_foreign hash:ip family inet -exist\n")
	sb.WriteString("create ban hash:ip family inet -exist\n")
	sb.WriteString("flush allow_foreign\n")
	sb.WriteString("flush ban\n")

	var allowed []models.AllowForeign
	s.DB.Find(&allowed)
	for _, a := range allowed {
		sb.WriteString(fmt.Sprintf("add allow_foreign %s\n", a.IP))
	}

	var banned []models.BanIP
	s.DB.Find(&banned)
	for _, b := range banned {
		sb.WriteString(fmt.Sprintf("add ban %s\n", b.IP))
	}

	return sb.String(), nil
}

func (s *FirewallService) generateIPTablesRules() (string, error) {
	// This would build the comprehensive iptables file content
	// referencing the services from DB for DNAT rules.
	return "*filter\n...\nCOMMIT\n", nil
}
