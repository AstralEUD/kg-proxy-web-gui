package handlers

import (
	"fmt"
	"kg-proxy-web-gui/backend/models"
	"kg-proxy-web-gui/backend/services"
	"kg-proxy-web-gui/backend/system"
	"runtime"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
)

// SystemStatus represents the current system state
type SystemStatus struct {
	OS             string            `json:"os"`
	MockMode       bool              `json:"mock_mode"`
	Uptime         string            `json:"uptime"`
	CPUUsage       int               `json:"cpu_usage"`
	MemoryUsage    int               `json:"memory_usage"`
	DiskUsage      int               `json:"disk_usage"`
	Connections    int               `json:"connections"`
	BlockedCount   int               `json:"blocked_count"`
	OriginsCount   int               `json:"origins_count"`
	FirewallRules  []string          `json:"firewall_rules"`
	Events         []SystemEvent     `json:"events"`
	RequiredPorts  []PortRequirement `json:"required_ports"`
	ActiveDefenses []string          `json:"active_defenses"`
}

type SystemEvent struct {
	Time    string `json:"time"`
	Type    string `json:"type"` // info, warning, error, success
	Message string `json:"message"`
}

type PortRequirement struct {
	Port        int    `json:"port"`
	Protocol    string `json:"protocol"`
	Service     string `json:"service"`
	Description string `json:"description"`
}

// Event log storage with mutex for thread safety
var (
	eventLog   []SystemEvent
	eventMutex sync.RWMutex
)

func init() {
	// Start with empty event log - real events will be added as they happen
	eventLog = []SystemEvent{}

	// Add startup event
	AddEvent("success", "KG-Proxy backend started")
}

// AddEvent adds a new event to the log
func AddEvent(eventType, message string) {
	eventMutex.Lock()
	defer eventMutex.Unlock()

	event := SystemEvent{
		Time:    time.Now().Format("15:04:05"),
		Type:    eventType,
		Message: message,
	}
	eventLog = append([]SystemEvent{event}, eventLog...)
	if len(eventLog) > 100 {
		eventLog = eventLog[:100]
	}

	// Also log to file
	switch eventType {
	case "error":
		system.Error(message)
	case "warning":
		system.Warn(message)
	default:
		system.Info(message)
	}
}

// GetEvents returns a copy of the event log
func GetEventLog() []SystemEvent {
	eventMutex.RLock()
	defer eventMutex.RUnlock()

	result := make([]SystemEvent, len(eventLog))
	copy(result, eventLog)
	return result
}

// GetSystemStatus returns current system status
func (h *Handler) GetSystemStatus(c *fiber.Ctx) error {
	// Create sysinfo service for real data
	sysInfo := services.NewSysInfoService()

	// 1. Get Firewall Rules (Real execution)
	// We want to see actual rules. If it fails, we report error in the rules array.
	// 1. Get Firewall Rules (Real execution)
	// We want to see actual rules. If it fails, we report error in the rules array.
	var rules []string

	// Helper to get table output
	getTable := func(table string) string {
		out, err := h.Firewall.Executor.Execute("iptables", "-t", table, "-L", "-n", "--line-numbers")
		if err != nil {
			return fmt.Sprintf("Error fetching %s table: %v", table, err)
		}
		return fmt.Sprintf("=== %s Table ===\n%s", table, out)
	}

	// Fetch all relevant tables
	mangle := getTable("mangle") // DDoS defenses
	nat := getTable("nat")       // Port Forwarding
	filter := getTable("filter") // Traffic Policy

	rules = []string{mangle + "\n\n" + nat + "\n\n" + filter}

	// Calculate required ports based on services
	var services []models.Service
	h.DB.Preload("Ports").Find(&services)

	requiredPorts := []PortRequirement{
		{Port: 22, Protocol: "TCP", Service: "SSH", Description: "Remote Management"},
		{Port: 80, Protocol: "TCP", Service: "HTTP", Description: "Web Redirect"},
		{Port: 443, Protocol: "TCP", Service: "HTTPS", Description: "Web GUI (Secure)"},
		{Port: 8080, Protocol: "TCP", Service: "HTTP", Description: "Web GUI (Alternative)"},
		{Port: 51820, Protocol: "UDP", Service: "WireGuard", Description: "VPN Tunnel"},
	}

	for _, svc := range services {
		for _, port := range svc.Ports {
			requiredPorts = append(requiredPorts, PortRequirement{
				Port:        port.PublicPort,
				Protocol:    port.Protocol,
				Service:     svc.Name,
				Description: fmt.Sprintf("%s (%s -> %d)", port.Name, port.Protocol, port.PrivatePort),
			})
		}
	}

	// Count origins and blocked IPs from DB
	var originsCount int64
	h.DB.Table("origins").Count(&originsCount)

	var blockedCount int64
	h.DB.Table("ban_ips").Count(&blockedCount)

	// Build status with real data
	status := SystemStatus{
		OS:            runtime.GOOS,
		MockMode:      false, // Always false now
		Uptime:        sysInfo.GetUptime(),
		CPUUsage:      sysInfo.GetCPUUsage(),
		MemoryUsage:   sysInfo.GetMemoryUsage(),
		DiskUsage:     sysInfo.GetDiskUsage(),
		Connections:   sysInfo.GetActiveConnections(),
		BlockedCount:  int(blockedCount),
		OriginsCount:  int(originsCount),
		FirewallRules: rules,
		Events:        GetEventLog(),
		RequiredPorts: requiredPorts,
		ActiveDefenses: func() []string {
			var defs []string
			var settings models.SecuritySettings
			if err := h.DB.First(&settings, 1).Error; err == nil {
				if settings.GlobalProtection {
					defs = append(defs, "Invalid Packet Drop")
					defs = append(defs, "TCP Flag Validation")
					defs = append(defs, "Bogon Filtering")
					defs = append(defs, "ICMP Rate Limiting")
				}
				if settings.SYNCookies {
					defs = append(defs, "SYN Flood Protection (Cookies)")
				}
				if settings.BlockVPN {
					defs = append(defs, "VPN/Proxy Blocking")
				}
				if settings.BlockTOR {
					defs = append(defs, "TOR Exit Node Blocking")
				}
				// Added new defenses
				if settings.GlobalProtection {
					defs = append(defs, "UDP/ICMP Rate Limiting (Per-IP)")
				}
				if lvl := settings.ProtectionLevel; lvl >= 2 {
					defs = append(defs, "High Sensitivity Flood Detection")
				} else {
					defs = append(defs, "Standard Flood Detection")
				}
			} else {
				// Default assumption if DB read fails (defaults)
				defs = []string{"Invalid Packet Drop", "Bogon Filtering", "Standard Flood Detection"}
			}
			return defs
		}(),
	}

	return c.JSON(status)
}

// GetEvents returns recent events
func (h *Handler) GetEvents(c *fiber.Ctx) error {
	return c.JSON(GetEventLog())
}

// GetFirewallStatus returns current iptables rules
func (h *Handler) GetFirewallStatus(c *fiber.Ctx) error {
	// Real execution - use iptables-save for complete structured dump
	output, err := h.Firewall.Executor.Execute("iptables-save")
	if err != nil {
		// Fallback to separate commands if save fails
		mangle, _ := h.Firewall.Executor.Execute("iptables", "-t", "mangle", "-L", "-n", "-v", "--line-numbers")
		nat, _ := h.Firewall.Executor.Execute("iptables", "-t", "nat", "-L", "-n", "-v", "--line-numbers")
		filter, _ := h.Firewall.Executor.Execute("iptables", "-t", "filter", "-L", "-n", "-v", "--line-numbers")
		output = fmt.Sprintf("=== Mangle Table ===\n%s\n\n=== NAT Table ===\n%s\n\n=== Filter Table ===\n%s", mangle, nat, filter)
	}

	return c.JSON(fiber.Map{
		"mock":  false,
		"rules": output,
	})
}

// GetServerInfo returns server's public IP and other info
func (h *Handler) GetServerInfo(c *fiber.Ctx) error {
	sysInfo := services.NewSysInfoService()
	publicIP := sysInfo.GetPublicIP()
	serverPubKey := h.WG.GetServerPublicKey()

	return c.JSON(fiber.Map{
		"public_ip":            publicIP,
		"wireguard_port":       51820,
		"wireguard_public_key": serverPubKey,
		"wg_subnet":            "10.200.0.0/24",
	})
}
