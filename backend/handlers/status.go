package handlers

import (
	"fmt"
	"kg-proxy-web-gui/backend/services"
	"kg-proxy-web-gui/backend/system"
	"runtime"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
)

// SystemStatus represents the current system state
type SystemStatus struct {
	OS            string            `json:"os"`
	MockMode      bool              `json:"mock_mode"`
	Uptime        string            `json:"uptime"`
	CPUUsage      int               `json:"cpu_usage"`
	MemoryUsage   int               `json:"memory_usage"`
	DiskUsage     int               `json:"disk_usage"`
	Connections   int               `json:"connections"`
	BlockedCount  int               `json:"blocked_count"`
	OriginsCount  int               `json:"origins_count"`
	FirewallRules []string          `json:"firewall_rules"`
	Events        []SystemEvent     `json:"events"`
	RequiredPorts []PortRequirement `json:"required_ports"`
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
	var rules []string
	output, err := h.Firewall.Executor.Execute("iptables", "-L", "-n", "--line-numbers")
	if err == nil {
		rules = []string{output}
	} else {
		// Just log, don't fail the whole request
		system.Warn("Failed to get iptables rules (is this Linux?): %v", err)
		rules = []string{fmt.Sprintf("Error fetching rules: %v", err)}
	}

	// Calculate required ports based on services
	var dbServices []struct {
		PublicGamePort    int
		PublicBrowserPort int
		PublicA2SPort     int
	}
	h.DB.Table("services").Select("public_game_port, public_browser_port, public_a2s_port").Find(&dbServices)

	requiredPorts := []PortRequirement{
		{Port: 51820, Protocol: "UDP", Service: "WireGuard", Description: "VPN Tunnel"},
	}

	for _, svc := range dbServices {
		if svc.PublicGamePort > 0 {
			requiredPorts = append(requiredPorts, PortRequirement{
				Port: svc.PublicGamePort, Protocol: "UDP", Service: "Game", Description: "Game Traffic",
			})
		}
		if svc.PublicBrowserPort > 0 {
			requiredPorts = append(requiredPorts, PortRequirement{
				Port: svc.PublicBrowserPort, Protocol: "UDP", Service: "Browser", Description: "Server Browser",
			})
		}
		if svc.PublicA2SPort > 0 {
			requiredPorts = append(requiredPorts, PortRequirement{
				Port: svc.PublicA2SPort, Protocol: "UDP", Service: "Query", Description: "Steam Query",
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
	}

	return c.JSON(status)
}

// GetEvents returns recent events
func (h *Handler) GetEvents(c *fiber.Ctx) error {
	return c.JSON(GetEventLog())
}

// GetFirewallStatus returns current iptables rules
func (h *Handler) GetFirewallStatus(c *fiber.Ctx) error {
	// Real execution only
	output, err := h.Firewall.Executor.Execute("iptables", "-L", "-n", "-v", "--line-numbers")
	if err != nil {
		system.Error("Failed to get firewall status: %v", err)
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
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
