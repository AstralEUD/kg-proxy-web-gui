package handlers

import (
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
	isMock := runtime.GOOS == "windows"

	// Create sysinfo service for real data
	sysInfo := services.NewSysInfoService()

	// Get firewall rules (mock or real)
	var rules []string
	if isMock {
		rules = []string{
			"-A INPUT -p tcp --dport 51820 -j ACCEPT",
			"-A INPUT -i wg0 -j ACCEPT",
			"-A FORWARD -i wg0 -o eth0 -j ACCEPT",
			"-A INPUT -m conntrack --ctstate INVALID -j DROP",
		}
	} else {
		// Real mode: execute iptables -L -n
		output, err := h.Firewall.Executor.Execute("iptables", "-L", "-n", "--line-numbers")
		if err == nil {
			rules = []string{output}
		} else {
			system.Error("Failed to get iptables rules: %v", err)
			rules = []string{"Error fetching rules"}
		}
	}

	// Calculate required ports based on services
	var dbServices []struct {
		GamePort    int
		BrowserPort int
		QueryPort   int
	}
	h.DB.Table("services").Select("game_port, browser_port, query_port").Find(&dbServices)

	requiredPorts := []PortRequirement{
		{Port: 51820, Protocol: "UDP", Service: "WireGuard", Description: "VPN Tunnel"},
	}

	for _, svc := range dbServices {
		if svc.GamePort > 0 {
			requiredPorts = append(requiredPorts, PortRequirement{
				Port: svc.GamePort, Protocol: "UDP", Service: "Game", Description: "Game Traffic",
			})
		}
		if svc.BrowserPort > 0 {
			requiredPorts = append(requiredPorts, PortRequirement{
				Port: svc.BrowserPort, Protocol: "UDP", Service: "Browser", Description: "Server Browser",
			})
		}
		if svc.QueryPort > 0 {
			requiredPorts = append(requiredPorts, PortRequirement{
				Port: svc.QueryPort, Protocol: "UDP", Service: "Query", Description: "Steam Query",
			})
		}
	}

	// Build status with real data
	status := SystemStatus{
		OS:            runtime.GOOS,
		MockMode:      isMock,
		Uptime:        sysInfo.GetUptime(),
		CPUUsage:      sysInfo.GetCPUUsage(),
		MemoryUsage:   sysInfo.GetMemoryUsage(),
		DiskUsage:     sysInfo.GetDiskUsage(),
		Connections:   sysInfo.GetActiveConnections(),
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
	isMock := runtime.GOOS == "windows"

	if isMock {
		// Return mock rules
		mockRules := `Chain INPUT (policy DROP)
num  target     prot opt source               destination
1    ACCEPT     all  --  0.0.0.0/0            0.0.0.0/0            state RELATED,ESTABLISHED
2    ACCEPT     udp  --  0.0.0.0/0            0.0.0.0/0            udp dpt:51820
3    ACCEPT     all  --  0.0.0.0/0            0.0.0.0/0            /* wg0 */
4    DROP       all  --  0.0.0.0/0            0.0.0.0/0            ctstate INVALID

Chain FORWARD (policy DROP)
num  target     prot opt source               destination
1    ACCEPT     all  --  10.200.0.0/24        0.0.0.0/0
2    ACCEPT     all  --  0.0.0.0/0            10.200.0.0/24        state RELATED,ESTABLISHED

Chain OUTPUT (policy ACCEPT)`
		return c.JSON(fiber.Map{
			"mock":  true,
			"rules": mockRules,
		})
	}

	// Real execution
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
