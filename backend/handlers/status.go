package handlers

import (
	"fmt"
	"runtime"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/mem"

	"github.com/gofiber/fiber/v2"
)

// SystemStatus represents the current system state
type SystemStatus struct {
	OS            string            `json:"os"`
	MockMode      bool              `json:"mock_mode"`
	Uptime        string            `json:"uptime"`
	CPUUsage      int               `json:"cpu_usage"`
	MemoryUsage   int               `json:"memory_usage"`
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

// Mock event log storage
var eventLog []SystemEvent

func init() {
	eventLog = []SystemEvent{
		{Time: time.Now().Add(-5 * time.Minute).Format("15:04:05"), Type: "success", Message: "Origin-001 connected successfully"},
		{Time: time.Now().Add(-3 * time.Minute).Format("15:04:05"), Type: "error", Message: "Blocked SYN flood from 45.33.32.156"},
		{Time: time.Now().Add(-2 * time.Minute).Format("15:04:05"), Type: "info", Message: "GeoIP database updated"},
		{Time: time.Now().Add(-1 * time.Minute).Format("15:04:05"), Type: "warning", Message: "High traffic detected on port 20001"},
	}
}

// AddEvent adds a new event to the log
func AddEvent(eventType, message string) {
	event := SystemEvent{
		Time:    time.Now().Format("15:04:05"),
		Type:    eventType,
		Message: message,
	}
	eventLog = append([]SystemEvent{event}, eventLog...)
	if len(eventLog) > 100 {
		eventLog = eventLog[:100]
	}
}

// GetSystemStatus returns current system status
func (h *Handler) GetSystemStatus(c *fiber.Ctx) error {
	isMock := runtime.GOOS == "windows"

	// Get Real Stats
	var cpuUsage float64
	var memUsage, connections int
	var uptimeStr string

	if isMock {
		cpuUsage = 45.0
		memUsage = 62
		connections = 1245
		uptimeStr = "2d 5h 32m"
	} else {
		// CPU
		percentages, err := cpu.Percent(0, false)
		if err == nil && len(percentages) > 0 {
			cpuUsage = percentages[0]
		}
		// Memory
		v, err := mem.VirtualMemory()
		if err == nil {
			memUsage = int(v.UsedPercent)
		}
		// Uptime
		bootTime, err := host.BootTime()
		if err == nil {
			uptime := time.Since(time.Unix(int64(bootTime), 0))
			uptimeStr = formatDuration(uptime)
		}
		// WireGuard / Connections using service
		wgPeers, _, _, wgErr := h.WG.GetPeerStats()
		if wgErr == nil {
			connections = wgPeers
		} else {
			// On error (e.g. wg not installed or perm error), just show 0 or log
			// connections = 0 // default
		}
	}

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
			rules = []string{"Error fetching rules: " + err.Error()}
		}
	}

	// Calculate required ports based on services
	var services []struct {
		GamePort    int
		BrowserPort int
		QueryPort   int
	}
	h.DB.Table("services").Select("game_port, browser_port, query_port").Find(&services)

	requiredPorts := []PortRequirement{
		{Port: 51820, Protocol: "UDP", Service: "WireGuard", Description: "VPN Tunnel"},
	}

	for _, svc := range services {
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

	status := SystemStatus{
		OS:            runtime.GOOS,
		MockMode:      isMock,
		Uptime:        uptimeStr,
		CPUUsage:      int(cpuUsage),
		MemoryUsage:   memUsage,
		Connections:   connections,
		FirewallRules: rules,
		Events:        eventLog,
		RequiredPorts: requiredPorts,
	}

	return c.JSON(status)
}

func formatDuration(d time.Duration) string {
	d = d.Round(time.Minute)
	h := d / time.Hour
	d -= h * time.Hour
	m := d / time.Minute
	return fmt.Sprintf("%dh %dm", h, m)
}

// GetEvents returns recent events
func (h *Handler) GetEvents(c *fiber.Ctx) error {
	return c.JSON(eventLog)
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
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}

	return c.JSON(fiber.Map{
		"mock":  false,
		"rules": output,
	})
}
