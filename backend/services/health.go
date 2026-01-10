package services

import (
	"fmt"
	"kg-proxy-web-gui/backend/models"
	"kg-proxy-web-gui/backend/system"
	"net"
	"time"

	"gorm.io/gorm"
)

// HealthMonitor checks the health of origin services
type HealthMonitor struct {
	db      *gorm.DB
	webhook *WebhookService
	status  map[uint]bool // OriginID -> IsUp
}

func NewHealthMonitor(db *gorm.DB, webhook *WebhookService) *HealthMonitor {
	return &HealthMonitor{
		db:      db,
		webhook: webhook,
		status:  make(map[uint]bool),
	}
}

func (h *HealthMonitor) Start() {
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			h.checkCustomOrigins()
		}
	}()
	system.Info("Health Monitor started")
}

func (h *HealthMonitor) checkCustomOrigins() {
	var origins []models.Origin
	if err := h.db.Find(&origins).Error; err != nil {
		return
	}

	for _, origin := range origins {
		// Default to assuming it's up if we haven't checked
		isUp := h.checkPing(origin.WgIP)

		wasUp, exists := h.status[origin.ID]
		if !exists {
			// First check, just set status
			h.status[origin.ID] = isUp
			continue
		}

		if wasUp && !isUp {
			// Went DOWN
			h.sendAlert(origin.Name, origin.WgIP, false)
			h.status[origin.ID] = false
		} else if !wasUp && isUp {
			// Came UP
			h.sendAlert(origin.Name, origin.WgIP, true)
			h.status[origin.ID] = true
		}
	}
}

// checkPing attempts to connect to the WireGuard IP to verify reachability
// Since ICMP requires root/raw socket, we try a TCP connection to common ports or use ping command
func (h *HealthMonitor) checkPing(ip string) bool {
	// Try Ping via system command
	// Adding -w 1 (1 sec timeout) -n 1 (1 count) for Windows, -c 1 for Linux

	// Simple lookup to see if it's reachable?
	// Actually, just try to connect to a port? But we don't know ports.
	// Let's use `fast-ping` logic if possible, or just `net.DialTimeout` to a dummy port if we expect reject?
	// If the host is down, `Dial` times out. If up and port closed, it returns "connection refused" immediately.
	// "Connection refused" means host is UP!

	conn, err := net.DialTimeout("tcp", ip+":80", 2*time.Second)
	if conn != nil {
		conn.Close()
		return true
	}

	// If error is "connection refused", it means machine is reachable
	if err != nil {
		// "target machine actively refused it" -> Machine is UP
		// "i/o timeout" -> Machine is likely DOWN (or firewall drop)
		// We can parse error string, but slightly fragile.
		// Let's try ICMP ping command.
		return system.Ping(ip)
	}
	return true
}

func (h *HealthMonitor) sendAlert(name, ip string, isUp bool) {
	if !h.webhook.IsEnabled() {
		return
	}

	status := "DOWN"
	color := ColorRed
	title := "🚨 Service DOWN"
	if isUp {
		status = "UP"
		color = ColorGreen
		title = "✅ Service RECOVERED"
	}

	msg := fmt.Sprintf("Origin **%s** (%s) is now **%s**.", name, ip, status)
	h.webhook.SendSystemAlert(title, msg, color)
}
