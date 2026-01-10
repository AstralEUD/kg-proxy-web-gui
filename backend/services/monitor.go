package services

import (
	"fmt"
	"kg-proxy-web-gui/backend/system"
	"time"
)

// SystemMonitor monitors system resources and sends alerts
type SystemMonitor struct {
	webhook       *WebhookService
	sysInfo       *SysInfoService
	stopChan      chan struct{}
	threshold     int           // Percentage (e.g. 80)
	checkInterval time.Duration // Interval to check resources

	// Cooldown tracking
	lastCpuAlert time.Time
	lastRamAlert time.Time
	cooldown     time.Duration
}

// NewSystemMonitor creates a new SystemMonitor
func NewSystemMonitor(webhook *WebhookService) *SystemMonitor {
	return &SystemMonitor{
		webhook:       webhook,
		sysInfo:       NewSysInfoService(),
		stopChan:      make(chan struct{}),
		threshold:     80,               // Default 80%
		checkInterval: 1 * time.Minute,  // Check every minute
		cooldown:      10 * time.Minute, // Alert at most once every 10 mins
	}
}

// Start begins the monitoring loop
func (m *SystemMonitor) Start() {
	go func() {
		system.Info("System Resource Monitor started (Threshold: %d%%)", m.threshold)
		ticker := time.NewTicker(m.checkInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				m.checkResources()
			case <-m.stopChan:
				system.Info("System Resource Monitor stopped")
				return
			}
		}
	}()
}

// Stop stops the monitoring loop
func (m *SystemMonitor) Stop() {
	close(m.stopChan)
}

// checkResources checks CPU and RAM usage
func (m *SystemMonitor) checkResources() {
	if !m.webhook.IsEnabled() {
		return
	}

	// Check CPU
	cpu := m.sysInfo.GetCPUUsage()
	if cpu >= m.threshold {
		if time.Since(m.lastCpuAlert) >= m.cooldown {
			msg := fmt.Sprintf("CPU usage is high: **%d%%** (Threshold: %d%%)", cpu, m.threshold)
			m.webhook.SendSystemAlert("⚠️ High CPU Usage", msg, ColorOrange)
			m.lastCpuAlert = time.Now()
		}
	}

	// Check RAM
	ram := m.sysInfo.GetMemoryUsage()
	if ram >= m.threshold {
		if time.Since(m.lastRamAlert) >= m.cooldown {
			msg := fmt.Sprintf("Memory usage is high: **%d%%** (Threshold: %d%%)", ram, m.threshold)
			m.webhook.SendSystemAlert("⚠️ High Memory Usage", msg, ColorOrange)
			m.lastRamAlert = time.Now()
		}
	}
}
