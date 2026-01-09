package services

import (
	"fmt"
	"kg-proxy-web-gui/backend/models"
	"kg-proxy-web-gui/backend/system"
	"sync"
	"time"

	"gorm.io/gorm"
)

// FloodProtection implements rate limiting and DDoS mitigation
type FloodProtection struct {
	level         int // 0=low, 1=standard, 2=high
	ipConnections map[string]*ConnectionTracker
	mu            sync.RWMutex
	cleanupTicker *time.Ticker
	stopChan      chan struct{}

	// Service references for logging and notifications
	db      *gorm.DB
	webhook *WebhookService
	geoip   *GeoIPService
}

type ConnectionTracker struct {
	Count         int
	FirstSeen     time.Time
	LastSeen      time.Time
	PacketsPerSec int
	BytesPerSec   int64
	Violations    int
	Blocked       bool
	BlockedUntil  time.Time
}

func NewFloodProtection(level int) *FloodProtection {
	fp := &FloodProtection{
		level:         level,
		ipConnections: make(map[string]*ConnectionTracker),
		stopChan:      make(chan struct{}),
	}

	// Start cleanup goroutine
	fp.cleanupTicker = time.NewTicker(1 * time.Minute)
	go fp.cleanupRoutine()

	return fp
}

// SetServices connects external services for logging and notifications
func (fp *FloodProtection) SetServices(db *gorm.DB, webhook *WebhookService, geoip *GeoIPService) {
	fp.mu.Lock()
	defer fp.mu.Unlock()
	fp.db = db
	fp.webhook = webhook
	fp.geoip = geoip
}

// CheckIP returns true if IP should be blocked
func (fp *FloodProtection) CheckIP(ip string, packetCount int, byteCount int64) bool {
	fp.mu.Lock()
	defer fp.mu.Unlock()

	tracker, exists := fp.ipConnections[ip]
	if !exists {
		tracker = &ConnectionTracker{
			Count:     1,
			FirstSeen: time.Now(),
			LastSeen:  time.Now(),
		}
		fp.ipConnections[ip] = tracker
		return false
	}

	// Check if currently blocked
	if tracker.Blocked && time.Now().Before(tracker.BlockedUntil) {
		return true
	}

	// Update tracker
	tracker.Count++
	tracker.LastSeen = time.Now()
	tracker.PacketsPerSec = packetCount
	tracker.BytesPerSec = byteCount

	// Get thresholds based on protection level
	thresholds := fp.getThresholds()

	// Check connection rate
	duration := time.Since(tracker.FirstSeen).Seconds()
	if duration > 0 {
		connRate := float64(tracker.Count) / duration

		if connRate > thresholds.MaxConnPerSec {
			tracker.Violations++

			if tracker.Violations >= thresholds.MaxViolations {
				tracker.Blocked = true
				tracker.BlockedUntil = time.Now().Add(thresholds.BlockDuration)
				go fp.recordAttack(ip, "Connection Flood", int64(tracker.PacketsPerSec))
				return true
			}
		}
	}

	// Check packet rate
	if tracker.PacketsPerSec > thresholds.MaxPacketsPerSec {
		tracker.Violations++

		if tracker.Violations >= thresholds.MaxViolations {
			tracker.Blocked = true
			tracker.BlockedUntil = time.Now().Add(thresholds.BlockDuration)
			go fp.recordAttack(ip, "PPS Flood", int64(tracker.PacketsPerSec))
			return true
		}
	}

	// Check bandwidth
	if tracker.BytesPerSec > thresholds.MaxBytesPerSec {
		tracker.Violations++

		if tracker.Violations >= thresholds.MaxViolations {
			tracker.Blocked = true
			tracker.BlockedUntil = time.Now().Add(thresholds.BlockDuration)
			go fp.recordAttack(ip, "Bandwidth Flood", int64(tracker.PacketsPerSec))
			return true
		}
	}

	return false
}

type ProtectionThresholds struct {
	MaxConnPerSec    float64
	MaxPacketsPerSec int
	MaxBytesPerSec   int64
	MaxViolations    int
	BlockDuration    time.Duration
}

func (fp *FloodProtection) getThresholds() ProtectionThresholds {
	switch fp.level {
	case 0: // Low
		return ProtectionThresholds{
			MaxConnPerSec:    100,
			MaxPacketsPerSec: 50000,             // Increased for Arma Reforger
			MaxBytesPerSec:   100 * 1024 * 1024, // 100 MB/s
			MaxViolations:    10,
			BlockDuration:    5 * time.Minute,
		}
	case 1: // Standard
		return ProtectionThresholds{
			MaxConnPerSec:    50,
			MaxPacketsPerSec: 30000,            // Increased for Arma Reforger
			MaxBytesPerSec:   50 * 1024 * 1024, // 50 MB/s
			MaxViolations:    5,
			BlockDuration:    10 * time.Minute,
		}
	case 2: // High
		return ProtectionThresholds{
			MaxConnPerSec:    20,
			MaxPacketsPerSec: 20000,            // Increased for Arma Reforger
			MaxBytesPerSec:   20 * 1024 * 1024, // 20 MB/s
			MaxViolations:    3,
			BlockDuration:    30 * time.Minute,
		}
	default:
		return fp.getThresholds() // Default to standard
	}
}

// SetLevel updates protection level
func (fp *FloodProtection) SetLevel(level int) {
	fp.mu.Lock()
	defer fp.mu.Unlock()
	fp.level = level
}

// GetBlockedIPs returns list of currently blocked IPs
func (fp *FloodProtection) GetBlockedIPs() []string {
	fp.mu.RLock()
	defer fp.mu.RUnlock()

	blocked := make([]string, 0)
	now := time.Now()

	for ip, tracker := range fp.ipConnections {
		if tracker.Blocked && now.Before(tracker.BlockedUntil) {
			blocked = append(blocked, ip)
		}
	}

	return blocked
}

// UnblockIP manually unblocks an IP
func (fp *FloodProtection) UnblockIP(ip string) {
	fp.mu.Lock()
	defer fp.mu.Unlock()

	if tracker, exists := fp.ipConnections[ip]; exists {
		tracker.Blocked = false
		tracker.Violations = 0
	}
}

// recordAttack logs attack event to DB and sends webhook alert
// This should be called as a goroutine to avoid blocking the main packet processing path
func (fp *FloodProtection) recordAttack(ip string, attackType string, pps int64) {
	// 1. Resolve Country
	countryName := "Unknown"
	countryCode := "XX"
	if fp.geoip != nil {
		countryName, countryCode = fp.geoip.GetCountry(ip)
	}

	// 2. Log to Database
	if fp.db != nil {
		event := models.AttackEvent{
			Timestamp:   time.Now(),
			SourceIP:    ip,
			CountryCode: countryCode,
			CountryName: countryName,
			AttackType:  attackType,
			PPS:         pps,
			Action:      "blocked",
		}

		// Use a new goroutine for DB write to be extra safe against locking, though db calls are usually thread-safe
		if err := fp.db.Create(&event).Error; err != nil {
			system.Warn("Failed to log attack event: %v", err)
		}
	} else {
		system.Warn("Attack detected but DB not connected: %s (%s)", ip, attackType)
	}

	// 3. Send Webhook Alert
	if fp.webhook != nil {
		// Use default alert settings (true/true) or read from config if we had access to settings here
		// For now, we assume if webhook is set, we want alerts
		fp.webhook.SendAttackAlert(ip, countryName, attackType, pps, "Blocked via Flood Protection")
	}
}

// GetStats returns current statistics
func (fp *FloodProtection) GetStats() map[string]interface{} {
	fp.mu.RLock()
	defer fp.mu.RUnlock()

	totalIPs := len(fp.ipConnections)
	blockedCount := 0
	now := time.Now()

	for _, tracker := range fp.ipConnections {
		if tracker.Blocked && now.Before(tracker.BlockedUntil) {
			blockedCount++
		}
	}

	return map[string]interface{}{
		"total_tracked_ips": totalIPs,
		"blocked_ips":       blockedCount,
		"protection_level":  fp.level,
	}
}

// cleanupRoutine removes old entries
func (fp *FloodProtection) cleanupRoutine() {
	for {
		select {
		case <-fp.stopChan:
			return
		case <-fp.cleanupTicker.C:
			fp.cleanup()
		}
	}
}

func (fp *FloodProtection) cleanup() {
	fp.mu.Lock()
	defer fp.mu.Unlock()

	now := time.Now()
	for ip, tracker := range fp.ipConnections {
		// Remove entries older than 1 hour that are not blocked
		if !tracker.Blocked && now.Sub(tracker.LastSeen) > 1*time.Hour {
			delete(fp.ipConnections, ip)
		}
		// Remove expired blocks
		if tracker.Blocked && now.After(tracker.BlockedUntil) {
			tracker.Blocked = false
			tracker.Violations = 0
		}
	}
}

// Stop stops the flood protection service
func (fp *FloodProtection) Stop() {
	close(fp.stopChan)
	fp.cleanupTicker.Stop()
}

// SYN Flood Protection using SYN cookies
func (fp *FloodProtection) EnableSYNCookies() error {
	// On Linux, enable SYN cookies via sysctl
	cmd := fmt.Sprintf("sysctl -w net.ipv4.tcp_syncookies=1")
	// Execute command (implementation depends on executor)
	fmt.Println("Enabling SYN cookies:", cmd)
	return nil
}

// Connection tracking limits
func (fp *FloodProtection) SetConntrackLimits() error {
	// Increase conntrack table size for high traffic
	commands := []string{
		"sysctl -w net.netfilter.nf_conntrack_max=1000000",
		"sysctl -w net.netfilter.nf_conntrack_tcp_timeout_established=600",
		"sysctl -w net.netfilter.nf_conntrack_tcp_timeout_time_wait=30",
	}

	for _, cmd := range commands {
		fmt.Println("Setting conntrack limit:", cmd)
	}

	return nil
}
