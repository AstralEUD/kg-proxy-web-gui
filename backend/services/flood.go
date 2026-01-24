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

	// Optimization: Buffered channel for attack events to prevent goroutine explosion
	attackQueue chan models.AttackEvent
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
		attackQueue:   make(chan models.AttackEvent, 1000), // Buffer 1000 events
	}

	// Start cleanup goroutine
	fp.cleanupTicker = time.NewTicker(1 * time.Minute)
	go fp.cleanupRoutine()

	// Start attack event worker
	go fp.processAttackQueue()

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
				fp.recordAttack(ip, "Connection Flood", int64(tracker.PacketsPerSec))
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
			fp.recordAttack(ip, "PPS Flood", int64(tracker.PacketsPerSec))
			return true
		}
	}

	// Check bandwidth
	if tracker.BytesPerSec > thresholds.MaxBytesPerSec {
		tracker.Violations++

		if tracker.Violations >= thresholds.MaxViolations {
			tracker.Blocked = true
			tracker.BlockedUntil = time.Now().Add(thresholds.BlockDuration)
			fp.recordAttack(ip, "Bandwidth Flood", int64(tracker.PacketsPerSec))
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

// recordAttack queues an attack event for processing
// Non-blocking: If queue is full, event is dropped to protect system stability
func (fp *FloodProtection) recordAttack(ip string, attackType string, pps int64) {
	// 1. Resolve Country (Fast enough to do here, or move to worker if needed)
	// Moving to worker is better to avoid holding lock/cpu here,
	// but CheckIP holds lock, so we already have lock contention.
	// Actually CheckIP calls this inside a goroutine in the old code.
	// In new code, we want this to be instant.

	select {
	case fp.attackQueue <- models.AttackEvent{
		Timestamp:  time.Now(),
		SourceIP:   ip,
		AttackType: attackType,
		PPS:        pps,
		Action:     "blocked",
	}:
		// Queued successfully
	default:
		// Queue full - dropping event to save system
		system.Warn("FloodProtection queue full, dropping alert for %s", ip)
	}
}

// processAttackQueue processes events with batching for DB performance
func (fp *FloodProtection) processAttackQueue() {
	// Optimization: Batch DB inserts to reduce IOPS during floods
	batchSize := 100
	batch := make([]models.AttackEvent, 0, batchSize)

	// Flush ticker (500ms) - ensures logs appear quickly even if batch isn't full
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	// Webhook aggregation ticker (10s) - prevents goroutine explosion
	webhookTicker := time.NewTicker(10 * time.Second)
	defer webhookTicker.Stop()
	webhookBuffer := make([]models.AttackEvent, 0, 50)

	flush := func() {
		if len(batch) == 0 {
			return
		}

		// Bulk Insert into DB
		if fp.db != nil {
			// CreateInBatches is more efficient than single inserts
			if err := fp.db.CreateInBatches(batch, batchSize).Error; err != nil {
				system.Warn("Failed to batch insert attack events: %v", err)
			}
		}

		// Reset batch
		batch = make([]models.AttackEvent, 0, batchSize)
	}

	flushWebhook := func() {
		if len(webhookBuffer) == 0 || fp.webhook == nil {
			return
		}

		// Send aggregated alert (single HTTP call)
		count := len(webhookBuffer)
		topIP := webhookBuffer[0].SourceIP
		topCountry := webhookBuffer[0].CountryName
		topType := webhookBuffer[0].AttackType
		var totalPPS int64
		for _, e := range webhookBuffer {
			totalPPS += e.PPS
		}

		// Clear buffer before sending (in case webhook is slow)
		webhookBuffer = make([]models.AttackEvent, 0, 50)

		// Single goroutine for aggregated alert
		go fp.webhook.SendAttackAlert(
			fmt.Sprintf("%s (+%d more)", topIP, count-1),
			topCountry,
			topType,
			totalPPS,
			fmt.Sprintf("Blocked %d attacks in 10s", count),
		)
	}

	for {
		select {
		case <-fp.stopChan:
			flush()
			flushWebhook()
			return

		case event := <-fp.attackQueue:
			// 1. Resolve Country (CPU work done here)
			if fp.geoip != nil {
				countryName, countryCode := fp.geoip.GetCountry(event.SourceIP)
				event.CountryName = countryName
				event.CountryCode = countryCode
			}

			// 2. Add to Webhook Buffer (aggregated, not immediate)
			if len(webhookBuffer) < 50 {
				webhookBuffer = append(webhookBuffer, event)
			}

			// 3. Add to DB Batch
			batch = append(batch, event)
			if len(batch) >= batchSize {
				flush()
			}

		case <-ticker.C:
			flush()

		case <-webhookTicker.C:
			flushWebhook()
		}
	}
}

// handleAttackEvent is deprecated but kept if needed for single calls (refactored into processAttackQueue)
func (fp *FloodProtection) handleAttackEvent(event models.AttackEvent) {
	// Legacy support or fallback
	if fp.geoip != nil {
		event.CountryName, event.CountryCode = fp.geoip.GetCountry(event.SourceIP)
	}
	if fp.db != nil {
		fp.db.Create(&event)
	}
	if fp.webhook != nil {
		fp.webhook.SendAttackAlert(event.SourceIP, event.CountryName, event.AttackType, event.PPS, "Blocked")
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

	// Optimization: Clean old attack logs from DB (Retention: 7 days)
	if fp.db != nil {
		cutoff := now.AddDate(0, 0, -7)
		fp.db.Where("timestamp < ?", cutoff).Delete(&models.AttackEvent{})
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
		"sysctl -w net.netfilter.nf_conntrack_max=2000000",
		"sysctl -w net.netfilter.nf_conntrack_tcp_timeout_established=600",
		"sysctl -w net.netfilter.nf_conntrack_tcp_timeout_time_wait=30",
	}

	for _, cmd := range commands {
		fmt.Println("Setting conntrack limit:", cmd)
	}

	return nil
}
