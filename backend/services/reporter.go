package services

import (
	"fmt"
	"kg-proxy-web-gui/backend/models"
	"kg-proxy-web-gui/backend/system"
	"time"

	"gorm.io/gorm"
)

// DailyReporter generates and sends daily traffic reports
type DailyReporter struct {
	db      *gorm.DB
	webhook *WebhookService
}

func NewDailyReporter(db *gorm.DB, webhook *WebhookService) *DailyReporter {
	return &DailyReporter{
		db:      db,
		webhook: webhook,
	}
}

// Start schedules the daily report at 00:00 KST
func (r *DailyReporter) Start() {
	go func() {
		for {
			now := time.Now()
			// Calculate next midnight
			next := time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 0, 0, now.Location())
			duration := next.Sub(now)

			system.Info("Next daily report scheduled in %v", duration)
			time.Sleep(duration)

			r.SendReport()

			// Sleep a bit to avoid double firing if execution is fast
			time.Sleep(60 * time.Second)
		}
	}()
}

// SendReport generates and sends the report
func (r *DailyReporter) SendReport() {
	if !r.webhook.IsEnabled() {
		return
	}

	system.Info("Generating daily traffic report...")
	now := time.Now()
	yesterday := now.Add(-24 * time.Hour)

	// 1. Traffic Stats (Bytes, Peak PPS)
	var stats struct {
		TotalBytes int64
		MaxPPS     int64
	}
	// We sum TotalBPS * 60 (approx bytes per minute) ? No, TotalBPS is rate.
	// TrafficSnapshot is every minute.
	// Total bytes approx = sum(TotalBPS * 60)

	// Simply sum bytes from snapshots if available?
	// Note: TrafficSnapshot has TotalBPS (int64).
	// Let's approximate.

	// Actually, we can get better stats from AttackEvent for blocks.
	// For general traffic, we use snapshots.

	r.db.Model(&models.TrafficSnapshot{}).
		Where("timestamp >= ?", yesterday).
		Select("SUM(total_bps * 60) as total_bytes, MAX(total_pps) as max_pps").
		Scan(&stats)

	// 2. Attack Stats
	var attackStats struct {
		Count        int64
		BlockedCount int64
		TopCountry   string
	}
	r.db.Model(&models.AttackEvent{}).Where("timestamp >= ?", yesterday).Count(&attackStats.Count)
	r.db.Model(&models.AttackEvent{}).Where("timestamp >= ? AND action = ?", yesterday, "blocked").Count(&attackStats.BlockedCount)

	// Top country
	var topCountry struct {
		CountryCode string
		Count       int64
	}
	r.db.Model(&models.AttackEvent{}).
		Select("country_code, COUNT(*) as count").
		Where("timestamp >= ?", yesterday).
		Group("country_code").
		Order("count DESC").
		Limit(1).
		Scan(&topCountry)
	attackStats.TopCountry = topCountry.CountryCode
	if attackStats.TopCountry == "" {
		attackStats.TopCountry = "None"
	}

	// 3. Construct Message
	title := fmt.Sprintf("📊 Daily Traffic Report (%s)", yesterday.Format("2006-01-02"))

	desc := fmt.Sprintf("**Traffic Summary**\n"+
		"• Total Traffic: `%s`\n"+
		"• Peak Traffic: `%d PPS`\n\n"+
		"**Security Summary**\n"+
		"• Total Attacks: `%d`\n"+
		"• Blocked Attacks: `%d`\n"+
		"• Top Attacker Country: `%s`",
		formatBytes(stats.TotalBytes), stats.MaxPPS,
		attackStats.Count, attackStats.BlockedCount, attackStats.TopCountry)

	r.webhook.SendSystemAlert(title, desc, ColorBlue)
}

func formatBytes(bytes int64) string {
	if bytes < 1024 {
		return fmt.Sprintf("%d B", bytes)
	} else if bytes < 1024*1024 {
		return fmt.Sprintf("%.2f KB", float64(bytes)/1024.0)
	} else if bytes < 1024*1024*1024 {
		return fmt.Sprintf("%.2f MB", float64(bytes)/(1024.0*1024.0))
	} else {
		return fmt.Sprintf("%.2f GB", float64(bytes)/(1024.0*1024.0*1024.0))
	}
}
