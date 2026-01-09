package handlers

import (
	"kg-proxy-web-gui/backend/models"
	"net/http"
	"time"

	"github.com/gofiber/fiber/v2"
)

// GetTrafficHistory returns historical traffic data for charts
// GET /api/traffic/history?range=1h|6h|24h|7d
func (h *Handler) GetTrafficHistory(c *fiber.Ctx) error {
	rangeParam := c.Query("range", "1h")

	var since time.Time
	now := time.Now()

	switch rangeParam {
	case "1h":
		since = now.Add(-1 * time.Hour)
	case "6h":
		since = now.Add(-6 * time.Hour)
	case "24h":
		since = now.Add(-24 * time.Hour)
	case "7d":
		since = now.Add(-7 * 24 * time.Hour)
	default:
		since = now.Add(-1 * time.Hour)
	}

	var snapshots []models.TrafficSnapshot
	if err := h.DB.Where("timestamp > ?", since).Order("timestamp ASC").Find(&snapshots).Error; err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	return c.JSON(fiber.Map{
		"range":     rangeParam,
		"count":     len(snapshots),
		"snapshots": snapshots,
	})
}

// GetAttackHistory returns attack event history
// GET /api/attacks?page=1&limit=50&type=&country=
func (h *Handler) GetAttackHistory(c *fiber.Ctx) error {
	page := c.QueryInt("page", 1)
	limit := c.QueryInt("limit", 50)
	attackType := c.Query("type", "")
	country := c.Query("country", "")

	if page < 1 {
		page = 1
	}
	if limit > 100 {
		limit = 100
	}

	offset := (page - 1) * limit

	query := h.DB.Model(&models.AttackEvent{})

	if attackType != "" {
		query = query.Where("attack_type = ?", attackType)
	}
	if country != "" {
		query = query.Where("country_code = ?", country)
	}

	var total int64
	query.Count(&total)

	var events []models.AttackEvent
	if err := query.Order("timestamp DESC").Offset(offset).Limit(limit).Find(&events).Error; err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	return c.JSON(fiber.Map{
		"page":   page,
		"limit":  limit,
		"total":  total,
		"events": events,
	})
}

// GetAttackStats returns aggregated attack statistics
// GET /api/attacks/stats
func (h *Handler) GetAttackStats(c *fiber.Ctx) error {
	now := time.Now()
	todayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	weekStart := todayStart.AddDate(0, 0, -7)
	monthStart := todayStart.AddDate(0, -1, 0)

	var todayCount, weekCount, monthCount int64

	h.DB.Model(&models.AttackEvent{}).Where("timestamp >= ?", todayStart).Count(&todayCount)
	h.DB.Model(&models.AttackEvent{}).Where("timestamp >= ?", weekStart).Count(&weekCount)
	h.DB.Model(&models.AttackEvent{}).Where("timestamp >= ?", monthStart).Count(&monthCount)

	// Get top attack type
	var topAttackType struct {
		AttackType string
		Count      int64
	}
	h.DB.Model(&models.AttackEvent{}).
		Select("attack_type, COUNT(*) as count").
		Where("timestamp >= ?", weekStart).
		Group("attack_type").
		Order("count DESC").
		Limit(1).
		Scan(&topAttackType)

	// Get top country
	var topCountry struct {
		CountryCode string
		Count       int64
	}
	h.DB.Model(&models.AttackEvent{}).
		Select("country_code, COUNT(*) as count").
		Where("timestamp >= ?", weekStart).
		Group("country_code").
		Order("count DESC").
		Limit(1).
		Scan(&topCountry)

	// Get top attacker IP
	var topAttacker struct {
		SourceIP string
		Count    int64
	}
	h.DB.Model(&models.AttackEvent{}).
		Select("source_ip, COUNT(*) as count").
		Where("timestamp >= ?", weekStart).
		Group("source_ip").
		Order("count DESC").
		Limit(1).
		Scan(&topAttacker)

	// Total blocked count
	var totalBlocked int64
	h.DB.Model(&models.AttackEvent{}).Where("action = ?", "blocked").Count(&totalBlocked)

	stats := models.AttackStats{
		TodayCount:    todayCount,
		WeekCount:     weekCount,
		MonthCount:    monthCount,
		TopAttackType: topAttackType.AttackType,
		TopCountry:    topCountry.CountryCode,
		TopAttackerIP: topAttacker.SourceIP,
		TotalBlocked:  totalBlocked,
	}

	return c.JSON(stats)
}
