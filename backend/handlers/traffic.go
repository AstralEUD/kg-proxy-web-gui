package handlers

import (
	"kg-proxy-web-gui/backend/services"
	"net/http"

	"github.com/gofiber/fiber/v2"
)

// GetTrafficData returns eBPF collected traffic data
func (h *Handler) GetTrafficData(c *fiber.Ctx) error {
	if h.EBPF == nil {
		return c.Status(http.StatusServiceUnavailable).JSON(fiber.Map{
			"error": "eBPF service not initialized",
		})
	}

	data := h.EBPF.GetTrafficData()

	// Convert to frontend format
	var trafficList []map[string]interface{}
	for _, entry := range data {
		trafficList = append(trafficList, map[string]interface{}{
			"ip":          entry.SourceIP,
			"countryCode": entry.CountryCode,
			"countryName": getCountryName(entry.CountryCode),
			"pps":         entry.PacketCount,
			"total_bytes": formatBytes(entry.ByteCount),
			"status":      getStatus(entry.Blocked),
			"last_seen":   entry.Timestamp.Format("2006-01-02 15:04:05"),
			"risk_score":  calculateRiskScore(entry),
		})
	}

	return c.JSON(fiber.Map{
		"data":    trafficList,
		"enabled": h.EBPF.IsEnabled(),
		"stats":   h.EBPF.GetStats(),
	})
}

func getCountryName(code string) string {
	countryMap := map[string]string{
		"KR": "South Korea", "US": "United States", "CN": "China", "JP": "Japan",
		"DE": "Germany", "RU": "Russia", "BR": "Brazil", "GB": "United Kingdom",
		"CA": "Canada", "AU": "Australia", "IN": "India", "FR": "France",
	}
	if name, ok := countryMap[code]; ok {
		return name
	}
	return code
}

func getStatus(blocked bool) string {
	if blocked {
		return "blocked"
	}
	return "allowed"
}

func formatBytes(bytes int64) string {
	if bytes < 1024 {
		return "< 1 KB"
	} else if bytes < 1024*1024 {
		return string(rune(bytes/1024)) + " KB"
	} else {
		return string(rune(bytes/(1024*1024))) + " MB"
	}
}

func calculateRiskScore(entry services.TrafficEntry) int {
	score := 0
	if entry.Blocked {
		score += 50
	}
	if entry.PacketCount > 500 {
		score += 30
	}
	if entry.CountryCode == "CN" || entry.CountryCode == "RU" {
		score += 20
	}
	if score > 100 {
		score = 100
	}
	return score
}
