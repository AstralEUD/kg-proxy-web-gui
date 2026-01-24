package handlers

import (
	"fmt"
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
			"port":        entry.DestPort,
			"countryCode": entry.CountryCode,
			"countryName": getCountryName(entry.CountryCode),
			"pps":         entry.PacketCount,
			"total_bytes": formatBytes(entry.ByteCount),
			"status":      getStatus(entry.Blocked),
			"last_seen":   entry.Timestamp.Format("2006-01-02 15:04:05"),
			"risk_score":  calculateRiskScore(entry),
		})
	}

	// GetStats now returns DetailedTrafficStats struct
	stats := h.EBPF.GetStats()

	// Convert stats to map for JSON response with extra details
	statsMap := fiber.Map{
		"total_pps":        stats.TotalPPS,
		"total_bps":        stats.TotalBPS,
		"allowed_pps":      stats.AllowedPPS,
		"blocked_pps":      stats.BlockedPPS,
		"rate_limited_pps": stats.RateLimitedPPS,
		"invalid_pps":      stats.InvalidPPS,
		"geoip_block_pps":  stats.GeoIPBlockPPS,
		"unique_ips":       stats.UniqueIPs,
		"top_country":      stats.TopCountry,
		"network_rx":       stats.NetworkRX,
		"network_tx":       stats.NetworkTX,
		"cpu_usage":        stats.CPUUsage,
		"memory_usage":     stats.MemoryUsage,
		"timestamp":        stats.Timestamp,
		"total_packets":    stats.TotalPackets,   // For graph (cumulative)
		"blocked_packets":  stats.BlockedPackets, // For graph (cumulative)
	}

	return c.JSON(fiber.Map{
		"data":    trafficList,
		"enabled": h.EBPF.IsEnabled(),
		"stats":   statsMap,
	})
}

// ResetTrafficStats manually resets traffic statistics
func (h *Handler) ResetTrafficStats(c *fiber.Ctx) error {
	if h.EBPF == nil {
		return c.Status(http.StatusServiceUnavailable).JSON(fiber.Map{
			"error": "eBPF service not initialized",
		})
	}

	if err := h.EBPF.ResetTrafficStats(); err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": fmt.Sprintf("Failed to reset stats: %v", err),
		})
	}

	return c.JSON(fiber.Map{
		"message": "Traffic statistics reset successfully",
	})
}

func getCountryName(code string) string {
	// Country names MUST match world-atlas GeoJSON names exactly for map visualization
	// Source: https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json
	countryMap := map[string]string{
		"AF": "Afghanistan", "AL": "Albania", "DZ": "Algeria", "AO": "Angola", "AR": "Argentina",
		"AM": "Armenia", "AU": "Australia", "AT": "Austria", "AZ": "Azerbaijan", "BS": "Bahamas",
		"BD": "Bangladesh", "BY": "Belarus", "BE": "Belgium", "BZ": "Belize", "BJ": "Benin",
		"BT": "Bhutan", "BO": "Bolivia", "BA": "Bosnia and Herz.", "BW": "Botswana", "BR": "Brazil",
		"BN": "Brunei Darussalam", "BG": "Bulgaria", "BF": "Burkina Faso", "BI": "Burundi", "KH": "Cambodia",
		"CM": "Cameroon", "CA": "Canada", "CF": "Central African Rep.", "TD": "Chad", "CL": "Chile",
		"CN": "China", "CO": "Colombia", "CG": "Congo", "CD": "Dem. Rep. Congo", "CR": "Costa Rica",
		"CI": "Côte d'Ivoire", "HR": "Croatia", "CU": "Cuba", "CY": "Cyprus", "CZ": "Czechia",
		"DK": "Denmark", "DJ": "Djibouti", "DO": "Dominican Rep.", "EC": "Ecuador", "EG": "Egypt",
		"SV": "El Salvador", "GQ": "Eq. Guinea", "ER": "Eritrea", "EE": "Estonia", "ET": "Ethiopia",
		"FK": "Falkland Is.", "FJ": "Fiji", "FI": "Finland", "FR": "France", "TF": "Fr. S. Antarctic Lands",
		"GA": "Gabon", "GM": "Gambia", "GE": "Georgia", "DE": "Germany", "GH": "Ghana",
		"GR": "Greece", "GL": "Greenland", "GT": "Guatemala", "GN": "Guinea", "GW": "Guinea-Bissau",
		"GY": "Guyana", "HT": "Haiti", "HN": "Honduras", "HU": "Hungary", "IS": "Iceland",
		"IN": "India", "ID": "Indonesia", "IR": "Iran, Islamic Republic of", "IQ": "Iraq", "IE": "Ireland",
		"IL": "Israel", "IT": "Italy", "JM": "Jamaica", "JP": "Japan", "JO": "Jordan",
		"KZ": "Kazakhstan", "KE": "Kenya", "KP": "North Korea", "KR": "South Korea", "XK": "Kosovo",
		"KW": "Kuwait", "KG": "Kyrgyzstan", "LA": "Lao People's Democratic Republic", "LV": "Latvia", "LB": "Lebanon",
		"LS": "Lesotho", "LR": "Liberia", "LY": "Libya", "LT": "Lithuania", "LU": "Luxembourg",
		"MK": "Macedonia", "MG": "Madagascar", "MW": "Malawi", "MY": "Malaysia", "ML": "Mali",
		"MR": "Mauritania", "MX": "Mexico", "MD": "Moldova, Republic of", "MN": "Mongolia", "ME": "Montenegro",
		"MA": "Morocco", "MZ": "Mozambique", "MM": "Myanmar", "NA": "Namibia", "NP": "Nepal",
		"NL": "Netherlands", "NC": "New Caledonia", "NZ": "New Zealand", "NI": "Nicaragua", "NE": "Niger",
		"NG": "Nigeria", "NO": "Norway", "OM": "Oman", "PK": "Pakistan", "PS": "Palestine",
		"PA": "Panama", "PG": "Papua New Guinea", "PY": "Paraguay", "PE": "Peru", "PH": "Philippines",
		"PL": "Poland", "PT": "Portugal", "PR": "Puerto Rico", "QA": "Qatar", "RO": "Romania",
		"RU": "Russia", "RW": "Rwanda", "SA": "Saudi Arabia", "SN": "Senegal", "RS": "Serbia",
		"SL": "Sierra Leone", "SG": "Singapore", "SK": "Slovakia", "SI": "Slovenia", "SB": "Solomon Is.",
		"SO": "Somalia", "ZA": "South Africa", "SS": "S. Sudan", "ES": "Spain", "LK": "Sri Lanka",
		"SD": "Sudan", "SR": "Suriname", "SZ": "eSwatini", "SE": "Sweden", "CH": "Switzerland",
		"SY": "Syrian Arab Republic", "TW": "Taiwan", "TJ": "Tajikistan", "TZ": "Tanzania", "TH": "Thailand",
		"TL": "Timor-Leste", "TG": "Togo", "TT": "Trinidad and Tobago", "TN": "Tunisia", "TR": "Turkey",
		"TM": "Turkmenistan", "UG": "Uganda", "UA": "Ukraine", "AE": "United Arab Emirates",
		"GB": "United Kingdom", "US": "United States of America", "UY": "Uruguay", "UZ": "Uzbekistan",
		"VU": "Vanuatu", "VE": "Venezuela", "VN": "Vietnam", "EH": "W. Sahara", "YE": "Yemen",
		"ZM": "Zambia", "ZW": "Zimbabwe",
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
		return fmt.Sprintf("%d B", bytes)
	} else if bytes < 1024*1024 {
		return fmt.Sprintf("%.1f KB", float64(bytes)/1024.0)
	} else {
		return fmt.Sprintf("%.1f MB", float64(bytes)/(1024.0*1024.0))
	}
}

func calculateRiskScore(entry services.TrafficEntry) int {
	score := 0
	if entry.Blocked {
		score += 10 // Basic block score
	}
	if entry.PacketCount > 100 {
		score += 10
	}
	if entry.PacketCount > 1000 {
		score += 40
	}
	if entry.CountryCode == "CN" || entry.CountryCode == "RU" {
		score += 20
	}
	if score > 100 {
		score = 100
	}
	return score
}

// GetPortStats returns per-destination-port traffic statistics
func (h *Handler) GetPortStats(c *fiber.Ctx) error {
	if h.EBPF == nil {
		return c.Status(http.StatusServiceUnavailable).JSON(fiber.Map{
			"error": "eBPF service not initialized",
		})
	}

	stats := h.EBPF.GetPortStats()
	if stats == nil {
		stats = []services.PortStats{}
	}

	return c.JSON(fiber.Map{
		"ports": stats,
		"count": len(stats),
	})
}

// GetBlockedIPList returns a list of currently blocked IPs
// GET /api/traffic/blocked
func (h *Handler) GetBlockedIPList(c *fiber.Ctx) error {
	if h.EBPF == nil {
		return c.Status(http.StatusServiceUnavailable).JSON(fiber.Map{
			"error": "eBPF service not initialized",
		})
	}

	blockedList, err := h.EBPF.IterateBlockedIPs()
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": fmt.Sprintf("Failed to retrieve blocked IPs: %v", err),
		})
	}

	return c.JSON(fiber.Map{
		"data":  blockedList,
		"count": len(blockedList),
	})
}

// UnblockIP removes an IP from the blocklist
// DELETE /api/traffic/blocked
func (h *Handler) UnblockIP(c *fiber.Ctx) error {
	var input struct {
		IP string `json:"ip"`
	}
	if err := c.BodyParser(&input); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "Invalid input"})
	}

	if input.IP == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "IP address key required"})
	}

	if h.EBPF == nil {
		return c.Status(http.StatusServiceUnavailable).JSON(fiber.Map{
			"error": "eBPF service not initialized",
		})
	}

	if err := h.EBPF.RemoveBlockedIP(input.IP); err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": fmt.Sprintf("Failed to unblock IP: %v", err),
		})
	}

	return c.JSON(fiber.Map{
		"message": fmt.Sprintf("IP %s has been unblocked", input.IP),
	})
}
