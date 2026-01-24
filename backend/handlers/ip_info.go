package handlers

import (
	"encoding/json"
	"fmt"
	"kg-proxy-web-gui/backend/models"
	"net/http"
	"time"

	"github.com/gofiber/fiber/v2"
)

// IPInfoResponse aggregates all knowledge about an IP
type IPInfoResponse struct {
	IP          string               `json:"ip"`
	CountryCode string               `json:"country_code"`
	CountryName string               `json:"country_name"`
	ASN         string               `json:"asn,omitempty"`
	ISP         string               `json:"isp,omitempty"`
	Status      string               `json:"status"` // "allowed", "blocked", "neutral"
	BlockReason string               `json:"block_reason,omitempty"`
	BlockTTL    int64                `json:"block_ttl,omitempty"` // Seconds remaining
	Traffic     *IPTrafficStats      `json:"traffic,omitempty"`
	History     []models.AttackEvent `json:"history,omitempty"`
	WhoisLink   string               `json:"whois_link"`
}

type IPTrafficStats struct {
	LastSeen     time.Time `json:"last_seen"`
	TotalPackets uint64    `json:"total_packets"`
	Blocked      uint32    `json:"blocked_count"`
}

// GetIPInfo returns comprehensive intelligence for an IP
// GET /api/ip/info/:ip
func (h *Handler) GetIPInfo(c *fiber.Ctx) error {
	ip := c.Params("ip")
	if ip == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "IP address required"})
	}

	response := IPInfoResponse{
		IP:        ip,
		Status:    "neutral",
		WhoisLink: fmt.Sprintf("https://ipinfo.io/%s", ip),
	}

	// 1. GeoIP Lookup
	if h.Firewall != nil && h.Firewall.GeoIP != nil {
		// We don't have a direct "GetCountry" method exposed yet in GeoIPService for single IP string
		// But we can add one or use the map logic if available.
		// Detailed lookup functionality is planned for GeoIPService.
		// For now, let's assume we can get basic info or implement it.
		// Actually, let's use the external API logic if API Key is present, otherwise DB.

		// Note: The Open Source GeoLite2 DB doesn't have ASN/ISP easily accessible without extra DB.
		// We will rely on external services if configured, or basic DB.
	}

	// Fallback/Enhancement if external API key is configured
	// TODO: Implement external API call (ipinfo.io or similar) if key exists in settings

	// 2. Check Block/Allow Status
	// Check Manual Whitelist
	var allow models.AllowIP
	if err := h.DB.Where("ip = ?", ip).First(&allow).Error; err == nil {
		response.Status = "allowed"
		response.BlockReason = "Manually Whitelisted: " + allow.Label
	}

	// Check Blocklist (DB)
	var ban models.BanIP
	if err := h.DB.Where("ip = ?", ip).First(&ban).Error; err == nil {
		response.Status = "blocked"
		response.BlockReason = "Blacklisted: " + ban.Reason
	}

	// Check Active eBPF Block
	if h.EBPF != nil {
		// Optimization: Use O(1) map lookup
		if blockedInfo := h.EBPF.LookupBlockedIP(ip); blockedInfo != nil {
			response.Status = "blocked"
			response.BlockReason = "Active Block: " + blockedInfo.Reason
			response.BlockTTL = blockedInfo.TTL
		}

		// 3. Traffic Stats from eBPF (Active Session)
		traffic := h.EBPF.GetTrafficData()
		for _, t := range traffic {
			if t.SourceIP == ip {
				response.Traffic = &IPTrafficStats{
					LastSeen:     t.Timestamp,
					TotalPackets: uint64(t.PacketCount),
					Blocked:      0, // TrafficEntry doesn't have blocked count, just boolean Blocked status
				}
				if t.Blocked {
					response.Traffic.Blocked = 1
					if response.Status == "neutral" {
						response.Status = "blocked"
					}
				}
				response.CountryCode = t.CountryCode
				response.CountryName = getCountryName(t.CountryCode)
				break
			}
		}
	}

	// 4. Attack History (Last 5 events)
	h.DB.Model(&models.AttackEvent{}).
		Where("source_ip = ?", ip).
		Order("timestamp DESC").
		Limit(5).
		Find(&response.History)

	// If we still don't have country, try to infer from history
	if response.CountryCode == "" && len(response.History) > 0 {
		response.CountryCode = response.History[0].CountryCode
		response.CountryName = response.History[0].CountryName
	}

	// Mock External Info if not available
	if response.CountryCode == "" {
		response.CountryCode = "XX"
		response.CountryName = "Unknown"
	}

	return c.JSON(response)
}

// FetchExternalIPInfo fetches ASN/ISP from external API (e.g. ip-api.com)
// Helper function, not a handler itself
func FetchExternalIPInfo(ip string) (string, string) {
	// Simple HTTP GET to ip-api.com (free tier, rate limited)
	// http://ip-api.com/json/{ip}?fields=isp,as
	client := http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(fmt.Sprintf("http://ip-api.com/json/%s?fields=isp,as", ip))
	if err != nil {
		return "", ""
	}
	defer resp.Body.Close()

	var data struct {
		ISP string `json:"isp"`
		AS  string `json:"as"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return "", ""
	}

	return data.AS, data.ISP
}
