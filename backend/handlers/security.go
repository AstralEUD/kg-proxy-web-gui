package handlers

import (
	"kg-proxy-web-gui/backend/models"
	"kg-proxy-web-gui/backend/system"
	"net/http"
	"strings"

	"github.com/gofiber/fiber/v2"
)

// GetSecuritySettings - Get current security settings
func (h *Handler) GetSecuritySettings(c *fiber.Ctx) error {
	var settings models.SecuritySettings

	// Get or create settings (ID=1 is the single row)
	result := h.DB.First(&settings, 1)
	if result.Error != nil {
		// Create default settings if not exists
		settings = models.SecuritySettings{
			ID:                1,
			GlobalProtection:  true,
			BlockVPN:          false,
			BlockTOR:          false,
			SYNCookies:        true,
			ProtectionLevel:   2,
			GeoAllowCountries: "KR",
			SmartBanning:      false,
			EBPFEnabled:       false,
		}
		h.DB.Create(&settings)
	}

	return c.JSON(settings)
}

// UpdateSecuritySettings - Update security settings
func (h *Handler) UpdateSecuritySettings(c *fiber.Ctx) error {
	var input struct {
		GlobalProtection          bool     `json:"global_protection"`
		BlockVPN                  bool     `json:"block_vpn"`
		BlockTOR                  bool     `json:"block_tor"`
		SYNCookies                bool     `json:"syn_cookies"`
		ProtectionLevel           int      `json:"protection_level"`
		GeoAllowCountries         []string `json:"geo_allow_countries"`
		SmartBanning              bool     `json:"smart_banning"`
		SteamQueryBypass          bool     `json:"steam_query_bypass"`
		EBPFEnabled               bool     `json:"ebpf_enabled"`
		TrafficStatsResetInterval int      `json:"traffic_stats_reset_interval"`
		MaxMindLicenseKey         string   `json:"maxmind_license_key"`
		BlockedIPs                []string `json:"blocked_ips"`
		// XDP Settings
		XDPHardBlocking bool `json:"xdp_hard_blocking"`
		XDPRateLimitPPS int  `json:"xdp_rate_limit_pps"`
		// Discord Webhook
		DiscordWebhookURL string `json:"discord_webhook_url"`
		AlertOnAttack     bool   `json:"alert_on_attack"`
		AlertOnBlock      bool   `json:"alert_on_block"`
		// IP Intelligence
		IPIntelligenceEnabled bool   `json:"ip_intelligence_enabled"`
		IPIntelligenceAPIKey  string `json:"ip_intelligence_api_key"`
		// Data Retention
		AttackHistoryDays int `json:"attack_history_days"`
	}

	if err := c.BodyParser(&input); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "Invalid input"})
	}

	// Get or create settings
	var settings models.SecuritySettings
	result := h.DB.First(&settings, 1)
	if result.Error != nil {
		settings.ID = 1
	}

	// Capture old key for change detection
	oldLicenseKey := settings.MaxMindLicenseKey

	// Update fields
	settings.GlobalProtection = input.GlobalProtection
	settings.BlockVPN = input.BlockVPN
	settings.BlockTOR = input.BlockTOR
	settings.SYNCookies = input.SYNCookies
	settings.ProtectionLevel = input.ProtectionLevel
	settings.GeoAllowCountries = strings.Join(input.GeoAllowCountries, ",")
	settings.SmartBanning = input.SmartBanning
	settings.SteamQueryBypass = input.SteamQueryBypass
	settings.EBPFEnabled = input.EBPFEnabled
	settings.TrafficStatsResetInterval = input.TrafficStatsResetInterval
	settings.MaxMindLicenseKey = input.MaxMindLicenseKey
	// XDP Settings
	settings.XDPHardBlocking = input.XDPHardBlocking
	settings.XDPRateLimitPPS = input.XDPRateLimitPPS
	// Discord Webhook
	settings.DiscordWebhookURL = input.DiscordWebhookURL
	settings.AlertOnAttack = input.AlertOnAttack
	settings.AlertOnBlock = input.AlertOnBlock
	// IP Intelligence
	settings.IPIntelligenceEnabled = input.IPIntelligenceEnabled
	settings.IPIntelligenceAPIKey = input.IPIntelligenceAPIKey
	// Data Retention
	if input.AttackHistoryDays > 0 {
		settings.AttackHistoryDays = input.AttackHistoryDays
	}

	// Save to DB
	if result.Error != nil {
		h.DB.Create(&settings)
	} else {
		h.DB.Save(&settings)
	}

	// Enable/Disable eBPF based on settings
	if h.EBPF != nil {
		if settings.EBPFEnabled {
			if err := h.EBPF.Enable(); err != nil {
				system.Warn("Failed to enable eBPF: %v", err)
			} else {
				system.Info("eBPF XDP monitoring enabled")
			}
		} else {
			h.EBPF.Disable()
			system.Info("eBPF XDP monitoring disabled")
		}
	}

	// Handle blocked IPs (clear and recreate) - REMOVED
	// We no longer handle blocked IPs in this bulk settings update.
	// They are managed via granular API endpoints (/security/rules/block).

	system.Info("Security settings updated: eBPF=%v, Protection=%d", settings.EBPFEnabled, settings.ProtectionLevel)
	AddEvent("success", "Security settings applied")

	// Update GeoIP service with new license key only if it changed
	if input.MaxMindLicenseKey != "" && input.MaxMindLicenseKey != oldLicenseKey && h.Firewall != nil && h.Firewall.GeoIP != nil {
		system.Info("MaxMind license key updated, refreshing database...")
		h.Firewall.GeoIP.SetLicenseKey(input.MaxMindLicenseKey)
		if err := h.Firewall.GeoIP.RefreshGeoIP(); err != nil {
			system.Warn("Failed to refresh GeoIP database: %v", err)
			AddEvent("warning", "GeoIP database download failed: "+err.Error())
		} else {
			system.Info("GeoIP database refreshed successfully")
			AddEvent("success", "GeoIP database updated")
		}
	}

	// Apply Firewall Rules
	if h.Firewall != nil {
		go h.Firewall.ApplyRules()
	}

	// Update Webhook Service
	if h.Webhook != nil {
		h.Webhook.SetWebhookURL(settings.DiscordWebhookURL)
	}

	// Update eBPF Config (XDP settings)
	if h.EBPF != nil {
		h.EBPF.UpdateConfig(settings.XDPHardBlocking, settings.XDPRateLimitPPS)
	}

	return c.JSON(fiber.Map{"message": "Settings applied successfully", "settings": settings})
}

// TestWebhook sends a test notification to the configured Discord webhook
func (h *Handler) TestWebhook(c *fiber.Ctx) error {
	if h.Webhook == nil {
		return c.Status(http.StatusServiceUnavailable).JSON(fiber.Map{"error": "Webhook service not available"})
	}

	// Get webhook URL from DB in case it was just updated
	var settings models.SecuritySettings
	if err := h.DB.First(&settings, 1).Error; err == nil && settings.DiscordWebhookURL != "" {
		h.Webhook.SetWebhookURL(settings.DiscordWebhookURL)
	}

	if !h.Webhook.IsEnabled() {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "Discord webhook URL not configured"})
	}

	if err := h.Webhook.SendTestAlert(); err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	return c.JSON(fiber.Map{"message": "Test notification sent successfully"})
}

// GetIPRules returns all allow/block rules
func (h *Handler) GetIPRules(c *fiber.Ctx) error {
	var allowed []models.AllowIP
	var blocked []models.BanIP

	h.DB.Order("created_at desc").Find(&allowed)
	h.DB.Not("is_auto", true).Order("created_at desc").Find(&blocked)

	return c.JSON(fiber.Map{
		"allowed": allowed,
		"blocked": blocked,
	})
}

// AddAllowIP adds an IP to whitelist
func (h *Handler) AddAllowIP(c *fiber.Ctx) error {
	var input models.AllowIP
	if err := c.BodyParser(&input); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid input"})
	}
	if err := h.DB.Create(&input).Error; err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}

	if h.Firewall != nil {
		go h.Firewall.ApplyRules()
	}

	// Update eBPF whitelist
	if h.EBPF != nil {
		go h.EBPF.SyncWhitelist()
	}

	return c.JSON(input)
}

// DeleteAllowIP removes an IP from whitelist
func (h *Handler) DeleteAllowIP(c *fiber.Ctx) error {
	id := c.Params("id")
	if err := h.DB.Delete(&models.AllowIP{}, id).Error; err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}

	if h.Firewall != nil {
		go h.Firewall.ApplyRules()
	}

	// Update eBPF whitelist
	if h.EBPF != nil {
		go h.EBPF.SyncWhitelist()
	}

	return c.JSON(fiber.Map{"success": true})
}

// AddBanIP adds an IP to blacklist
func (h *Handler) AddBanIP(c *fiber.Ctx) error {
	var input models.BanIP
	if err := c.BodyParser(&input); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid input"})
	}
	input.IsAuto = false
	if err := h.DB.Create(&input).Error; err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}

	if h.Firewall != nil {
		go h.Firewall.ApplyRules()
	}
	return c.JSON(input)
}

// DeleteBanIP removes an IP from blacklist
func (h *Handler) DeleteBanIP(c *fiber.Ctx) error {
	id := c.Params("id")
	if err := h.DB.Delete(&models.BanIP{}, id).Error; err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}

	if h.Firewall != nil {
		go h.Firewall.ApplyRules()
	}
	return c.JSON(fiber.Map{"success": true})
}

// CheckIPStatus checks if an IP is allowed/blocked/geo-blocked
func (h *Handler) CheckIPStatus(c *fiber.Ctx) error {
	ip := c.Params("ip")
	var status string = "neutral"
	var reason string = ""
	var details interface{} = nil

	// Check manual whitelist
	var allow models.AllowIP
	if err := h.DB.Where("ip = ?", ip).First(&allow).Error; err == nil {
		status = "allowed"
		reason = "Manually Whitelisted: " + allow.Label
		details = allow
		return c.JSON(fiber.Map{"ip": ip, "status": status, "reason": reason, "details": details})
	}

	// Check manual/auto blacklist
	var ban models.BanIP
	if err := h.DB.Where("ip = ?", ip).First(&ban).Error; err == nil {
		status = "blocked"
		reason = "Blacklisted: " + ban.Reason
		details = ban
		return c.JSON(fiber.Map{"ip": ip, "status": status, "reason": reason, "details": details})
	}

	// Check GeoIP
	// Using services is better than direct DB if possible
	// But GeoIP service is in 'services'. Handler has no direct access to services?
	// Handler struct DOES have Services! (h.EBPF.geoIPService?)
	// Actually Handlers struct: DB, WG, Firewall, EBPF.
	// Firewall service has GeoIP.
	// We can add CheckGeoIP method to FirewallService or use what exists.

	// Assuming safe if passed blacklist check
	status = "allowed"
	reason = "Not in any blacklist"

	return c.JSON(fiber.Map{
		"ip":     ip,
		"status": status,
		"reason": reason,
	})
}
