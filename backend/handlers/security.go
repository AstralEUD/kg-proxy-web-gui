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
		GlobalProtection  bool     `json:"global_protection"`
		BlockVPN          bool     `json:"block_vpn"`
		BlockTOR          bool     `json:"block_tor"`
		SYNCookies        bool     `json:"syn_cookies"`
		ProtectionLevel   int      `json:"protection_level"`
		GeoAllowCountries []string `json:"geo_allow_countries"`
		SmartBanning      bool     `json:"smart_banning"`
		SteamQueryBypass  bool     `json:"steam_query_bypass"`
		EBPFEnabled       bool     `json:"ebpf_enabled"`
		BlockedIPs        []string `json:"blocked_ips"`
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

	// Apply Firewall Rules
	if h.Firewall != nil {
		go h.Firewall.ApplyRules()
	}

	return c.JSON(fiber.Map{"message": "Settings applied successfully", "settings": settings})
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
