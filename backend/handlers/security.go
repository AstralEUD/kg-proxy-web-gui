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
	settings.EBPFEnabled = input.EBPFEnabled

	// Save to DB
	if result.Error != nil {
		h.DB.Create(&settings)
	} else {
		h.DB.Save(&settings)
	}

	// Handle blocked IPs (clear and recreate)
	h.DB.Where("is_auto = ?", false).Delete(&models.BanIP{})
	for _, ip := range input.BlockedIPs {
		if ip != "" {
			h.DB.Create(&models.BanIP{
				IP:     ip,
				Reason: "Manual blacklist",
				IsAuto: false,
			})
		}
	}

	system.Info("Security settings updated: eBPF=%v, Protection=%d", settings.EBPFEnabled, settings.ProtectionLevel)
	AddEvent("success", "Security settings applied")

	return c.JSON(fiber.Map{"message": "Settings applied successfully", "settings": settings})
}
