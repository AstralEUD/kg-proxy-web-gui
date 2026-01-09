package handlers

import (
	"kg-proxy-web-gui/backend/models"
	"kg-proxy-web-gui/backend/system"
	"net/http"
	"time"

	"github.com/gofiber/fiber/v2"
)

// BackupData represents the complete system configuration for export/import
type BackupData struct {
	ExportedAt       time.Time               `json:"exported_at"`
	Version          string                  `json:"version"`
	Origins          []models.Origin         `json:"origins"`
	Services         []models.Service        `json:"services"`
	SecuritySettings models.SecuritySettings `json:"security_settings"`
	AllowIPs         []models.AllowIP        `json:"allow_ips"`
	BanIPs           []models.BanIP          `json:"ban_ips"`
	AllowForeign     []models.AllowForeign   `json:"allow_foreign"`
}

// ExportConfig exports all configuration as JSON
// GET /api/backup/export
func (h *Handler) ExportConfig(c *fiber.Ctx) error {
	backup := BackupData{
		ExportedAt: time.Now(),
		Version:    "1.0",
	}

	// Fetch all data
	h.DB.Preload("Services.Ports").Find(&backup.Origins)
	h.DB.Preload("Ports").Find(&backup.Services)
	h.DB.First(&backup.SecuritySettings, 1)
	h.DB.Find(&backup.AllowIPs)
	h.DB.Find(&backup.BanIPs)
	h.DB.Find(&backup.AllowForeign)

	// Set filename for download
	filename := "kg-proxy-backup-" + time.Now().Format("2006-01-02") + ".json"
	c.Set("Content-Disposition", "attachment; filename="+filename)
	c.Set("Content-Type", "application/json")

	system.Info("Configuration exported")
	AddEvent("success", "Configuration exported")

	return c.JSON(backup)
}

// ImportConfig imports configuration from JSON
// POST /api/backup/import
func (h *Handler) ImportConfig(c *fiber.Ctx) error {
	var backup BackupData
	if err := c.BodyParser(&backup); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "Invalid backup file format"})
	}

	// Validate version
	if backup.Version == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "Invalid backup file: missing version"})
	}

	// Count items for summary
	summary := fiber.Map{
		"origins":       len(backup.Origins),
		"services":      len(backup.Services),
		"allow_ips":     len(backup.AllowIPs),
		"ban_ips":       len(backup.BanIPs),
		"allow_foreign": len(backup.AllowForeign),
	}

	// Start transaction
	tx := h.DB.Begin()

	// Import Origins (update if exists, create if not)
	for _, origin := range backup.Origins {
		var existing models.Origin
		if err := tx.First(&existing, origin.ID).Error; err == nil {
			// Update existing
			existing.Name = origin.Name
			existing.WgIP = origin.WgIP
			tx.Save(&existing)
		} else {
			// Create new (without ID to let DB assign)
			newOrigin := models.Origin{
				Name: origin.Name,
				WgIP: origin.WgIP,
			}
			tx.Create(&newOrigin)
		}
	}

	// Import Services
	for _, service := range backup.Services {
		var existing models.Service
		if err := tx.First(&existing, service.ID).Error; err == nil {
			existing.Name = service.Name
			existing.OriginID = service.OriginID
			tx.Save(&existing)
			// Update ports
			tx.Where("service_id = ?", existing.ID).Delete(&models.ServicePort{})
			for _, port := range service.Ports {
				port.ServiceID = existing.ID
				port.ID = 0 // Reset ID
				tx.Create(&port)
			}
		} else {
			newService := models.Service{
				Name:     service.Name,
				OriginID: service.OriginID,
			}
			tx.Create(&newService)
			for _, port := range service.Ports {
				port.ServiceID = newService.ID
				port.ID = 0
				tx.Create(&port)
			}
		}
	}

	// Import Security Settings
	if backup.SecuritySettings.ID > 0 {
		var existing models.SecuritySettings
		if err := tx.First(&existing, 1).Error; err == nil {
			// Copy relevant fields (not sensitive ones like webhook URL)
			existing.GlobalProtection = backup.SecuritySettings.GlobalProtection
			existing.BlockVPN = backup.SecuritySettings.BlockVPN
			existing.BlockTOR = backup.SecuritySettings.BlockTOR
			existing.SYNCookies = backup.SecuritySettings.SYNCookies
			existing.ProtectionLevel = backup.SecuritySettings.ProtectionLevel
			existing.GeoAllowCountries = backup.SecuritySettings.GeoAllowCountries
			existing.SmartBanning = backup.SecuritySettings.SmartBanning
			existing.SteamQueryBypass = backup.SecuritySettings.SteamQueryBypass
			existing.XDPHardBlocking = backup.SecuritySettings.XDPHardBlocking
			existing.XDPRateLimitPPS = backup.SecuritySettings.XDPRateLimitPPS
			tx.Save(&existing)
		}
	}

	// Import AllowIPs
	for _, ip := range backup.AllowIPs {
		var existing models.AllowIP
		if err := tx.Where("ip = ?", ip.IP).First(&existing).Error; err != nil {
			// Create new
			newIP := models.AllowIP{
				IP:        ip.IP,
				Label:     ip.Label,
				ExpiresAt: ip.ExpiresAt,
			}
			tx.Create(&newIP)
		}
	}

	// Import BanIPs
	for _, ip := range backup.BanIPs {
		var existing models.BanIP
		if err := tx.Where("ip = ?", ip.IP).First(&existing).Error; err != nil {
			newIP := models.BanIP{
				IP:        ip.IP,
				Reason:    ip.Reason,
				IsAuto:    ip.IsAuto,
				ExpiresAt: ip.ExpiresAt,
			}
			tx.Create(&newIP)
		}
	}

	// Import AllowForeign
	for _, ip := range backup.AllowForeign {
		var existing models.AllowForeign
		if err := tx.Where("ip = ?", ip.IP).First(&existing).Error; err != nil {
			newIP := models.AllowForeign{
				IP:        ip.IP,
				Label:     ip.Label,
				ExpiresAt: ip.ExpiresAt,
			}
			tx.Create(&newIP)
		}
	}

	tx.Commit()

	system.Info("Configuration imported: %v", summary)
	AddEvent("success", "Configuration imported from backup")

	// Apply firewall rules after import
	if h.Firewall != nil {
		go h.Firewall.ApplyRules()
	}

	return c.JSON(fiber.Map{
		"message": "Configuration imported successfully",
		"summary": summary,
	})
}
