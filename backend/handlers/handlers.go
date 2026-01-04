package handlers

import (
	"kg-proxy-web-gui/backend/models"
	"kg-proxy-web-gui/backend/services"
	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"
)

type Handler struct {
	DB       *gorm.DB
	WG       *services.WireGuardService
	Firewall *services.FirewallService
}

func NewHandler(db *gorm.DB, wg *services.WireGuardService, fw *services.FirewallService) *Handler {
	return &Handler{DB: db, WG: wg, Firewall: fw}
}

// GetOrigins - List all origins
func (h *Handler) GetOrigins(c *fiber.Ctx) error {
	var origins []models.Origin
	if err := h.DB.Preload("Services").Find(&origins).Error; err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(origins)
}

// CreateOrigin - Add new origin
func (h *Handler) CreateOrigin(c *fiber.Ctx) error {
	var origin models.Origin
	if err := c.BodyParser(&origin); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid input"})
	}

	// Generate WireGuard Keys
	priv, pub, err := h.WG.GenerateKeys()
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to generate keys: " + err.Error()})
	}

	// Save to DB (Origin + WG Peer)
	// Transaction
	tx := h.DB.Begin()
	if err := tx.Create(&origin).Error; err != nil {
		tx.Rollback()
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}

	peer := models.WireGuardPeer{
		OriginID:   origin.ID,
		PublicKey:  pub,
		PrivateKey: priv, // In real app, might want to output this once or store securely
	}
	if err := tx.Create(&peer).Error; err != nil {
		tx.Rollback()
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	tx.Commit()

	return c.Status(201).JSON(fiber.Map{
		"origin": origin,
		"wg_config": fiber.Map{
			"private_key": priv,
			"public_key":  pub,
		},
	})
}

// ApplyFirewall - Trigger firewall update
func (h *Handler) ApplyFirewall(c *fiber.Ctx) error {
	if err := h.Firewall.ApplyRules(); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(fiber.Map{"status": "applied", "message": "Firewall rules updated successfully"})
}
