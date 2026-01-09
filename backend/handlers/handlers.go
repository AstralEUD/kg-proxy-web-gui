package handlers

import (
	"fmt"
	"kg-proxy-web-gui/backend/models"
	"kg-proxy-web-gui/backend/services"
	"kg-proxy-web-gui/backend/system"

	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"
)

type Handler struct {
	DB       *gorm.DB
	WG       *services.WireGuardService
	Firewall *services.FirewallService
	EBPF     *services.EBPFService
	Webhook  *services.WebhookService
}

func NewHandler(db *gorm.DB, wg *services.WireGuardService, fw *services.FirewallService, ebpf *services.EBPFService, webhook *services.WebhookService) *Handler {
	return &Handler{DB: db, WG: wg, Firewall: fw, EBPF: ebpf, Webhook: webhook}
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

	// Apply Peer to WireGuard Interface
	if err := h.WG.AddPeer(&peer, origin.WgIP); err != nil {
		system.Error("Failed to add WireGuard peer for Origin %d: %v", origin.ID, err)
	} else {
		system.Info("Added WireGuard peer for Origin %d with IP %s", origin.ID, origin.WgIP)
	}

	// Calculate AllowedIPs
	sysInfo := services.NewSysInfoService()
	vpsIP := sysInfo.GetPublicIP()
	allowedIPs, _ := h.WG.GenerateAllowedIPs(vpsIP, "10.0.0.0/8") // Assuming internal network

	// Endpoint
	endpoint := fmt.Sprintf("%s:51820", vpsIP)
	serverPubKey := h.WG.GetServerPublicKey()

	return c.Status(201).JSON(fiber.Map{
		"origin": origin,
		"wg_config": fiber.Map{
			"private_key":       priv,
			"public_key":        pub,
			"server_public_key": serverPubKey,
			"allowed_ips":       allowedIPs,
			"endpoint":          endpoint,
		},
	})
}

// UpdateOrigin - Update existing origin
func (h *Handler) UpdateOrigin(c *fiber.Ctx) error {
	id := c.Params("id")
	var origin models.Origin
	if err := h.DB.First(&origin, id).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Origin not found"})
	}

	var input models.Origin
	if err := c.BodyParser(&input); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid input"})
	}

	origin.Name = input.Name
	origin.WgIP = input.WgIP

	if err := h.DB.Save(&origin).Error; err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}

	// Also fetch peer to return config info if needed
	var peer models.WireGuardPeer
	h.DB.Where("origin_id = ?", origin.ID).First(&peer)

	// Calculate AllowedIPs (Recalculate in case they want to update client config)
	sysInfo := services.NewSysInfoService()
	vpsIP := sysInfo.GetPublicIP()
	allowedIPs, _ := h.WG.GenerateAllowedIPs(vpsIP, "10.0.0.0/8")
	endpoint := fmt.Sprintf("%s:51820", vpsIP)
	serverPubKey := h.WG.GetServerPublicKey()

	return c.JSON(fiber.Map{
		"origin": origin,
		"wg_config": fiber.Map{
			"private_key":       peer.PrivateKey,
			"public_key":        peer.PublicKey,
			"server_public_key": serverPubKey,
			"allowed_ips":       allowedIPs,
			"endpoint":          endpoint,
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
