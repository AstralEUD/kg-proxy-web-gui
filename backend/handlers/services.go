package handlers

import (
	"kg-proxy-web-gui/backend/models"
	"kg-proxy-web-gui/backend/system"
	"net/http"

	"github.com/gofiber/fiber/v2"
)

// GetServices - List all services
func (h *Handler) GetServices(c *fiber.Ctx) error {
	var services []models.Service
	if err := h.DB.Preload("Origin").Find(&services).Error; err != nil {
		system.Error("Failed to fetch services: %v", err)
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(services)
}

// CreateService - Add new service
func (h *Handler) CreateService(c *fiber.Ctx) error {
	var input struct {
		Name              string `json:"name"`
		OriginID          uint   `json:"origin_id"`
		PublicGamePort    int    `json:"public_game_port"`
		PublicBrowserPort int    `json:"public_browser_port"`
		PublicA2SPort     int    `json:"public_a2s_port"`
	}

	if err := c.BodyParser(&input); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "Invalid input"})
	}

	// Validate origin exists
	var origin models.Origin
	if err := h.DB.First(&origin, input.OriginID).Error; err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "Origin not found"})
	}

	service := models.Service{
		Name:              input.Name,
		OriginID:          input.OriginID,
		PublicGamePort:    input.PublicGamePort,
		PublicBrowserPort: input.PublicBrowserPort,
		PublicA2SPort:     input.PublicA2SPort,
	}

	if err := h.DB.Create(&service).Error; err != nil {
		system.Error("Failed to create service: %v", err)
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	system.Info("Service created: %s", service.Name)
	AddEvent("success", "Service created: "+service.Name)

	// Auto-apply firewall rules after service creation
	if h.Firewall != nil {
		if err := h.Firewall.ApplyRules(); err != nil {
			system.Warn("Failed to auto-apply firewall rules: %v", err)
		} else {
			system.Info("Firewall rules auto-applied for new service")
		}
	}

	return c.Status(http.StatusCreated).JSON(service)
}

// DeleteService - Delete a service
func (h *Handler) DeleteService(c *fiber.Ctx) error {
	id := c.Params("id")
	if result := h.DB.Delete(&models.Service{}, id); result.Error != nil {
		system.Error("Failed to delete service: %v", result.Error)
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": result.Error.Error()})
	}

	system.Info("Service deleted: ID %s", id)
	AddEvent("warning", "Service deleted: ID "+id)

	return c.JSON(fiber.Map{"message": "Service deleted"})
}

// DeleteOrigin - Delete an origin and its services
func (h *Handler) DeleteOrigin(c *fiber.Ctx) error {
	id := c.Params("id")

	// Delete associated services first
	h.DB.Where("origin_id = ?", id).Delete(&models.Service{})

	// Delete associated WireGuard peer
	h.DB.Where("origin_id = ?", id).Delete(&models.WireGuardPeer{})

	// Delete origin
	if result := h.DB.Delete(&models.Origin{}, id); result.Error != nil {
		system.Error("Failed to delete origin: %v", result.Error)
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": result.Error.Error()})
	}

	system.Info("Origin deleted: ID %s", id)
	AddEvent("warning", "Origin deleted: ID "+id)

	return c.JSON(fiber.Map{"message": "Origin deleted"})
}
