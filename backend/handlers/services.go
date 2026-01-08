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
	if err := h.DB.Preload("Origin").Preload("Ports").Find(&services).Error; err != nil {
		system.Error("Failed to fetch services: %v", err)
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(services)
}

// CreateService - Add new service
func (h *Handler) CreateService(c *fiber.Ctx) error {
	type PortInput struct {
		Name           string `json:"name"`
		Protocol       string `json:"protocol"`
		PublicPort     int    `json:"public_port"`
		PublicPortEnd  int    `json:"public_port_end"` // Optional, for range
		PrivatePort    int    `json:"private_port"`
		PrivatePortEnd int    `json:"private_port_end"` // Optional
	}

	var input struct {
		Name     string      `json:"name"`
		OriginID uint        `json:"origin_id"`
		Ports    []PortInput `json:"ports"`
	}

	if err := c.BodyParser(&input); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "Invalid input"})
	}

	// Validate origin exists
	var origin models.Origin
	if err := h.DB.First(&origin, input.OriginID).Error; err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "Origin not found"})
	}

	// Create Service
	service := models.Service{
		Name:     input.Name,
		OriginID: input.OriginID,
	}

	if err := h.DB.Create(&service).Error; err != nil {
		system.Error("Failed to create service: %v", err)
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	// Create Ports
	for _, p := range input.Ports {
		port := models.ServicePort{
			ServiceID:      service.ID,
			Name:           p.Name,
			Protocol:       p.Protocol,
			PublicPort:     p.PublicPort,
			PublicPortEnd:  p.PublicPortEnd,
			PrivatePort:    p.PrivatePort,
			PrivatePortEnd: p.PrivatePortEnd,
		}
		if err := h.DB.Create(&port).Error; err != nil {
			system.Warn("Failed to create port %d for service %s: %v", p.PublicPort, service.Name, err)
		}
	}

	system.Info("Service created: %s with %d ports", service.Name, len(input.Ports))
	AddEvent("success", "Service created: "+service.Name)

	// Auto-apply firewall rules
	if h.Firewall != nil {
		go h.Firewall.ApplyRules()
	}

	// Return full object with ports
	h.DB.Preload("Ports").First(&service, service.ID)
	return c.Status(http.StatusCreated).JSON(service)
}

// UpdateService - Update existing service
func (h *Handler) UpdateService(c *fiber.Ctx) error {
	id := c.Params("id")
	var service models.Service

	if err := h.DB.First(&service, id).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Service not found"})
	}

	type PortInput struct {
		Name           string `json:"name"`
		Protocol       string `json:"protocol"`
		PublicPort     int    `json:"public_port"`
		PublicPortEnd  int    `json:"public_port_end"`
		PrivatePort    int    `json:"private_port"`
		PrivatePortEnd int    `json:"private_port_end"`
	}

	var input struct {
		Name     string      `json:"name"`
		OriginID uint        `json:"origin_id"`
		Ports    []PortInput `json:"ports"`
	}

	if err := c.BodyParser(&input); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid input"})
	}

	// Update fields
	service.Name = input.Name
	service.OriginID = input.OriginID

	// Transaction for atomic update
	tx := h.DB.Begin()

	if err := tx.Save(&service).Error; err != nil {
		tx.Rollback()
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}

	// Delete old ports
	if err := tx.Where("service_id = ?", service.ID).Delete(&models.ServicePort{}).Error; err != nil {
		tx.Rollback()
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}

	// Add new ports
	for _, p := range input.Ports {
		port := models.ServicePort{
			ServiceID:      service.ID,
			Name:           p.Name,
			Protocol:       p.Protocol,
			PublicPort:     p.PublicPort,
			PublicPortEnd:  p.PublicPortEnd,
			PrivatePort:    p.PrivatePort,
			PrivatePortEnd: p.PrivatePortEnd,
		}
		if err := tx.Create(&port).Error; err != nil {
			tx.Rollback()
			return c.Status(500).JSON(fiber.Map{"error": err.Error()})
		}
	}

	tx.Commit()

	system.Info("Service updated: %s", service.Name)
	AddEvent("success", "Service updated: "+service.Name)

	// Apply firewall
	if h.Firewall != nil {
		go h.Firewall.ApplyRules()
	}

	h.DB.Preload("Ports").First(&service, service.ID)
	return c.JSON(service)
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

	// Trigger firewall update to remove rules
	if h.Firewall != nil {
		go h.Firewall.ApplyRules()
	}

	return c.JSON(fiber.Map{"message": "Service deleted"})
}

// DeleteOrigin - Delete an origin and its services
func (h *Handler) DeleteOrigin(c *fiber.Ctx) error {
	id := c.Params("id")

	// Delete associated services first
	h.DB.Where("origin_id = ?", id).Delete(&models.Service{})

	// Delete associated WireGuard peer
	var peer models.WireGuardPeer
	if err := h.DB.Where("origin_id = ?", id).First(&peer).Error; err == nil {
		if err := h.WG.RemovePeer(&peer); err != nil {
			system.Warn("Failed to remove WireGuard peer from interface: %v", err)
		}
	}
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
