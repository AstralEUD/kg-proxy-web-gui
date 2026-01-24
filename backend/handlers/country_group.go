package handlers

import (
	"kg-proxy-web-gui/backend/models"
	"net/http"
	"strings"

	"github.com/gofiber/fiber/v2"
)

// GetCountryGroups returns all country groups
// GET /api/security/countries/groups
func (h *Handler) GetCountryGroups(c *fiber.Ctx) error {
	var groups []models.CountryGroup
	if err := h.DB.Order("name ASC").Find(&groups).Error; err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(groups)
}

// CreateCountryGroup creates a new country group
// POST /api/security/countries/groups
func (h *Handler) CreateCountryGroup(c *fiber.Ctx) error {
	var input models.CountryGroup
	if err := c.BodyParser(&input); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "Invalid input"})
	}

	if input.Name == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "Name is required"})
	}

	// Normalize country codes (uppercase, trim spaces)
	codes := strings.Split(input.Countries, ",")
	var normalized []string
	for _, code := range codes {
		trimmed := strings.TrimSpace(strings.ToUpper(code))
		if len(trimmed) == 2 {
			normalized = append(normalized, trimmed)
		}
	}
	input.Countries = strings.Join(normalized, ",")

	if err := h.DB.Create(&input).Error; err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	return c.Status(http.StatusCreated).JSON(input)
}

// UpdateCountryGroup updates an existing country group
// PUT /api/security/countries/groups/:id
func (h *Handler) UpdateCountryGroup(c *fiber.Ctx) error {
	id := c.Params("id")
	var group models.CountryGroup

	if err := h.DB.First(&group, id).Error; err != nil {
		return c.Status(http.StatusNotFound).JSON(fiber.Map{"error": "Group not found"})
	}

	var input models.CountryGroup
	if err := c.BodyParser(&input); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "Invalid input"})
	}

	group.Name = input.Name
	group.Description = input.Description
	group.Color = input.Color

	// Normalize country codes
	if input.Countries != "" {
		codes := strings.Split(input.Countries, ",")
		var normalized []string
		for _, code := range codes {
			trimmed := strings.TrimSpace(strings.ToUpper(code))
			if len(trimmed) == 2 {
				normalized = append(normalized, trimmed)
			}
		}
		group.Countries = strings.Join(normalized, ",")
	} else {
		group.Countries = ""
	}

	if err := h.DB.Save(&group).Error; err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	return c.JSON(group)
}

// DeleteCountryGroup deletes a country group
// DELETE /api/security/countries/groups/:id
func (h *Handler) DeleteCountryGroup(c *fiber.Ctx) error {
	id := c.Params("id")
	if err := h.DB.Delete(&models.CountryGroup{}, id).Error; err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(fiber.Map{"success": true})
}
