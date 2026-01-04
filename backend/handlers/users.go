package handlers

import (
	"kg-proxy-web-gui/backend/models"
	"net/http"

	"github.com/gofiber/fiber/v2"
	"golang.org/x/crypto/bcrypt"
)

// Extending the main Handler struct in handlers.go
// Note: In Go, methods can be in different files if in the same package.

func (h *Handler) GetUsers(c *fiber.Ctx) error {
	var users []models.Admin
	if result := h.DB.Find(&users); result.Error != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": result.Error.Error()})
	}
	// Hide passwords
	for i := range users {
		users[i].Password = ""
	}
	return c.JSON(users)
}

func (h *Handler) CreateUser(c *fiber.Ctx) error {
	var input struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := c.BodyParser(&input); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Could not hash password"})
	}
	user := models.Admin{Username: input.Username, Password: string(hashed)}
	if result := h.DB.Create(&user); result.Error != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": result.Error.Error()})
	}
	return c.JSON(fiber.Map{"message": "User created", "user": user.Username})
}

func (h *Handler) DeleteUser(c *fiber.Ctx) error {
	id := c.Params("id")
	if result := h.DB.Delete(&models.Admin{}, id); result.Error != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": result.Error.Error()})
	}
	return c.JSON(fiber.Map{"message": "User deleted"})
}
