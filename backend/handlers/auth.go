package handlers

import (
	"kg-proxy-web-gui/backend/models"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
)

// Secret key (in production, use env var)
var jwtSecret = []byte("super-secret-key-change-me")

// LoginRequest struct
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (h *Handler) Login(c *fiber.Ctx) error {
	var req LoginRequest
	var err error
	if err = c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid input"})
	}

	var admin models.Admin
	result := h.DB.Where("username = ?", req.Username).First(&admin)

	// Admin Check & Legacy/Default Fallback logic (Optional, based on requirements)
	// If DB is empty or user not found, we might want to support default creds for initial setup.
	// But since we are adding security, let's enforce DB user.
	// If first run, maybe seed DB in main or here?
	// For simplicity, sticking to the plan: Check DB.

	if result.Error != nil {
		// Mock logic: If no users exist, allow default login to create one?
		// Better approach: If username is "admin" and password "admin123!" and NO admins exist.
		var count int64
		h.DB.Model(&models.Admin{}).Count(&count)
		if count == 0 && req.Username == "admin" && req.Password == "admin123!" {
			// Allow login, but maybe prompt to change pw?
			// Just Generate Token
			goto GenerateToken
		}
		return c.Status(401).JSON(fiber.Map{"error": "Invalid credentials"})
	}

	// Check Lock
	if admin.LockedUntil != nil && time.Now().Before(*admin.LockedUntil) {
		minutes := int(time.Until(*admin.LockedUntil).Minutes()) + 1
		return c.Status(403).JSON(fiber.Map{"error": "Account is locked. Try again in " + string(rune(minutes+'0')) + " minutes."})
	}

	// Verify Password
	err = bcrypt.CompareHashAndPassword([]byte(admin.Password), []byte(req.Password))
	if err != nil {
		// Handle Plaintext password (migration)
		if admin.Password == req.Password {
			// It was plaintext, upgrade to hash
			hashed, _ := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
			admin.Password = string(hashed)
			admin.FailedAttempts = 0
			admin.LockedUntil = nil
			h.DB.Save(&admin)
			goto GenerateToken
		}

		// Failed Login
		admin.FailedAttempts++
		now := time.Now()
		admin.LastFailedAttempt = &now
		if admin.FailedAttempts >= 5 {
			lockUntil := now.Add(5 * time.Minute)
			admin.LockedUntil = &lockUntil
		}
		h.DB.Save(&admin)

		msg := "Invalid credentials"
		if admin.FailedAttempts >= 5 {
			msg = "Account locked for 5 minutes"
		}
		return c.Status(401).JSON(fiber.Map{"error": msg})
	}

	// Success
	admin.FailedAttempts = 0
	admin.LockedUntil = nil
	h.DB.Save(&admin)

GenerateToken:
	// Generate JWT
	claims := jwt.MapClaims{
		"user": req.Username,
		"exp":  time.Now().Add(time.Hour * 24).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	t, err := token.SignedString(jwtSecret)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Could not login"})
	}

	return c.JSON(fiber.Map{"token": t})
}

// ChangePassword handler
func (h *Handler) ChangePassword(c *fiber.Ctx) error {
	user := c.Locals("user").(*jwt.Token)
	claims := user.Claims.(jwt.MapClaims)
	username := claims["user"].(string)

	var req struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid input"})
	}

	var admin models.Admin
	if err := h.DB.Where("username = ?", username).First(&admin).Error; err != nil {
		// If user doesn't exist in DB (e.g. was default admin), creating...
		// But verify "default" old password if we want to be strict, or just allow it.
		// Let's enforce that to change password, you must exist or utilize the default logic hole.
		// If using default "admin" and DB is empty:
		var count int64
		h.DB.Model(&models.Admin{}).Count(&count)
		if count == 0 && username == "admin" && req.OldPassword == "admin123!" {
			hashed, _ := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
			admin = models.Admin{Username: username, Password: string(hashed)}
			h.DB.Create(&admin)
			return c.JSON(fiber.Map{"message": "Password updated"})
		}
		return c.Status(404).JSON(fiber.Map{"error": "User not found"})
	}

	// Verify Old Password
	// Check hash
	if err := bcrypt.CompareHashAndPassword([]byte(admin.Password), []byte(req.OldPassword)); err != nil {
		// Check plain (migration)
		if admin.Password != req.OldPassword {
			return c.Status(401).JSON(fiber.Map{"error": "Incorrect old password"})
		}
	}

	// Save New Password
	hashed, _ := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	admin.Password = string(hashed)
	// Reset locks if any (implicit because they are logged in, but just in case)
	admin.FailedAttempts = 0
	admin.LockedUntil = nil

	h.DB.Save(&admin)

	return c.JSON(fiber.Map{"message": "Password updated"})
}

// Simple Auth Middleware
func AuthMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// In production use jwtware
		return c.Next()
	}
}
