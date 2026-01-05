package handlers

import (
	"kg-proxy-web-gui/backend/models"
	"kg-proxy-web-gui/backend/system"
	"strings"
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

	if result.Error != nil {
		// If no users exist, allow default login
		var count int64
		h.DB.Model(&models.Admin{}).Count(&count)
		if count == 0 && req.Username == "admin" && req.Password == "admin123!" {
			// Create the user so it persists and shows up in User Management
			hashed, _ := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
			admin = models.Admin{Username: req.Username, Password: string(hashed)}
			if err := h.DB.Create(&admin).Error; err != nil {
				system.Error("Failed to create default admin user: %v", err)
			} else {
				system.Info("Default admin login - Created persistent 'admin' user")
			}
			goto GenerateToken
		}
		system.Warn("Failed login attempt for user: %s", req.Username)
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
		system.Warn("Failed login attempt for user: %s (attempt %d)", req.Username, admin.FailedAttempts)
		return c.Status(401).JSON(fiber.Map{"error": msg})
	}

	// Success
	admin.FailedAttempts = 0
	admin.LockedUntil = nil
	h.DB.Save(&admin)
	system.Info("User logged in: %s", req.Username)

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

	AddEvent("success", "User logged in: "+req.Username)
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
	if err := bcrypt.CompareHashAndPassword([]byte(admin.Password), []byte(req.OldPassword)); err != nil {
		if admin.Password != req.OldPassword {
			return c.Status(401).JSON(fiber.Map{"error": "Incorrect old password"})
		}
	}

	// Save New Password
	hashed, _ := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	admin.Password = string(hashed)
	admin.FailedAttempts = 0
	admin.LockedUntil = nil

	h.DB.Save(&admin)
	system.Info("User changed password: %s", username)

	return c.JSON(fiber.Map{"message": "Password updated"})
}

// JWTAuthMiddleware validates JWT token
func JWTAuthMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		authHeader := c.Get("Authorization")
		if authHeader == "" {
			return c.Status(401).JSON(fiber.Map{"error": "Missing authorization header"})
		}

		// Check Bearer prefix
		if !strings.HasPrefix(authHeader, "Bearer ") {
			return c.Status(401).JSON(fiber.Map{"error": "Invalid authorization format"})
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")

		// Parse and validate token
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fiber.NewError(401, "Invalid signing method")
			}
			return jwtSecret, nil
		})

		if err != nil || !token.Valid {
			return c.Status(401).JSON(fiber.Map{"error": "Invalid or expired token"})
		}

		// Store token in context for handlers
		c.Locals("user", token)

		return c.Next()
	}
}
