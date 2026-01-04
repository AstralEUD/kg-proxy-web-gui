package main

import (
	"kg-proxy-web-gui/backend/handlers"
	"kg-proxy-web-gui/backend/models"
	"kg-proxy-web-gui/backend/services"
	"kg-proxy-web-gui/backend/system"
	"log"
	"os"
	"path/filepath"

	"github.com/glebarez/sqlite"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"gorm.io/gorm"
)

func main() {
	// 0. Initialize Logger
	logDir := "./logs"
	if _, err := os.Stat("/opt/kg-proxy"); err == nil {
		logDir = "/opt/kg-proxy/logs"
	}
	if err := system.InitLogger(logDir); err != nil {
		log.Printf("Warning: Could not initialize file logger: %v", err)
	}
	defer system.Close()

	system.Info("KG-Proxy backend starting...")

	// 1. Setup Database
	dbPath := "armaguard.db"
	if _, err := os.Stat("/opt/kg-proxy"); err == nil {
		dbPath = "/opt/kg-proxy/armaguard.db"
	}

	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		system.Error("Failed to connect to database: %v", err)
		log.Fatal("Failed to connect to database:", err)
	}
	system.Info("Database connected: %s", dbPath)

	// Migrate
	db.AutoMigrate(&models.Origin{}, &models.Service{}, &models.AllowForeign{}, &models.BanIP{}, &models.WireGuardPeer{}, &models.Admin{}, &models.SecuritySettings{})

	// 2. Setup Services
	executor := system.NewExecutor()
	sysConfig := &models.SystemConfig{}

	wgService := services.NewWireGuardService(executor, sysConfig)
	fwService := services.NewFirewallService(db, executor)

	// 3. Setup Handlers
	h := handlers.NewHandler(db, wgService, fwService)

	// 4. Setup Fiber
	app := fiber.New(fiber.Config{
		DisableStartupMessage: false,
	})

	// Add request logging middleware
	app.Use(logger.New(logger.Config{
		Format:     "${time} | ${status} | ${latency} | ${ip} | ${method} ${path}\n",
		TimeFormat: "2006-01-04 15:04:05",
		Output:     os.Stdout,
	}))

	app.Use(cors.New())

	api := app.Group("/api")

	// ===== Public Routes (No Auth Required) =====
	api.Post("/login", h.Login)

	// ===== Protected Routes (JWT Required) =====
	protected := api.Group("", handlers.JWTAuthMiddleware())

	// Auth
	protected.Put("/auth/password", h.ChangePassword)

	// Origins
	protected.Get("/origins", h.GetOrigins)
	protected.Post("/origins", h.CreateOrigin)
	protected.Delete("/origins/:id", h.DeleteOrigin)

	// Firewall
	protected.Post("/firewall/apply", h.ApplyFirewall)
	protected.Get("/firewall/status", h.GetFirewallStatus)

	// System Status
	protected.Get("/status", h.GetSystemStatus)
	protected.Get("/events", h.GetEvents)

	// WireGuard
	protected.Get("/wireguard/status", h.GetWireGuardStatus)

	// User Management
	protected.Get("/users", h.GetUsers)
	protected.Post("/users", h.CreateUser)
	protected.Delete("/users/:id", h.DeleteUser)

	// Services
	protected.Get("/services", h.GetServices)
	protected.Post("/services", h.CreateService)
	protected.Delete("/services/:id", h.DeleteService)

	// Security Settings
	protected.Get("/security/settings", h.GetSecuritySettings)
	protected.Put("/security/settings", h.UpdateSecuritySettings)

	// 5. Serve Static Files (Frontend)
	frontendPath := "./frontend/dist"
	if _, err := os.Stat("/opt/kg-proxy/frontend/dist"); err == nil {
		frontendPath = "/opt/kg-proxy/frontend/dist"
	} else if _, err := os.Stat("/opt/kg-proxy/frontend"); err == nil {
		frontendPath = "/opt/kg-proxy/frontend"
	}

	app.Static("/", frontendPath)

	// 6. SPA Fallback: Serve index.html for all other routes
	app.Get("/*", func(c *fiber.Ctx) error {
		return c.SendFile(filepath.Join(frontendPath, "index.html"))
	})

	// Start
	system.Info("Server starting on :8080 (Mode: %s)", executor.GetOS())
	log.Println("Server starting on :8080 (Mode: " + executor.GetOS() + ")")
	log.Fatal(app.Listen(":8080"))
}
