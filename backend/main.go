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
	sysConfig := &models.SystemConfig{} // Load from file in real app

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

	app.Use(cors.New()) // Allow Frontend to access

	api := app.Group("/api")

	// Auth
	api.Post("/login", h.Login)
	api.Put("/auth/password", h.ChangePassword) // Needs middleware in real app

	// Origins
	api.Get("/origins", h.GetOrigins)
	api.Post("/origins", h.CreateOrigin)

	// Firewall
	api.Post("/firewall/apply", h.ApplyFirewall)
	api.Get("/firewall/status", h.GetFirewallStatus)

	// System Status
	api.Get("/status", h.GetSystemStatus)
	api.Get("/events", h.GetEvents)

	// WireGuard
	api.Get("/wireguard/status", h.GetWireGuardStatus)

	// User Management
	api.Get("/users", h.GetUsers)
	api.Post("/users", h.CreateUser)
	api.Delete("/users/:id", h.DeleteUser)

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
