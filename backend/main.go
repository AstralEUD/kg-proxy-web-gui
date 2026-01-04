package main

import (
	"kg-proxy-web-gui/backend/handlers"
	"kg-proxy-web-gui/backend/models"
	"kg-proxy-web-gui/backend/services"
	"kg-proxy-web-gui/backend/system"
	"log"

	"github.com/glebarez/sqlite"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"gorm.io/gorm"
)

func main() {
	// 1. Setup Database
	db, err := gorm.Open(sqlite.Open("armaguard.db"), &gorm.Config{})
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}

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
	app := fiber.New()

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
	// System Status
	api.Get("/status", h.GetSystemStatus)
	api.Get("/events", h.GetEvents)

	// User Management
	api.Get("/users", h.GetUsers)
	api.Post("/users", h.CreateUser)
	api.Delete("/users/:id", h.DeleteUser)

	// 5. Serve Static Files (Frontend)
	app.Static("/", "./frontend/dist")

	// 6. SPA Fallback: Serve index.html for all other routes
	app.Get("/*", func(c *fiber.Ctx) error {
		return c.SendFile("./frontend/dist/index.html")
	})

	// Start
	log.Println("Server starting on :8080 (Mock Mode: " + executor.GetOS() + ")")
	log.Fatal(app.Listen(":8080"))
}
