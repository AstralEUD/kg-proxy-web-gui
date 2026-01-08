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
	// Migrate
	// CRITICAL: Ensure schema is up to date. Panic if migration fails.
	if err := db.AutoMigrate(&models.Origin{}, &models.Service{}, &models.ServicePort{}, &models.AllowForeign{}, &models.BanIP{}, &models.AllowIP{}, &models.WireGuardPeer{}, &models.Admin{}, &models.SecuritySettings{}); err != nil {
		system.Error("Database migration failed: %v", err)
		log.Fatalf("CRITICAL: Database migration failed. Application cannot start: %v", err)
	}
	system.Info("Database migration completed successfully")

	// 2. Setup Services
	executor := system.NewExecutor()
	sysConfig := &models.SystemConfig{}

	// Initialize GeoIP service
	geoipService := services.NewGeoIPService()
	system.Info("GeoIP service initialized")

	// Initialize Flood Protection
	var settings models.SecuritySettings
	protectionLevel := 2 // Default to high
	if err := db.First(&settings, 1).Error; err == nil {
		protectionLevel = settings.ProtectionLevel
	}
	floodProtect := services.NewFloodProtection(protectionLevel)
	system.Info("Flood protection initialized (level: %d)", protectionLevel)

	// Determine Data Directory
	dataDir := os.Getenv("KG_DATA_DIR")
	if dataDir == "" {
		dataDir = "." // Default to current dir if env not set
	}
	if _, err := os.Stat("/var/lib/kg-proxy"); err == nil && dataDir == "." {
		dataDir = "/var/lib/kg-proxy"
	}

	wgService := services.NewWireGuardService(executor, sysConfig, dataDir)
	// Initialize WireGuard Interface (Create wg0, assign IP, set key)
	if err := wgService.Init(); err != nil {
		system.Error("Failed to initialize WireGuard service: %v", err)
		// We continue, but warn heavily. Connectivity will likely fail.
	}

	fwService := services.NewFirewallService(db, executor, geoipService, floodProtect)

	// Load MaxMind license key from DB if available
	var settings models.SecuritySettings
	if err := db.First(&settings, 1).Error; err == nil && settings.MaxMindLicenseKey != "" {
		system.Info("Loading MaxMind license key from database...")
		geoipService.SetLicenseKey(settings.MaxMindLicenseKey)
		go func() {
			if err := geoipService.RefreshGeoIP(); err != nil {
				system.Warn("Failed to load GeoIP database: %v", err)
			} else {
				system.Info("GeoIP database loaded from MaxMind")
			}
		}()
	}

	ebpfService := services.NewEBPFService()
	ebpfService.SetGeoIPService(geoipService) // Connect GeoIP to eBPF

	// Always try to enable eBPF XDP monitoring
	// CRITICAL: Fail if eBPF cannot be loaded
	if err := ebpfService.Enable(); err != nil {
		system.Error("Failed to enable eBPF service: %v", err)
		// Need to crash explicitly so the user knows it failed (no silent failure)
		log.Fatalf("CRITICAL: eBPF initialization failed. Application cannot start: %v", err)
	} else {
		system.Info("eBPF XDP monitoring enabled successfully")
	}

	// 3. Setup Handlers
	h := handlers.NewHandler(db, wgService, fwService, ebpfService)

	// 4. Initial Firewall Application
	// This ensures management ports are open even if the DB was empty
	system.Info("Applying initial firewall rules...")
	if err := fwService.ApplyRules(); err != nil {
		system.Error("Failed to apply initial firewall rules: %v", err)
		// We don't log.Fatal here because the app might still be accessible via SSH/other means
		// but we want this recorded.
	}
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
	protected.Put("/origins/:id", h.UpdateOrigin)
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

	// IP Rules (Custom Whitelist/Blacklist)
	protected.Get("/security/rules", h.GetIPRules)
	protected.Post("/security/rules/allow", h.AddAllowIP)
	protected.Delete("/security/rules/allow/:id", h.DeleteAllowIP)
	protected.Post("/security/rules/block", h.AddBanIP)
	protected.Delete("/security/rules/block/:id", h.DeleteBanIP)
	protected.Get("/security/check/:ip", h.CheckIPStatus)

	// Traffic Data (eBPF)
	protected.Get("/traffic/data", h.GetTrafficData)

	// Server Info (Public IP, etc.)
	protected.Get("/server/info", h.GetServerInfo)

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
