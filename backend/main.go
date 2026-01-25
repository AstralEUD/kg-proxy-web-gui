package main

import (
	"fmt"
	"kg-proxy-web-gui/backend/handlers"
	"kg-proxy-web-gui/backend/models"
	"kg-proxy-web-gui/backend/services"
	"kg-proxy-web-gui/backend/system"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"syscall"
	"time"

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

	// Optimization: Enable WAL Mode for better concurrency
	// This prevents "database is locked" errors during high traffic/logging
	if err := db.Exec("PRAGMA journal_mode=WAL;").Error; err != nil {
		system.Warn("Failed to enable WAL mode: %v", err)
	} else {
		system.Info("SQLite WAL mode enabled")
	}

	// Optimization: Tuning GC for high throughput (v1.8.0 Restoration)
	// Set GC percentage to 500% to reduce GC frequency at cost of higher RAM usage.
	// This is critical for preventing latency spikes during traffic floods.
	debug.SetGCPercent(500)
	system.Info("GC Optimization enabled (GOGC=500)")

	// Migrate
	// Migrate
	// CRITICAL: Ensure schema is up to date. Panic if migration fails.
	if err := db.AutoMigrate(
		&models.Origin{},
		&models.Service{},
		&models.ServicePort{},
		&models.AllowForeign{},
		&models.BanIP{},
		&models.AllowIP{},
		&models.WireGuardPeer{},
		&models.Admin{},
		&models.SecuritySettings{},
		&models.TrafficSnapshot{},
		&models.AttackEvent{},
		&models.AttackEvent{},
		&models.AttackSignature{},
		&models.CountryGroup{},
	); err != nil {
		system.Error("Database migration failed: %v", err)
		log.Fatalf("CRITICAL: Database migration failed. Application cannot start: %v", err)
	}
	system.Info("Database migration completed successfully")

	// Seed default attack signatures if empty
	var sigCount int64
	db.Model(&models.AttackSignature{}).Count(&sigCount)
	if sigCount == 0 {
		for _, sig := range models.SeedDefaultSignatures() {
			if err := db.Create(&sig).Error; err != nil {
				system.Warn("Failed to seed signature %s: %v", sig.Name, err)
			}
		}
		system.Info("Seeded %d default attack signatures", len(models.SeedDefaultSignatures()))
	}

	// 2. Setup Services
	executor := system.NewExecutor()
	sysConfig := &models.SystemConfig{}

	// Initialize GeoIP service
	geoipService := services.NewGeoIPService()
	geoipService.StartAutoUpdateScheduler() // Start weekly auto-refresh
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

	// Sync Peers (Restore connectivity for existing Origins)
	var origins []models.Origin
	if err := db.Preload("Peer").Find(&origins).Error; err != nil {
		system.Warn("Failed to fetch origins for peer sync: %v", err)
	} else {
		if err := wgService.SyncOriginsToPeers(origins); err != nil {
			system.Warn("Failed to sync WireGuard peers: %v", err)
		}
	}

	fwService := services.NewFirewallService(db, executor, geoipService, floodProtect)
	fwService.StartMaintenanceWatcher()

	// Load MaxMind license key from DB if available (using settings fetched above)
	if settings.MaxMindLicenseKey != "" {
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

	// Set IP Intelligence API Key
	if settings.IPIntelligenceAPIKey != "" {
		geoipService.SetIPInfoAPIKey(settings.IPIntelligenceAPIKey)
		system.Info("IP Intelligence API Key configured")
	}

	ebpfService := services.NewEBPFService()
	ebpfService.SetGeoIPService(geoipService) // Connect GeoIP to eBPF
	ebpfService.SetDatabase(db)               // Connect DB for traffic snapshots

	// Connect Firewall to eBPF for coordinated maintenance mode
	fwService.SetEBPF(ebpfService)

	// 4. Initial Firewall Application
	// This ensures management ports are open even if the DB was empty
	// CRITICAL: This must run BEFORE eBPF Enable to ensure GeoIP CIDRs are downloaded and ready
	system.Info("Applying initial firewall rules...")
	if err := fwService.ApplyRules(); err != nil {
		system.Error("Failed to apply initial firewall rules: %v", err)
	}

	// Always try to enable eBPF XDP monitoring
	// CRITICAL: Fail if eBPF cannot be loaded
	if err := ebpfService.Enable(); err != nil {
		system.Error("Failed to enable eBPF service: %v", err)
		// Need to crash explicitly so the user knows it failed (no silent failure)
		log.Fatalf("CRITICAL: eBPF initialization failed. Application cannot start: %v", err)
	} else {
		system.Info("eBPF XDP monitoring enabled successfully")
	}

	// Start traffic stats auto-reset loop
	ebpfService.StartAutoResetLoop(db)

	// Apply saved eBPF configuration
	if ebpfService.IsEnabled() {
		ebpfService.UpdateConfig(settings.XDPHardBlocking, settings.XDPRateLimitPPS)
	}

	// Initialize Webhook Service
	webhookService := services.NewWebhookService()
	if settings.DiscordWebhookURL != "" {
		webhookService.SetWebhookURL(settings.DiscordWebhookURL)
		system.Info("Discord webhook configured")
	}

	// Initialize System Monitor
	sysMonitor := services.NewSystemMonitor(webhookService)
	sysMonitor.Start()

	// Initialize Daily Traffic Reporter
	dailyReporter := services.NewDailyReporter(db, webhookService)
	dailyReporter.Start()

	// Initialize Health Monitor (Origin Connectivity)
	healthMonitor := services.NewHealthMonitor(db, webhookService)
	healthMonitor.Start()

	// Set Webhook for GeoIP Alerts
	geoipService.SetWebhookService(webhookService)

	// Connect dependencies for Flood Protection (Logging & Alerts)
	floodProtect.SetServices(db, webhookService, geoipService)

	// 3. Setup Handlers
	h := handlers.NewHandler(db, wgService, fwService, ebpfService, webhookService)

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
	api.Post("/services", h.CreateService)
	api.Put("/services/:id", h.UpdateService)
	api.Delete("/services/:id", h.DeleteService)

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
	// IP Intelligence
	protected.Get("/ip/info/:ip", h.GetIPInfo)

	// Country Groups
	protected.Get("/security/countries/groups", h.GetCountryGroups)
	protected.Post("/security/countries/groups", h.CreateCountryGroup)
	protected.Put("/security/countries/groups/:id", h.UpdateCountryGroup)
	protected.Delete("/security/countries/groups/:id", h.DeleteCountryGroup)

	// Traffic Data (eBPF)
	protected.Get("/traffic/data", h.GetTrafficData)
	protected.Post("/traffic/reset", h.ResetTrafficStats)
	protected.Get("/traffic/history", h.GetTrafficHistory)
	protected.Get("/traffic/ports", h.GetPortStats)
	// Blocked IP Management
	protected.Get("/traffic/blocked", h.GetBlockedIPList)
	protected.Delete("/traffic/blocked", h.UnblockIP)

	// Diagnostics / Tools
	protected.Post("/tools/ping", h.RunPing)
	protected.Post("/tools/traceroute", h.RunTraceroute)
	protected.Get("/tools/wg-ping", h.CheckWireGuardConnectivity)

	// Attack History
	protected.Get("/attacks", h.GetAttackHistory)
	protected.Get("/attacks/stats", h.GetAttackStats)

	// Attack Signatures
	protected.Get("/signatures", h.GetSignatures)
	protected.Post("/signatures", h.CreateSignature)
	protected.Put("/signatures/:id", h.UpdateSignature)
	protected.Delete("/signatures/:id", h.DeleteSignature)
	protected.Post("/signatures/reset-stats", h.ResetSignatureStats)

	// Webhook
	protected.Post("/webhook/test", h.TestWebhook)

	// Backup & Restore
	protected.Get("/backup/export", h.ExportConfig)
	protected.Post("/backup/import", h.ImportConfig)

	// Server Info (Public IP, etc.)
	protected.Get("/server/info", h.GetServerInfo)

	// PCAP (Packet Capture)
	handlers.SetupPCAPRoutes(protected)

	// 5. Serve Static Files (Frontend)
	frontendPath := "./frontend/dist"
	if _, err := os.Stat("/opt/kg-proxy/frontend/dist"); err == nil {
		frontendPath = "/opt/kg-proxy/frontend/dist"
	} else if _, err := os.Stat("/opt/kg-proxy/frontend"); err == nil {
		frontendPath = "/opt/kg-proxy/frontend"
	}

	app.Static("/", frontendPath, fiber.Static{
		ByteRange: true,
		Browse:    false,
		MaxAge:    3600, // Cache for 1 hour to reduce reload strain
	})

	// 6. SPA Fallback: Serve index.html for all other routes
	app.Get("/*", func(c *fiber.Ctx) error {
		return c.SendFile(filepath.Join(frontendPath, "index.html"))
	})

	// Start
	system.Info("Server starting on :8080 (Mode: %s)", executor.GetOS())
	log.Println("Server starting on :8080 (Mode: " + executor.GetOS() + ")")

	// Send Startup Alert
	go func() {
		// Wait a bit for server to be fully up
		time.Sleep(2 * time.Second)
		if webhookService.IsEnabled() {
			sysInfo := services.NewSysInfoService()
			publicIP := sysInfo.GetPublicIP()
			msg := fmt.Sprintf("KG-Proxy backend is now running on **%s** (%s)\nPublic IP: `%s`",
				executor.GetOS(), time.Now().Format("2006-01-02 15:04:05"), publicIP)
			webhookService.SendSystemAlert("🚀 Server Started", msg, services.ColorGreen)
		}
	}()

	// Graceful Shutdown Handling
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-c // Wait for signal
		system.Info("Gracefully shutting down...")

		sysMonitor.Stop()

		// Disable XDP (detach filter) to ensure fail-open
		if ebpfService.IsEnabled() {
			ebpfService.Disable()
		}

		// Send Shutdown Alert
		if webhookService.IsEnabled() {
			webhookService.SendSystemAlert("🛑 Server Stopping", "KG-Proxy backend is shutting down...", services.ColorOrange)
		}

		_ = app.Shutdown()
	}()

	if err := app.Listen(":8080"); err != nil {
		log.Fatal(err)
	}
}
