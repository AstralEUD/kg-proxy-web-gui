package handlers

import (
	"kg-proxy-web-gui/backend/services"
	"kg-proxy-web-gui/backend/system"
	"path/filepath"
	"time"

	"github.com/gofiber/fiber/v2"
)

// SetupPCAPRoutes registers PCAP related routes
func SetupPCAPRoutes(router fiber.Router) {
	pcap := router.Group("/pcap")

	pcap.Post("/start", StartCapture)
	pcap.Post("/stop", StopCapture)
	pcap.Get("/status", GetCaptureStatus)
	pcap.Get("/files", ListCaptureFiles)
	pcap.Get("/files/:filename", DownloadCaptureFile)
	pcap.Delete("/files/:filename", DeleteCaptureFile)
}

// StartCaptureRequest
type StartCaptureRequest struct {
	Interface string `json:"interface"`
	Duration  int    `json:"duration"` // Seconds
	Filter    string `json:"filter"`
}

// StartCapture starts a new packet capture
func StartCapture(c *fiber.Ctx) error {
	var req StartCaptureRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request body"})
	}

	svc := services.NewPCAPService()
	duration := time.Duration(req.Duration) * time.Second
	if duration == 0 {
		duration = 60 * time.Second // Default 1 min
	}

	filename, err := svc.StartCapture(req.Interface, duration, req.Filter)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	system.Info("Started PCAP capture on %s for %v", req.Interface, duration)
	return c.JSON(fiber.Map{
		"message":   "Capture started",
		"filename":  filename,
		"interface": req.Interface,
	})
}

// StopCapture stops the current capture
func StopCapture(c *fiber.Ctx) error {
	svc := services.NewPCAPService()
	if err := svc.StopCapture(); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	return c.JSON(fiber.Map{"message": "Capture stopped"})
}

// GetCaptureStatus returns current status
func GetCaptureStatus(c *fiber.Ctx) error {
	svc := services.NewPCAPService()
	return c.JSON(svc.GetStatus())
}

// ListCaptureFiles lists all pcap files
func ListCaptureFiles(c *fiber.Ctx) error {
	svc := services.NewPCAPService()
	files, err := svc.GetCaptureFiles()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(files)
}

// DownloadCaptureFile downloads a specific file
func DownloadCaptureFile(c *fiber.Ctx) error {
	filename := c.Params("filename")
	if filename == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Filename required"})
	}

	svc := services.NewPCAPService()
	captureDir := svc.GetCaptureDir()
	fullPath := filepath.Join(captureDir, filename)

	// Security check (prevent directory traversal)
	// Clean path and ensure it starts with captureDir
	if filepath.Dir(fullPath) != filepath.Clean(captureDir) {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "Invalid file path"})
	}

	return c.Download(fullPath)
}

// DeleteCaptureFile deletes a specific file
func DeleteCaptureFile(c *fiber.Ctx) error {
	filename := c.Params("filename")
	if filename == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Filename required"})
	}

	svc := services.NewPCAPService()
	if err := svc.DeleteCaptureFile(filename); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	return c.JSON(fiber.Map{"message": "File deleted"})
}
