package services

import (
	"path/filepath"
	"sync"
	"time"
)

// PCAPService defines the interface for packet capture
type PCAPService interface {
	StartCapture(interfaceName string, duration time.Duration, filter string) (string, error)
	StopCapture() error
	IsCapturing() bool
	GetStatus() PCAPStatus
	GetCaptureFiles() ([]string, error)
	DeleteCaptureFile(filename string) error
	GetCaptureDir() string
}

// PCAPStatus holds the current status of the capture service
type PCAPStatus struct {
	IsCapturing   bool      `json:"is_capturing"`
	StartTime     time.Time `json:"start_time"`
	Duration      string    `json:"duration"` // formatted string
	CurrentFile   string    `json:"current_file"`
	InterfaceName string    `json:"interface_name"`
	Filter        string    `json:"filter"`
}

var (
	pcapInstance PCAPService
	pcapOnce     sync.Once
)

// NewPCAPService is now defined in pcap_linux.go and pcap_windows.go
// to ensure compile-time safety.

// Common helper to get capture directory
func getCaptureDir() string {
	// In a real app this might be configurable
	return filepath.Join(".", "captures")
}
