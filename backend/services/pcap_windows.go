//go:build windows

package services

import (
	"fmt"
	"os"
	"time"
)

type WindowsPCAPService struct {
	status PCAPStatus
}

// NewPCAPService creates a new instance of the Windows PCAP service (stub)
func NewPCAPService() PCAPService {
	pcapOnce.Do(func() {
		pcapInstance = newWindowsPCAPService()
	})
	return pcapInstance
}

func newWindowsPCAPService() *WindowsPCAPService {
	// Ensure capture directory exists even on Windows for consistency
	os.MkdirAll(getCaptureDir(), 0755)
	return &WindowsPCAPService{
		status: PCAPStatus{IsCapturing: false},
	}
}

func (s *WindowsPCAPService) StartCapture(interfaceName string, duration time.Duration, filter string) (string, error) {
	return "", fmt.Errorf("packet capture is not supported on Windows in this version")
}

func (s *WindowsPCAPService) StopCapture() error {
	return nil
}

func (s *WindowsPCAPService) IsCapturing() bool {
	return false
}

func (s *WindowsPCAPService) GetStatus() PCAPStatus {
	return s.status
}

func (s *WindowsPCAPService) GetCaptureFiles() ([]string, error) {
	return []string{}, nil
}

func (s *WindowsPCAPService) DeleteCaptureFile(filename string) error {
	return nil
}

func (s *WindowsPCAPService) GetCaptureDir() string {
	return getCaptureDir()
}
