//go:build linux

package services

import (
	"context"
	"fmt"
	"kg-proxy-web-gui/backend/system"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

type LinuxPCAPService struct {
	mu         sync.Mutex
	status     PCAPStatus
	cancelFunc context.CancelFunc
	cmd        *exec.Cmd
	captureDir string
}

func newLinuxPCAPService() *LinuxPCAPService {
	dir := getCaptureDir()
	if err := os.MkdirAll(dir, 0755); err != nil {
		system.Warn("Failed to create capture directory: %v", err)
	}

	return &LinuxPCAPService{
		captureDir: dir,
		status:     PCAPStatus{IsCapturing: false},
	}
}

func (s *LinuxPCAPService) StartCapture(interfaceName string, duration time.Duration, filter string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.status.IsCapturing {
		return "", fmt.Errorf("capture already in progress")
	}

	// Validate interface
	if interfaceName == "" {
		interfaceName = system.GetDefaultInterface()
	}

	// Generate filename
	timestamp := time.Now().Format("20060102-150405")
	filename := fmt.Sprintf("capture_%s.pcap", timestamp)
	fullPath := filepath.Join(s.captureDir, filename)

	// Prepare context with timeout
	// Default to 5 minutes if 0 provided to prevent disk fill
	if duration == 0 {
		duration = 5 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), duration)
	s.cancelFunc = cancel

	// Prepare command
	// tcpdump -i <interface> -w <file> <filter>
	// -U: Packet-buffered output
	// -n: Don't convert addresses to names
	args := []string{"-i", interfaceName, "-w", fullPath, "-U", "-n"}
	if filter != "" {
		args = append(args, filter)
	}

	cmd := exec.CommandContext(ctx, "tcpdump", args...)
	s.cmd = cmd

	if err := cmd.Start(); err != nil {
		cancel()
		return "", fmt.Errorf("failed to start tcpdump: %w", err)
	}

	// Update status
	s.status = PCAPStatus{
		IsCapturing:   true,
		StartTime:     time.Now(),
		CurrentFile:   filename,
		InterfaceName: interfaceName,
		Filter:        filter,
	}

	// Monitor process in background
	go func() {
		err := cmd.Wait()
		s.mu.Lock()
		defer s.mu.Unlock()

		// Check if we were manually stopped (cancelFunc called) vs natural exit
		// But in both cases, we are no longer capturing
		s.status.IsCapturing = false
		s.status.Duration = time.Since(s.status.StartTime).String()
		s.cmd = nil
		s.cancelFunc = nil // Clear cancel func

		if err != nil {
			// Check if it was a timeout (deadline exceeded)
			if ctx.Err() == context.DeadlineExceeded {
				system.Info("PCAP capture finished (timeout reached): %s", filename)
			} else if ctx.Err() == context.Canceled {
				system.Info("PCAP capture stopped manually: %s", filename)
			} else {
				system.Warn("PCAP capture exited with error: %v", err)
			}
		} else {
			system.Info("PCAP capture finished successfully: %s", filename)
		}
	}()

	return filename, nil
}

func (s *LinuxPCAPService) StopCapture() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.status.IsCapturing || s.cancelFunc == nil {
		return fmt.Errorf("no capture in progress")
	}

	// Cancel the context, which sends SIGKILL/SIGTERM to the command
	s.cancelFunc()
	return nil
}

func (s *LinuxPCAPService) IsCapturing() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.status.IsCapturing
}

func (s *LinuxPCAPService) GetStatus() PCAPStatus {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Update duration on the fly if capturing
	if s.status.IsCapturing {
		s.status.Duration = time.Since(s.status.StartTime).String()
	}
	return s.status
}

func (s *LinuxPCAPService) GetCaptureFiles() ([]string, error) {
	files, err := os.ReadDir(s.captureDir)
	if err != nil {
		return nil, err
	}

	var filenames []string
	for _, f := range files {
		if !f.IsDir() && filepath.Ext(f.Name()) == ".pcap" {
			filenames = append(filenames, f.Name())
		}
	}

	// Sort by modification time (newest first)
	sort.Slice(filenames, func(i, j int) bool {
		fi, _ := os.Stat(filepath.Join(s.captureDir, filenames[i]))
		fj, _ := os.Stat(filepath.Join(s.captureDir, filenames[j]))
		return fi.ModTime().After(fj.ModTime())
	})

	return filenames, nil
}

func (s *LinuxPCAPService) DeleteCaptureFile(filename string) error {
	// Sanity check to prevent directory traversal
	if filepath.Dir(filename) != "." {
		return fmt.Errorf("invalid filename")
	}
	return os.Remove(filepath.Join(s.captureDir, filename))
}

func (s *LinuxPCAPService) GetCaptureDir() string {
	return s.captureDir
}
