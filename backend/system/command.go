package system

import (
	"fmt"
	"os/exec"
	"runtime"
)

// IsWindows returns true if the current OS is Windows
func IsWindows() bool {
	return runtime.GOOS == "windows"
}

type CommandExecutor interface {
	Execute(command string, args ...string) (string, error)
	GetOS() string
}

type RealExecutor struct{}

func (e *RealExecutor) Execute(command string, args ...string) (string, error) {
	cmd := exec.Command(command, args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (e *RealExecutor) GetOS() string {
	return runtime.GOOS
}

type MockExecutor struct{}

func (e *MockExecutor) Execute(command string, args ...string) (string, error) {
	// Simulate success for common commands
	fmt.Printf("[MockExecutor] Executing: %s %v\n", command, args)

	if command == "wg" && len(args) > 0 && args[0] == "genkey" {
		return "MB9k...MockPrivateKey...", nil
	}
	if command == "wg" && len(args) > 0 && args[0] == "pubkey" {
		return "PB9k...MockPublicKey...", nil
	}

	return "Mock Success", nil
}

func (e *MockExecutor) GetOS() string {
	return "mock-" + runtime.GOOS
}

func NewExecutor() CommandExecutor {
	if runtime.GOOS == "windows" {
		return &MockExecutor{}
	}
	return &RealExecutor{}
}

// Ping checks if an IP is reachable
func Ping(ip string) bool {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("ping", "-n", "1", "-w", "1000", ip)
	} else {
		cmd = exec.Command("ping", "-c", "1", "-W", "1", ip)
	}
	return cmd.Run() == nil
}

// GetDefaultInterface returns the default network interface name (e.g., "eth0", "ens3")
func GetDefaultInterface() string {
	if runtime.GOOS == "windows" {
		return "" // Not applicable on Windows
	}

	// Try to get default interface from ip route
	cmd := exec.Command("ip", "route", "show", "default")
	out, err := cmd.Output()
	if err != nil {
		return "eth0" // Fallback
	}

	// Parse "default via X.X.X.X dev eth0"
	fields := string(out)
	if len(fields) > 0 {
		// Simple parsing: look for "dev <interface>"
		parts := exec.Command("sh", "-c", "ip route show default | awk '/default/ {print $5}'")
		if iface, err := parts.Output(); err == nil && len(iface) > 0 {
			return string(iface[:len(iface)-1]) // Remove trailing newline
		}
	}

	return "eth0" // Default fallback
}
