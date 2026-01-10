package system

import (
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strings"
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

// GetDefaultInterface returns the default network interface name (e.g., "eth0", "enp1s0")
func GetDefaultInterface() string {
	if runtime.GOOS == "windows" {
		return ""
	}

	// 1. Get all interfaces
	ifaces, err := net.Interfaces()
	if err != nil {
		return "eth0"
	}

	// 2. Look for the first non-loopback interface that is up
	// and likely has the default gateway (usually eth0, ens3, enp1s0, etc.)
	for _, iface := range ifaces {
		// Skip loopback and down interfaces
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}

		// Skip WireGuard and virtual interfaces
		name := strings.ToLower(iface.Name)
		if strings.HasPrefix(name, "wg") || strings.HasPrefix(name, "lo") || strings.HasPrefix(name, "docker") || strings.HasPrefix(name, "br-") {
			continue
		}

		// Most VPS use ethX, ensX, enpX
		if strings.HasPrefix(name, "eth") || strings.HasPrefix(name, "en") || strings.HasPrefix(name, "es") {
			return iface.Name
		}
	}

	return "eth0" // Final fallback
}
