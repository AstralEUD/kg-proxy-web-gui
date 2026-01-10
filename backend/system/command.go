package system

import (
	"fmt"
	"net"
	"os"
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

	// Method 1: Robust parsing of /proc/net/route to find default gateway
	data, err := os.ReadFile("/proc/net/route")
	if err == nil {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				// Field 0: Interface Name
				// Field 1: Destination (Hex)
				// Check for Default Gateway (Destination 00000000)
				if fields[1] == "00000000" {
					return fields[0]
				}
			}
		}
	}

	// Method 2: Fallback to net.Interfaces() heuristic
	ifaces, err := net.Interfaces()
	if err != nil {
		return "eth0"
	}

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

	// Last resort
	return "eth0"
}
