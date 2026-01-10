package services

import (
	"fmt"
	"kg-proxy-web-gui/backend/system"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// SysInfoService provides real system information on Linux, mock on Windows
type SysInfoService struct{}

func NewSysInfoService() *SysInfoService {
	return &SysInfoService{}
}

// GetUptime returns system uptime as human-readable string
func (s *SysInfoService) GetUptime() string {
	if runtime.GOOS != "linux" {
		return "0d 0h 0m (Mock)"
	}

	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return "Unknown"
	}

	parts := strings.Fields(string(data))
	if len(parts) < 1 {
		return "Unknown"
	}

	seconds, err := strconv.ParseFloat(parts[0], 64)
	if err != nil {
		return "Unknown"
	}

	duration := time.Duration(seconds) * time.Second
	days := int(duration.Hours()) / 24
	hours := int(duration.Hours()) % 24
	minutes := int(duration.Minutes()) % 60

	return fmt.Sprintf("%dd %dh %dm", days, hours, minutes)
}

// GetBootTime returns the estimated system boot time
func GetBootTime() time.Time {
	if runtime.GOOS != "linux" {
		// Mock for windows
		return time.Now().Add(-1 * time.Hour)
	}

	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return time.Now()
	}

	parts := strings.Fields(string(data))
	if len(parts) < 1 {
		return time.Now()
	}

	seconds, err := strconv.ParseFloat(parts[0], 64)
	if err != nil {
		return time.Now()
	}

	return time.Now().Add(-time.Duration(seconds * float64(time.Second)))
}

// GetCPUUsage returns current CPU usage percentage (0-100)
func (s *SysInfoService) GetCPUUsage() int {
	if runtime.GOOS != "linux" {
		return 0
	}

	// Read initial CPU stats
	idle1, total1 := s.readCPUStat()
	time.Sleep(100 * time.Millisecond)
	idle2, total2 := s.readCPUStat()

	idleDelta := idle2 - idle1
	totalDelta := total2 - total1

	if totalDelta == 0 {
		return 0
	}

	usage := 100 * (1.0 - float64(idleDelta)/float64(totalDelta))
	return int(usage)
}

func (s *SysInfoService) readCPUStat() (idle, total uint64) {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0, 0
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "cpu ") {
			fields := strings.Fields(line)
			if len(fields) < 5 {
				return 0, 0
			}
			for i := 1; i < len(fields); i++ {
				val, _ := strconv.ParseUint(fields[i], 10, 64)
				total += val
				if i == 4 { // idle is the 4th value (index 4)
					idle = val
				}
			}
			return idle, total
		}
	}
	return 0, 0
}

// GetMemoryUsage returns current memory usage percentage (0-100)
func (s *SysInfoService) GetMemoryUsage() int {
	if runtime.GOOS != "linux" {
		return 0
	}

	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}

	var memTotal, memAvailable uint64
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		val, _ := strconv.ParseUint(fields[1], 10, 64)
		switch fields[0] {
		case "MemTotal:":
			memTotal = val
		case "MemAvailable:":
			memAvailable = val
		}
	}

	if memTotal == 0 {
		return 0
	}

	used := memTotal - memAvailable
	return int((float64(used) / float64(memTotal)) * 100)
}

// GetDiskUsage returns root partition disk usage percentage
func (s *SysInfoService) GetDiskUsage() int {
	if runtime.GOOS != "linux" {
		return 0
	}

	out, err := exec.Command("df", "-h", "/").Output()
	if err != nil {
		return 0
	}

	lines := strings.Split(string(out), "\n")
	if len(lines) < 2 {
		return 0
	}

	fields := strings.Fields(lines[1])
	if len(fields) < 5 {
		return 0
	}

	// Fields[4] is like "35%"
	usage := strings.TrimSuffix(fields[4], "%")
	val, _ := strconv.Atoi(usage)
	return val
}

// GetActiveConnections returns number of established network connections
func (s *SysInfoService) GetActiveConnections() int {
	if runtime.GOOS != "linux" {
		return 0
	}

	// Use ss command to count established connections
	out, err := exec.Command("ss", "-t", "-n", "state", "established").Output()
	if err != nil {
		// Fallback to netstat
		out, err = exec.Command("netstat", "-tn").Output()
		if err != nil {
			return 0
		}
	}

	lines := strings.Split(string(out), "\n")
	count := 0
	for _, line := range lines {
		if strings.Contains(line, "ESTAB") || strings.Contains(strings.ToUpper(line), "ESTABLISHED") {
			count++
		}
	}

	// If using ss, count non-header lines
	if count == 0 && len(lines) > 1 {
		count = len(lines) - 2 // Subtract header and empty line
		if count < 0 {
			count = 0
		}
	}

	return count
}

// GetNetworkIO returns network RX/TX bytes for primary interface
func (s *SysInfoService) GetNetworkIO() (rxBytes, txBytes uint64) {
	if runtime.GOOS != "linux" {
		return 0, 0
	}

	// Read /proc/net/dev
	data, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return 0, 0
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		// Skip loopback and header
		if strings.Contains(line, "lo:") || !strings.Contains(line, ":") {
			continue
		}

		// Parse interface stats
		parts := strings.Split(line, ":")
		if len(parts) < 2 {
			continue
		}

		fields := strings.Fields(parts[1])
		if len(fields) < 9 {
			continue
		}

		rx, _ := strconv.ParseUint(fields[0], 10, 64)
		tx, _ := strconv.ParseUint(fields[8], 10, 64)

		// Return first non-loopback interface
		return rx, tx
	}

	return 0, 0
}

// GetPublicIP returns the server's public IP address
func (s *SysInfoService) GetPublicIP() string {
	if runtime.GOOS != "linux" {
		return "127.0.0.1"
	}

	// Try to use curl to get public IP
	out, err := exec.Command("curl", "-s", "--max-time", "3", "https://icanhazip.com").Output()
	if err == nil && len(out) > 0 {
		return strings.TrimSpace(string(out))
	}

	// Fallback: try ipify
	out, err = exec.Command("curl", "-s", "--max-time", "3", "https://api.ipify.org").Output()
	if err == nil && len(out) > 0 {
		return strings.TrimSpace(string(out))
	}

	// Fallback: hostname -I (first IP)
	out, err = exec.Command("hostname", "-I").Output()
	if err == nil && len(out) > 0 {
		parts := strings.Fields(string(out))
		if len(parts) > 0 {
			return parts[0]
		}
	}

	return "0.0.0.0"
}

// GetPrimaryInterface returns the name of the primary network interface (e.g. eth0, ens3)
func (s *SysInfoService) GetPrimaryInterface() string {
	return system.GetDefaultInterface()
}
