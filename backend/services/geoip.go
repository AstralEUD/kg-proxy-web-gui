package services

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"kg-proxy-web-gui/backend/system"
)

// GeoIPService provides IP geolocation and blocking capabilities
type GeoIPService struct {
	dbPath        string
	countryRanges map[string][]net.IPNet // country code -> IP ranges
	vpnRanges     []net.IPNet
	torExitNodes  []net.IP
	mu            sync.RWMutex
	lastUpdate    time.Time
}

func NewGeoIPService() *GeoIPService {
	service := &GeoIPService{
		dbPath:        "./geoip",
		countryRanges: make(map[string][]net.IPNet),
		vpnRanges:     make([]net.IPNet, 0),
		torExitNodes:  make([]net.IP, 0),
	}

	// Create directory if not exists
	os.MkdirAll(service.dbPath, 0755)

	// Load existing data or download
	go service.Initialize()

	return service
}

// Initialize loads or downloads GeoIP data
func (g *GeoIPService) Initialize() error {
	system.Info("Initializing GeoIP service...")

	// Try to load from disk first
	if err := g.loadFromDisk(); err == nil {
		system.Info("GeoIP data loaded from disk")
		return nil
	}

	// Download if not available
	system.Info("Downloading GeoIP data...")
	if err := g.downloadGeoIPData(); err != nil {
		system.Warn("Failed to download GeoIP data: %v", err)
		// Load minimal fallback data
		g.loadFallbackData()
	}

	// Download TOR exit nodes
	if err := g.downloadTORExitNodes(); err != nil {
		system.Warn("Failed to download TOR exit nodes: %v", err)
	}

	// Download VPN/Proxy ranges
	if err := g.downloadVPNRanges(); err != nil {
		system.Warn("Failed to download VPN ranges: %v", err)
	}

	g.saveToDisk()
	return nil
}

// IsCountryAllowed checks if an IP is from an allowed country
func (g *GeoIPService) IsCountryAllowed(ipStr string, allowedCountries []string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	g.mu.RLock()
	defer g.mu.RUnlock()

	// Check each allowed country
	for _, country := range allowedCountries {
		if ranges, ok := g.countryRanges[country]; ok {
			for _, ipRange := range ranges {
				if ipRange.Contains(ip) {
					return true
				}
			}
		}
	}

	return false
}

// IsVPN checks if an IP is a known VPN/Proxy
func (g *GeoIPService) IsVPN(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	g.mu.RLock()
	defer g.mu.RUnlock()

	for _, vpnRange := range g.vpnRanges {
		if vpnRange.Contains(ip) {
			return true
		}
	}

	return false
}

// IsTOR checks if an IP is a TOR exit node
func (g *GeoIPService) IsTOR(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	g.mu.RLock()
	defer g.mu.RUnlock()

	for _, torIP := range g.torExitNodes {
		if torIP.Equal(ip) {
			return true
		}
	}

	return false
}

// GetCountryCode returns the country code for an IP
func (g *GeoIPService) GetCountryCode(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "XX"
	}

	g.mu.RLock()
	defer g.mu.RUnlock()

	for country, ranges := range g.countryRanges {
		for _, ipRange := range ranges {
			if ipRange.Contains(ip) {
				return country
			}
		}
	}

	return "XX"
}

// downloadGeoIPData downloads GeoIP database
func (g *GeoIPService) downloadGeoIPData() error {
	// Using a free GeoIP database (GeoLite2 alternative)
	// In production, use MaxMind GeoLite2 with license key

	// For now, we'll use a simplified approach with country CIDR blocks
	// This is a placeholder - in production, integrate with MaxMind or ip2location

	system.Info("Loading GeoIP country ranges...")

	// Load major country ranges (simplified)
	g.loadFallbackData()

	return nil
}

// downloadTORExitNodes downloads current TOR exit node list
func (g *GeoIPService) downloadTORExitNodes() error {
	url := "https://check.torproject.org/torbulkexitlist"

	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	g.torExitNodes = make([]net.IP, 0)
	lines := strings.Split(string(body), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if ip := net.ParseIP(line); ip != nil {
			g.torExitNodes = append(g.torExitNodes, ip)
		}
	}

	system.Info("Loaded %d TOR exit nodes", len(g.torExitNodes))
	return nil
}

// downloadVPNRanges downloads known VPN/Proxy IP ranges
func (g *GeoIPService) downloadVPNRanges() error {
	// In production, use services like:
	// - IPHub.info
	// - IP2Proxy
	// - VPN API

	// For now, load common VPN provider ranges
	g.mu.Lock()
	defer g.mu.Unlock()

	// Common VPN/Cloud provider ranges (simplified)
	vpnCIDRs := []string{
		// AWS
		"52.0.0.0/8",
		"54.0.0.0/8",
		// Google Cloud
		"35.0.0.0/8",
		// Azure
		"40.0.0.0/8",
		// DigitalOcean
		"104.131.0.0/16",
		"159.65.0.0/16",
		// Linode
		"45.79.0.0/16",
		"50.116.0.0/16",
	}

	g.vpnRanges = make([]net.IPNet, 0)
	for _, cidr := range vpnCIDRs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err == nil {
			g.vpnRanges = append(g.vpnRanges, *ipNet)
		}
	}

	system.Info("Loaded %d VPN/Proxy ranges", len(g.vpnRanges))
	return nil
}

// loadFallbackData loads minimal country data
func (g *GeoIPService) loadFallbackData() {
	g.mu.Lock()
	defer g.mu.Unlock()

	// Major country CIDR blocks (simplified for demonstration)
	// In production, use complete GeoIP database
	countryCIDRs := map[string][]string{
		"KR": {
			"1.11.0.0/16", "1.16.0.0/12", "14.0.0.0/8", "27.0.0.0/10",
			"58.120.0.0/13", "59.5.0.0/16", "61.72.0.0/13",
			"106.240.0.0/12", "112.104.0.0/13", "115.68.0.0/14",
			"121.128.0.0/10", "175.192.0.0/10", "211.32.0.0/12",
		},
		"US": {
			"3.0.0.0/8", "4.0.0.0/8", "6.0.0.0/8", "7.0.0.0/8",
			"8.0.0.0/8", "11.0.0.0/8", "12.0.0.0/8", "13.0.0.0/8",
		},
		"CN": {
			"1.0.1.0/24", "1.0.2.0/23", "1.0.8.0/21", "1.0.32.0/19",
			"36.0.0.0/8", "42.0.0.0/8", "58.0.0.0/8", "59.0.0.0/8",
			"60.0.0.0/8", "61.0.0.0/8", "101.0.0.0/8", "106.0.0.0/8",
		},
		"JP": {
			"1.0.16.0/20", "1.1.0.0/16", "1.21.0.0/16", "1.33.0.0/16",
			"27.0.0.0/9", "49.212.0.0/14", "58.0.0.0/9",
		},
		"DE": {
			"2.16.0.0/13", "5.0.0.0/8", "31.0.0.0/8", "37.0.0.0/8",
			"46.0.0.0/8", "62.0.0.0/8", "77.0.0.0/8", "78.0.0.0/8",
		},
		"RU": {
			"2.56.0.0/13", "5.0.0.0/9", "31.0.0.0/9", "37.0.0.0/9",
			"46.0.0.0/9", "77.0.0.0/9", "78.0.0.0/9", "79.0.0.0/9",
		},
		"BR": {
			"177.0.0.0/8", "179.0.0.0/8", "186.0.0.0/8", "189.0.0.0/8",
		},
		"GB": {
			"2.0.0.0/9", "5.0.0.0/9", "25.0.0.0/8", "31.0.0.0/9",
		},
		"CA": {
			"24.0.0.0/8", "64.0.0.0/10", "65.0.0.0/8", "66.0.0.0/8",
		},
		"AU": {
			"1.128.0.0/11", "14.0.0.0/12", "27.0.0.0/12", "58.0.0.0/11",
		},
	}

	for country, cidrs := range countryCIDRs {
		ranges := make([]net.IPNet, 0)
		for _, cidr := range cidrs {
			_, ipNet, err := net.ParseCIDR(cidr)
			if err == nil {
				ranges = append(ranges, *ipNet)
			}
		}
		g.countryRanges[country] = ranges
	}

	system.Info("Loaded fallback GeoIP data for %d countries", len(g.countryRanges))
}

// saveToDisk saves current data to disk
func (g *GeoIPService) saveToDisk() error {
	// Implementation for caching
	return nil
}

// loadFromDisk loads data from disk cache
func (g *GeoIPService) loadFromDisk() error {
	// Implementation for loading cache
	return fmt.Errorf("no cache available")
}
