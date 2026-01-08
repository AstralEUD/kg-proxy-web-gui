package services

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"kg-proxy-web-gui/backend/system"

	"github.com/oschwald/geoip2-golang"
)

// GeoIPService provides IP geolocation using MaxMind GeoLite2
type GeoIPService struct {
	dbPath       string
	db           *geoip2.Reader
	vpnRanges    []net.IPNet
	torExitNodes []net.IP
	countryCIDRs map[string][]string // country code -> CIDR strings
	mu           sync.RWMutex
	lastUpdate   time.Time
	licenseKey   string
}

func NewGeoIPService() *GeoIPService {
	// Try to get license key from environment
	licenseKey := os.Getenv("MAXMIND_LICENSE_KEY")

	dbDir := "./geoip"
	if _, err := os.Stat("/opt/kg-proxy"); err == nil {
		dbDir = "/opt/kg-proxy/geoip"
	}

	service := &GeoIPService{
		dbPath:       dbDir,
		vpnRanges:    make([]net.IPNet, 0),
		torExitNodes: make([]net.IP, 0),
		licenseKey:   licenseKey,
	}

	// Create directory if not exists
	os.MkdirAll(service.dbPath, 0755)

	// Initialize in background
	go service.Initialize()

	return service
}

// SetLicenseKey updates the license key and triggers a refresh
func (g *GeoIPService) SetLicenseKey(key string) {
	g.mu.Lock()
	g.licenseKey = key
	g.mu.Unlock()
}

// RefreshGeoIP downloads the GeoIP database with the current license key
func (g *GeoIPService) RefreshGeoIP() error {
	g.mu.RLock()
	key := g.licenseKey
	g.mu.RUnlock()

	if key == "" {
		return fmt.Errorf("no MaxMind license key configured")
	}

	if err := g.downloadGeoLite2(); err != nil {
		return err
	}

	// Reload the database
	dbFile := filepath.Join(g.dbPath, "GeoLite2-Country.mmdb")
	return g.loadDB(dbFile)
}

// Initialize loads or downloads GeoIP data
func (g *GeoIPService) Initialize() error {
	system.Info("Initializing GeoIP service...")

	// Try to load existing DB
	dbFile := filepath.Join(g.dbPath, "GeoLite2-Country.mmdb")
	if err := g.loadDB(dbFile); err == nil {
		system.Info("GeoIP database loaded from disk")
	} else {
		system.Warn("GeoIP database not found or failed to load: %v", err)
		// Try to download if license key is available
		if g.licenseKey != "" {
			if err := g.downloadGeoLite2(); err != nil {
				system.Error("Failed to download GeoLite2: %v", err)
			} else {
				g.loadDB(dbFile)
			}
		} else {
			system.Warn("No MAXMIND_LICENSE_KEY set. GeoIP filtering will use fallback (less accurate).")
			g.loadFallbackRanges()
		}
	}

	// Download TOR exit nodes
	if err := g.downloadTORExitNodes(); err != nil {
		system.Warn("Failed to download TOR exit nodes: %v", err)
	}

	// Load VPN ranges
	g.loadVPNRanges()

	return nil
}

// loadDB loads the MaxMind database
func (g *GeoIPService) loadDB(path string) error {
	db, err := geoip2.Open(path)
	if err != nil {
		return err
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	if g.db != nil {
		g.db.Close()
	}
	g.db = db
	g.lastUpdate = time.Now()

	return nil
}

// Close closes the database
func (g *GeoIPService) Close() {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.db != nil {
		g.db.Close()
		g.db = nil
	}
}

// GetCountryCode returns the ISO country code for an IP
func (g *GeoIPService) GetCountryCode(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "XX"
	}

	g.mu.RLock()
	defer g.mu.RUnlock()

	if g.db == nil {
		return "XX" // No database loaded
	}

	record, err := g.db.Country(ip)
	if err != nil {
		return "XX"
	}

	return record.Country.IsoCode
}

// IsCountryAllowed checks if an IP is from an allowed country
func (g *GeoIPService) IsCountryAllowed(ipStr string, allowedCountries []string) bool {
	countryCode := g.GetCountryCode(ipStr)
	if countryCode == "XX" {
		return false // Unknown = not allowed
	}

	for _, allowed := range allowedCountries {
		if strings.EqualFold(allowed, countryCode) {
			return true
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

// GetVPNRanges returns the list of VPN/Proxy IP ranges
func (g *GeoIPService) GetVPNRanges() []net.IPNet {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.vpnRanges
}

// GetTORExitNodes returns the list of TOR exit node IPs
func (g *GeoIPService) GetTORExitNodes() []net.IP {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.torExitNodes
}

// downloadGeoLite2 downloads the GeoLite2-Country database
func (g *GeoIPService) downloadGeoLite2() error {
	if g.licenseKey == "" {
		return fmt.Errorf("no MaxMind license key configured")
	}

	url := fmt.Sprintf(
		"https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country&license_key=%s&suffix=tar.gz",
		g.licenseKey,
	)

	system.Info("Downloading GeoLite2-Country database...")

	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("download failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("download failed with status: %s", resp.Status)
	}

	// Extract tar.gz
	gzr, err := gzip.NewReader(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to create gzip reader: %v", err)
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("tar read error: %v", err)
		}

		// Look for the .mmdb file
		if strings.HasSuffix(header.Name, ".mmdb") {
			outPath := filepath.Join(g.dbPath, "GeoLite2-Country.mmdb")
			outFile, err := os.Create(outPath)
			if err != nil {
				return fmt.Errorf("failed to create output file: %v", err)
			}
			defer outFile.Close()

			if _, err := io.Copy(outFile, tr); err != nil {
				return fmt.Errorf("failed to extract mmdb: %v", err)
			}

			system.Info("GeoLite2-Country database downloaded successfully")
			return nil
		}
	}

	return fmt.Errorf("mmdb file not found in archive")
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

// loadVPNRanges loads known VPN/Proxy IP ranges
func (g *GeoIPService) loadVPNRanges() {
	g.mu.Lock()
	defer g.mu.Unlock()

	// Common VPN/Cloud provider ranges (simplified)
	vpnCIDRs := []string{
		// AWS (partial)
		"52.0.0.0/8",
		"54.0.0.0/8",
		// Google Cloud (partial)
		"35.0.0.0/8",
		// Azure (partial)
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
}

// loadFallbackRanges loads minimal country data when MaxMind is unavailable
// This is NOT accurate and should only be used as a last resort
func (g *GeoIPService) loadFallbackRanges() {
	system.Warn("Using fallback GeoIP data - accuracy will be limited!")
	// No-op: Without MaxMind, we cannot accurately determine countries
	// The firewall will rely on ipset "geo_allowed" being empty,
	// which means GEO_GUARD will DROP non-whitelisted IPs.
	// Users should configure MAXMIND_LICENSE_KEY for proper functionality.
}

// GetCountryCIDRs returns CIDR ranges for a country (for ipset)
func (g *GeoIPService) GetCountryCIDRs(countryCode string) []string {
	g.mu.RLock()
	defer g.mu.RUnlock()

	if cidrs, ok := g.countryCIDRs[strings.ToLower(countryCode)]; ok {
		return cidrs
	}
	return nil
}

// DownloadCountryCIDRs downloads CIDR lists for specified countries
func (g *GeoIPService) DownloadCountryCIDRs(countries []string) error {
	g.mu.Lock()
	if g.countryCIDRs == nil {
		g.countryCIDRs = make(map[string][]string)
	}
	g.mu.Unlock()

	for _, country := range countries {
		country = strings.ToLower(strings.TrimSpace(country))
		if country == "" {
			continue
		}

		// Download from ipverse GitHub (RIR-sourced data)
		url := fmt.Sprintf("https://raw.githubusercontent.com/ipverse/rir-ip/master/country/%s/ipv4-aggregated.txt", country)

		resp, err := http.Get(url)
		if err != nil {
			system.Warn("Failed to download CIDR for %s: %v", country, err)
			continue
		}

		if resp.StatusCode != 200 {
			resp.Body.Close()
			system.Warn("Failed to download CIDR for %s: HTTP %d", country, resp.StatusCode)
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			system.Warn("Failed to read CIDR for %s: %v", country, err)
			continue
		}

		lines := strings.Split(string(body), "\n")
		cidrs := make([]string, 0, len(lines))
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			// Validate CIDR format
			if _, _, err := net.ParseCIDR(line); err == nil {
				cidrs = append(cidrs, line)
			}
		}

		g.mu.Lock()
		g.countryCIDRs[country] = cidrs
		g.mu.Unlock()

		system.Info("Loaded %d CIDRs for country %s", len(cidrs), strings.ToUpper(country))
	}

	return nil
}
