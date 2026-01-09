package services

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
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

	// IP Intelligence (IPinfo.io)
	ipInfoAPIKey string
	ipInfoCache  map[string]*IPIntelligenceResult // Cache for 24h
	cacheExpiry  map[string]time.Time
}

// IPIntelligenceResult represents the result of an IP intelligence check
type IPIntelligenceResult struct {
	IP        string `json:"ip"`
	IsVPN     bool   `json:"is_vpn"`
	IsProxy   bool   `json:"is_proxy"`
	IsTor     bool   `json:"is_tor"`
	IsHosting bool   `json:"is_hosting"`
	Threat    bool   `json:"threat"`
	Country   string `json:"country"`
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
		ipInfoCache:  make(map[string]*IPIntelligenceResult),
		cacheExpiry:  make(map[string]time.Time),
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

// StartAutoUpdateScheduler starts a background goroutine that refreshes GeoIP data periodically
func (g *GeoIPService) StartAutoUpdateScheduler() {
	go func() {
		// Check every 24 hours
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()

		for range ticker.C {
			g.mu.RLock()
			lastUpdate := g.lastUpdate
			hasLicense := g.licenseKey != ""
			g.mu.RUnlock()

			// Refresh if older than 7 days and we have a license key
			if hasLicense && time.Since(lastUpdate) > 7*24*time.Hour {
				system.Info("Auto-refreshing GeoIP database (last update: %s)", lastUpdate.Format("2006-01-02"))
				if err := g.RefreshGeoIP(); err != nil {
					system.Warn("Auto-refresh GeoIP failed: %v", err)
				} else {
					system.Info("GeoIP database auto-refreshed successfully")
				}

				// Also refresh TOR exit nodes
				if err := g.downloadTORExitNodes(); err != nil {
					system.Warn("Auto-refresh TOR exit nodes failed: %v", err)
				}
			}
		}
	}()
	system.Info("GeoIP auto-update scheduler started (checks daily, refreshes weekly)")
}

// GetLastUpdate returns the last update time
func (g *GeoIPService) GetLastUpdate() time.Time {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.lastUpdate
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

// GetCountry returns the country name and ISO code for an IP
func (g *GeoIPService) GetCountry(ipStr string) (string, string) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "Unknown", "XX"
	}

	g.mu.RLock()
	defer g.mu.RUnlock()

	if g.db == nil {
		return "Unknown", "XX"
	}

	record, err := g.db.Country(ip)
	if err != nil {
		return "Unknown", "XX"
	}

	name := record.Country.Names["en"]
	if name == "" {
		name = "Unknown"
	}
	code := record.Country.IsoCode
	if code == "" {
		code = "XX"
	}

	return name, code
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

// GetAllCountryCIDRs returns all loaded country CIDRs
func (g *GeoIPService) GetAllCountryCIDRs() map[string][]string {
	g.mu.RLock()
	defer g.mu.RUnlock()

	copy := make(map[string][]string)
	for k, v := range g.countryCIDRs {
		copy[k] = v
	}
	return copy
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

// SetIPInfoAPIKey sets the IPinfo.io API key
func (g *GeoIPService) SetIPInfoAPIKey(key string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.ipInfoAPIKey = key
}

// CheckIPIntelligence checks an IP against IPinfo.io for VPN/proxy detection
func (g *GeoIPService) CheckIPIntelligence(ipStr string) (*IPIntelligenceResult, error) {
	g.mu.RLock()
	apiKey := g.ipInfoAPIKey

	// Check cache first
	if cached, exists := g.ipInfoCache[ipStr]; exists {
		if expiry, hasExpiry := g.cacheExpiry[ipStr]; hasExpiry && time.Now().Before(expiry) {
			g.mu.RUnlock()
			return cached, nil
		}
	}
	g.mu.RUnlock()

	if apiKey == "" {
		return nil, fmt.Errorf("IPinfo.io API key not configured")
	}

	// Make API request
	url := fmt.Sprintf("https://ipinfo.io/%s?token=%s", ipStr, apiKey)
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("IPinfo.io request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("IPinfo.io returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Parse response (IPinfo.io basic format)
	var data struct {
		IP      string `json:"ip"`
		Country string `json:"country"`
		Privacy struct {
			VPN     bool `json:"vpn"`
			Proxy   bool `json:"proxy"`
			Tor     bool `json:"tor"`
			Hosting bool `json:"hosting"`
		} `json:"privacy"`
	}

	if err := json.Unmarshal(body, &data); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	result := &IPIntelligenceResult{
		IP:        data.IP,
		Country:   data.Country,
		IsVPN:     data.Privacy.VPN,
		IsProxy:   data.Privacy.Proxy,
		IsTor:     data.Privacy.Tor,
		IsHosting: data.Privacy.Hosting,
		Threat:    data.Privacy.VPN || data.Privacy.Proxy || data.Privacy.Tor,
	}

	// Cache for 24 hours
	g.mu.Lock()
	g.ipInfoCache[ipStr] = result
	g.cacheExpiry[ipStr] = time.Now().Add(24 * time.Hour)
	g.mu.Unlock()

	return result, nil
}

// IsThreat checks if an IP is a VPN/proxy/TOR based on cached intelligence
func (g *GeoIPService) IsThreat(ipStr string) bool {
	g.mu.RLock()
	if cached, exists := g.ipInfoCache[ipStr]; exists {
		if expiry, hasExpiry := g.cacheExpiry[ipStr]; hasExpiry && time.Now().Before(expiry) {
			g.mu.RUnlock()
			return cached.Threat
		}
	}
	g.mu.RUnlock()

	// Not in cache, check synchronously if API key is available
	g.mu.RLock()
	hasKey := g.ipInfoAPIKey != ""
	g.mu.RUnlock()

	if hasKey {
		result, err := g.CheckIPIntelligence(ipStr)
		if err == nil && result != nil {
			return result.Threat
		}
	}

	return false
}
