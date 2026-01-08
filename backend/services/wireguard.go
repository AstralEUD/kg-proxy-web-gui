package services

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"kg-proxy-web-gui/backend/models"
	"kg-proxy-web-gui/backend/system"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"golang.org/x/crypto/curve25519"
)

type WireGuardService struct {
	Executor system.CommandExecutor
	Config   *models.SystemConfig
	DataDir  string
}

func NewWireGuardService(exec system.CommandExecutor, cfg *models.SystemConfig, dataDir string) *WireGuardService {
	return &WireGuardService{Executor: exec, Config: cfg, DataDir: dataDir}
}

// Init ensures the WireGuard interface exists and is configured
func (s *WireGuardService) Init() error {
	if runtime.GOOS != "linux" {
		return nil
	}

	// 1. Check if wg0 exists
	if _, err := s.Executor.Execute("ip", "link", "show", "wg0"); err != nil {
		system.Info("Creating WireGuard interface wg0...")
		if _, err := s.Executor.Execute("ip", "link", "add", "dev", "wg0", "type", "wireguard"); err != nil {
			return fmt.Errorf("failed to create wg0 interface: %v", err)
		}
	}

	// 2. Assign IP (10.200.0.1/24) if not present
	// Simple check: see if "10.200.0.1" is in the output of ip addr show wg0
	out, _ := s.Executor.Execute("ip", "addr", "show", "wg0")
	if !strings.Contains(out, "10.200.0.1") {
		if _, err := s.Executor.Execute("ip", "addr", "add", "10.200.0.1/24", "dev", "wg0"); err != nil {
			return fmt.Errorf("failed to assign IP to wg0: %v", err)
		}
	}

	// 3. Ensure Server Private Key
	keyPath := filepath.Join(s.DataDir, "wg_private.key")
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		system.Info("Generating new WireGuard server private key...")
		privKey, err := s.generateKeyWithWG()
		if err != nil {
			return fmt.Errorf("failed to generate server key: %v", err)
		}
		if err := os.WriteFile(keyPath, []byte(privKey), 0600); err != nil {
			return fmt.Errorf("failed to save server key: %v", err)
		}
	}

	// 4. Apply Configuration (Key & Port)
	// wg set wg0 private-key <file> listen-port 51820
	// Note: 'wg set' expects the path to a file containing the key if using private-key argument with a path?
	// Actually 'wg set ... private-key <file>' works.
	if _, err := s.Executor.Execute("wg", "set", "wg0", "private-key", keyPath, "listen-port", "51820"); err != nil {
		return fmt.Errorf("failed to configure wg0: %v", err)
	}

	// 5. Bring Interface Up
	if _, err := s.Executor.Execute("ip", "link", "set", "up", "dev", "wg0"); err != nil {
		return fmt.Errorf("failed to bring up wg0: %v", err)
	}

	system.Info("WireGuard interface wg0 initialized successfully")
	return nil
}

// GenerateKeys returns privateKey, publicKey, error
func (s *WireGuardService) GenerateKeys() (string, string, error) {
	// On Linux with WireGuard installed, use wg commands
	// On Windows or when wg is not available, use Go crypto

	if runtime.GOOS == "linux" {
		// Try using wg command
		privKey, err := s.generateKeyWithWG()
		if err == nil {
			pubKey, err := s.derivePublicKey(privKey)
			if err == nil {
				return privKey, pubKey, nil
			}
		}
		// Fall back to Go implementation if wg command fails
	}

	// Pure Go implementation (works everywhere)
	return s.generateKeyWithGo()
}

// generateKeyWithWG uses wg command line tools
func (s *WireGuardService) generateKeyWithWG() (string, error) {
	cmd := exec.Command("wg", "genkey")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

// derivePublicKey derives public key from private key
func (s *WireGuardService) derivePublicKey(privKey string) (string, error) {
	if runtime.GOOS == "linux" {
		// Try using wg pubkey command
		cmd := exec.Command("wg", "pubkey")
		cmd.Stdin = strings.NewReader(privKey)
		output, err := cmd.Output()
		if err == nil {
			return strings.TrimSpace(string(output)), nil
		}
	}

	// Fall back to Go implementation
	privKeyBytes, err := base64.StdEncoding.DecodeString(privKey)
	if err != nil {
		return "", err
	}

	if len(privKeyBytes) != 32 {
		return "", fmt.Errorf("invalid private key length")
	}

	var privKeyArray [32]byte
	copy(privKeyArray[:], privKeyBytes)

	var pubKeyArray [32]byte
	curve25519.ScalarBaseMult(&pubKeyArray, &privKeyArray)

	return base64.StdEncoding.EncodeToString(pubKeyArray[:]), nil
}

// generateKeyWithGo generates WireGuard keys using pure Go crypto
func (s *WireGuardService) generateKeyWithGo() (string, string, error) {
	// Generate 32 random bytes for private key
	var privKey [32]byte
	if _, err := rand.Read(privKey[:]); err != nil {
		return "", "", err
	}

	// Clamp the private key (WireGuard requirement)
	privKey[0] &= 248
	privKey[31] &= 127
	privKey[31] |= 64

	// Derive public key using Curve25519
	var pubKey [32]byte
	curve25519.ScalarBaseMult(&pubKey, &privKey)

	privKeyStr := base64.StdEncoding.EncodeToString(privKey[:])
	pubKeyStr := base64.StdEncoding.EncodeToString(pubKey[:])

	return privKeyStr, pubKeyStr, nil
}

// GenerateAllowedIPs calculates the AllowedIPs list by excluding VPS IP and private ranges from 0.0.0.0/0
func (s *WireGuardService) GenerateAllowedIPs(vpsIP string, originLan string) (string, error) {
	// Base: All IPv4
	allowed := []string{"0.0.0.0/0"}

	// Exclusions
	exclusions := []string{
		"10.0.0.0/8",     // Private A
		"172.16.0.0/12",  // Private B
		"192.168.0.0/16", // Private C
	}

	// Add VPS IP (as /32)
	if vpsIP != "" && vpsIP != "0.0.0.0" {
		// Ensure it's just IP
		ip := net.ParseIP(vpsIP)
		if ip != nil {
			exclusions = append(exclusions, ip.String()+"/32")
		}
	}

	// Add Origin LAN if provided
	if originLan != "" {
		exclusions = append(exclusions, originLan)
	}

	// Process exclusions
	for _, exclude := range exclusions {
		var newAllowed []string
		for _, base := range allowed {
			subtracted := excludeNetwork(base, exclude)
			newAllowed = append(newAllowed, subtracted...)
		}
		allowed = newAllowed
	}

	// Combine into string
	return strings.Join(allowed, ", "), nil
}

// excludeNetwork subtracts 'exclude' CIDR from 'base' CIDR
// Returns a list of CIDRs covering (base - exclude)
func excludeNetwork(baseStr, excludeStr string) []string {
	_, base, err := net.ParseCIDR(baseStr)
	if err != nil {
		return []string{baseStr} // Keep if invalid
	}
	_, exclude, err := net.ParseCIDR(excludeStr)
	if err != nil {
		return []string{baseStr}
	}

	// Case 1: No overlap -> Return base
	if !networksOverlap(base, exclude) {
		return []string{baseStr}
	}

	// Case 2: Base is inside Exclude -> Remove strictly (Return empty)
	if networkContains(exclude, base) {
		// Special case: if base == exclude, it's removed
		return []string{}
	}

	// Case 3: Exclude is inside Base (or partial overlap being handled by recursion)
	// We need to split Base until Exclude is isolated

	// If base matches exclude exactly, return empty
	if base.String() == exclude.String() {
		return []string{}
	}

	// Split base into two halves
	ones, _ := base.Mask.Size()
	if ones >= 32 {
		// Cannot split /32 further. If we are here, it means overlap logic failed or it IS the excluded IP
		return []string{}
	}

	// Left: same IP, prefix+1
	// Right: IP + 2^(32-(prefix+1)), prefix+1

	prefix := ones + 1

	// Left child
	leftIP := base.IP
	leftCIDR := fmt.Sprintf("%s/%d", leftIP.String(), prefix)

	// Right child
	// Calculate offset
	ipInt := ipToUint32(leftIP)
	// size of the new block is 2^(32-prefix)
	size := uint32(1) << (32 - prefix)
	rightIPInt := ipInt + size
	rightIP := uint32ToIP(rightIPInt)
	rightCIDR := fmt.Sprintf("%s/%d", rightIP.String(), prefix)

	// Recurse
	result := []string{}
	result = append(result, excludeNetwork(leftCIDR, excludeStr)...)
	result = append(result, excludeNetwork(rightCIDR, excludeStr)...)

	return result
}

// Helper: Check if networks overlap
func networksOverlap(n1, n2 *net.IPNet) bool {
	return n1.Contains(n2.IP) || n2.Contains(n1.IP)
}

// Helper: Check if n1 contains n2 fully
func networkContains(n1, n2 *net.IPNet) bool {
	// n1 contains n2 if n1 contains n2.IP and n1 mask size <= n2 mask size
	s1, _ := n1.Mask.Size()
	s2, _ := n2.Mask.Size()
	return s1 <= s2 && n1.Contains(n2.IP)
}

func (s *WireGuardService) generateClientConfig(peer *models.WireGuardPeer, vpsIP string) string {
	return fmt.Sprintf(`[Interface]
Address = 10.200.0.%d/32
PrivateKey = %s
DNS = 8.8.8.8

[Peer]
PublicKey = <VPS_PUB_KEY>
Endpoint = %s:51820
AllowedIPs = %s
PersistentKeepalive = 25
`, peer.OriginID+2, peer.PrivateKey, vpsIP, "0.0.0.0/0, ::/0")
}

// GetServerPublicKey returns the public key of the WireGuard server interface (wg0)
func (s *WireGuardService) GetServerPublicKey() string {
	if runtime.GOOS != "linux" {
		// Mock key for dev
		return "SERVER_PUB_KEY_MOCK_123456="
	}

	// Try wg show
	out, err := exec.Command("wg", "show", "wg0", "public-key").Output()
	if err == nil {
		return strings.TrimSpace(string(out))
	}

	// If failed (maybe interface down?), try reading config or return error
	return "UNKNOWN_SERVER_KEY"
}

// AddPeer adds a peer to the running WireGuard interface
func (s *WireGuardService) AddPeer(peer *models.WireGuardPeer) error {
	if runtime.GOOS != "linux" {
		return nil // No-op on Windows/Dev
	}

	// Client IP is calculated as 10.200.0.(ID+2)
	clientIP := fmt.Sprintf("10.200.0.%d/32", peer.OriginID+2)

	// command: wg set wg0 peer <PUBKEY> allowed-ips <IP/32>
	_, err := s.Executor.Execute("wg", "set", "wg0", "peer", peer.PublicKey, "allowed-ips", clientIP)
	return err
}

// RemovePeer removes a peer from the WireGuard interface
func (s *WireGuardService) RemovePeer(peer *models.WireGuardPeer) error {
	if runtime.GOOS != "linux" {
		return nil
	}

	// command: wg set wg0 peer <PUBKEY> remove
	_, err := s.Executor.Execute("wg", "set", "wg0", "peer", peer.PublicKey, "remove")
	return err
}
