package services

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"kg-proxy-web-gui/backend/models"
	"kg-proxy-web-gui/backend/system"
	"os/exec"
	"runtime"
	"strings"

	"golang.org/x/crypto/curve25519"
)

type WireGuardService struct {
	Executor system.CommandExecutor
	Config   *models.SystemConfig
}

func NewWireGuardService(exec system.CommandExecutor, cfg *models.SystemConfig) *WireGuardService {
	return &WireGuardService{Executor: exec, Config: cfg}
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

// GenerateAllowedIPs excludes specific subnets from 0.0.0.0/0
func (s *WireGuardService) GenerateAllowedIPs(vpsIP, originLan string) (string, error) {
	// For now, return full routing
	// In production, this should exclude VPS IP and Origin LAN
	return "0.0.0.0/0, ::/0", nil
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
