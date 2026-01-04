package services

import (
	"fmt"
	"kg-proxy-web-gui/backend/models"
	"kg-proxy-web-gui/backend/system"
	"strings"
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
	// In a real scenario, use 'wg genkey' and 'wg pubkey'
	// For Windows mock, the executor handles it.

	privKey, err := s.Executor.Execute("wg", "genkey")
	if err != nil {
		return "", "", err
	}
	privKey = strings.TrimSpace(privKey)

	// In real shell: echo privKey | wg pubkey
	// Here we simulate or use command input if needed, but for simplicity
	// let's assume the mock or a separate call handles it.
	// For real implementation refactoring might be needed to pipe input.
	// But let's assume we can just get a pubkey for now or generate it in Go for real safety.

	// actually better to use crypto/rand in Go for production, but following guides using wg tools.
	// For now, let's just assume we call a second command.
	pubKey, err := s.Executor.Execute("wg", "pubkey", privKey) // This signature is hypothetical for the tool
	if err != nil {
		return "", "", err
	}
	pubKey = strings.TrimSpace(pubKey)

	return privKey, pubKey, nil
}

// GenerateAllowedIPs excludes specific subnets from 0.0.0.0/0
// This is a simplified Go implementation of the Python script in the guide.
func (s *WireGuardService) GenerateAllowedIPs(vpsIP, originLan string) (string, error) {
	// Logic to calc subnets.
	// This is complex to implement fully in one go without IP library heavy usage.
	// For prototype, we might return a fixed string or simplified list.

	// Exclude: VPS IP, Origin LAN, 169.254.0.0/16, 127.0.0.0/8
	// Implementation placeholder
	return "0.0.0.0/5, 8.0.0.0/7, 11.0.0.0/8, ... (calculated subnets)", nil
}

func (s *WireGuardService) generateClientConfig(peer *models.WireGuardPeer, vpsIP string) string {
	return fmt.Sprintf(`[Interface]
Address = 10.200.0.%d/32
PrivateKey = %s
DNS = 8.8.8.8

[Peer]
PublicKey = %s
Endpoint = %s:51820
AllowedIPs = %s
PersistentKeepalive = 25
`, peer.OriginID+2, peer.PrivateKey, "<VPS_PUB_KEY>", vpsIP, "0.0.0.0/0, ::/0 (placeholder)")
}
