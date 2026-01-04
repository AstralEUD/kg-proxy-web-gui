package handlers

import (
	"runtime"
	"strings"

	"github.com/gofiber/fiber/v2"
)

// WireGuardStatus represents WireGuard interface status
type WireGuardStatus struct {
	Interface   string          `json:"interface"`
	PublicKey   string          `json:"public_key"`
	ListenPort  string          `json:"listen_port"`
	Peers       []WireGuardPeer `json:"peers"`
	IsAvailable bool            `json:"is_available"`
	MockMode    bool            `json:"mock_mode"`
}

type WireGuardPeer struct {
	PublicKey       string `json:"public_key"`
	Endpoint        string `json:"endpoint"`
	AllowedIPs      string `json:"allowed_ips"`
	LatestHandshake string `json:"latest_handshake"`
	TransferRx      string `json:"transfer_rx"`
	TransferTx      string `json:"transfer_tx"`
}

// GetWireGuardStatus returns WireGuard interface status
func (h *Handler) GetWireGuardStatus(c *fiber.Ctx) error {
	isMock := runtime.GOOS == "windows"

	if isMock {
		// Return mock data for Windows development
		return c.JSON(WireGuardStatus{
			Interface:   "wg0",
			PublicKey:   "mock+public+key+base64==",
			ListenPort:  "51820",
			MockMode:    true,
			IsAvailable: true,
			Peers: []WireGuardPeer{
				{
					PublicKey:       "peer1+public+key+base64==",
					Endpoint:        "192.168.1.100:51820",
					AllowedIPs:      "10.200.0.2/32",
					LatestHandshake: "1 minute, 23 seconds ago",
					TransferRx:      "1.2 GiB",
					TransferTx:      "890 MiB",
				},
			},
		})
	}

	// Execute wg show command
	output, err := h.Firewall.Executor.Execute("wg", "show")
	if err != nil {
		return c.JSON(WireGuardStatus{
			IsAvailable: false,
			MockMode:    false,
			Interface:   "wg0",
			Peers:       []WireGuardPeer{},
		})
	}

	status := parseWgShow(output)
	status.MockMode = false
	return c.JSON(status)
}

// parseWgShow parses the output of 'wg show' command
func parseWgShow(output string) WireGuardStatus {
	status := WireGuardStatus{
		IsAvailable: true,
		Peers:       []WireGuardPeer{},
	}

	lines := strings.Split(output, "\n")
	var currentPeer *WireGuardPeer

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Check for interface line
		if strings.HasPrefix(line, "interface:") {
			status.Interface = strings.TrimSpace(strings.TrimPrefix(line, "interface:"))
			continue
		}

		// Check for public key
		if strings.HasPrefix(line, "public key:") {
			if currentPeer != nil {
				status.Peers = append(status.Peers, *currentPeer)
				currentPeer = nil
			}
			status.PublicKey = strings.TrimSpace(strings.TrimPrefix(line, "public key:"))
			continue
		}

		// Check for listen port
		if strings.HasPrefix(line, "listening port:") {
			status.ListenPort = strings.TrimSpace(strings.TrimPrefix(line, "listening port:"))
			continue
		}

		// Peer section
		if strings.HasPrefix(line, "peer:") {
			if currentPeer != nil {
				status.Peers = append(status.Peers, *currentPeer)
			}
			currentPeer = &WireGuardPeer{
				PublicKey: strings.TrimSpace(strings.TrimPrefix(line, "peer:")),
			}
			continue
		}

		if currentPeer != nil {
			if strings.HasPrefix(line, "endpoint:") {
				currentPeer.Endpoint = strings.TrimSpace(strings.TrimPrefix(line, "endpoint:"))
			} else if strings.HasPrefix(line, "allowed ips:") {
				currentPeer.AllowedIPs = strings.TrimSpace(strings.TrimPrefix(line, "allowed ips:"))
			} else if strings.HasPrefix(line, "latest handshake:") {
				currentPeer.LatestHandshake = strings.TrimSpace(strings.TrimPrefix(line, "latest handshake:"))
			} else if strings.HasPrefix(line, "transfer:") {
				transfer := strings.TrimSpace(strings.TrimPrefix(line, "transfer:"))
				parts := strings.Split(transfer, ",")
				if len(parts) >= 2 {
					currentPeer.TransferRx = strings.TrimSpace(strings.Replace(parts[0], "received", "", 1))
					currentPeer.TransferTx = strings.TrimSpace(strings.Replace(parts[1], "sent", "", 1))
				}
			}
		}
	}

	// Add last peer if exists
	if currentPeer != nil {
		status.Peers = append(status.Peers, *currentPeer)
	}

	return status
}
