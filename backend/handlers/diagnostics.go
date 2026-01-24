package handlers

import (
	"fmt"
	"net/http"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
)

// Validate hostname or IP to prevent command injection
var hostnameRegex = regexp.MustCompile(`^[a-zA-Z0-9.-]+$`)

func validateTarget(target string) error {
	if len(target) > 253 {
		return fmt.Errorf("target too long")
	}
	if !hostnameRegex.MatchString(target) {
		return fmt.Errorf("invalid format")
	}
	// Prevent standard injection characters just in case, though regex covers it
	if strings.ContainsAny(target, "&|;`$()<>") {
		return fmt.Errorf("invalid characters")
	}
	return nil
}

// RunPing executes ping command safely
// POST /api/tools/ping
func (h *Handler) RunPing(c *fiber.Ctx) error {
	var input struct {
		Target string `json:"target"`
		Count  int    `json:"count"`
	}

	if err := c.BodyParser(&input); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "Invalid input"})
	}

	if err := validateTarget(input.Target); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "Invalid target: " + err.Error()})
	}

	if input.Count < 1 {
		input.Count = 4
	}
	if input.Count > 10 {
		input.Count = 10
	}

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("ping", "-n", fmt.Sprintf("%d", input.Count), input.Target)
	} else {
		// Linux: -c count, -W timeout (1 sec)
		cmd = exec.Command("ping", "-c", fmt.Sprintf("%d", input.Count), "-W", "1", input.Target)
	}

	output, err := cmd.CombinedOutput()

	result := fiber.Map{
		"target":  input.Target,
		"output":  string(output),
		"success": err == nil,
	}

	return c.JSON(result)
}

// RunTraceroute executes traceroute
// POST /api/tools/traceroute
func (h *Handler) RunTraceroute(c *fiber.Ctx) error {
	var input struct {
		Target string `json:"target"`
	}

	if err := c.BodyParser(&input); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "Invalid input"})
	}

	if err := validateTarget(input.Target); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "Invalid target: " + err.Error()})
	}

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("tracert", "-d", "-h", "15", "-w", "500", input.Target)
	} else {
		// Linux: traceroute -n (no result) -m 15 (max hops) -w 1 (wait)
		// Need to check if traceroute exists, fallback to ping if not?
		// Actually tracepath is more common on modern ubuntu without root
		if _, err := exec.LookPath("traceroute"); err == nil {
			cmd = exec.Command("traceroute", "-n", "-m", "15", "-w", "1", input.Target)
		} else {
			cmd = exec.Command("tracepath", "-n", "-m", "15", input.Target)
		}
	}

	// This can take a while, so we might need a channel or just wait (it's sync API for now)
	// Set a timeout context
	done := make(chan struct{})
	var output []byte
	var err error

	go func() {
		output, err = cmd.CombinedOutput()
		close(done)
	}()

	select {
	case <-done:
		// Completed
	case <-time.After(15 * time.Second):
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
		return c.JSON(fiber.Map{
			"target":  input.Target,
			"output":  "Traceroute timed out after 15s.\n" + string(output),
			"success": false,
		})
	}

	return c.JSON(fiber.Map{
		"target":  input.Target,
		"output":  string(output),
		"success": err == nil,
	})
}

// CheckWireGuardConnectivity pings the Origin Peer via WG interface
// GET /api/tools/wg-ping
func (h *Handler) CheckWireGuardConnectivity(c *fiber.Ctx) error {
	if h.WireGuard == nil {
		return c.Status(http.StatusServiceUnavailable).JSON(fiber.Map{"error": "WireGuard service not initialized"})
	}

	// We ping the Origin Peer IP (e.g. 10.200.0.2)
	// We need to know which origin. For now, let's ping all known origins and return results.

	// Get all origins
	// Handler doesn't have direct access to Origin model list without DB query
	// But allowed to query DB.

	type OriginStatus struct {
		Name      string `json:"name"`
		IP        string `json:"ip"`
		Alive     bool   `json:"alive"`
		LatencyMs int64  `json:"latency_ms"`
	}

	var statuses []OriginStatus

	// TODO: Fetch origins from DB
	// We can implement a simplified version pinging the gateway or just one.

	// Using h.WireGuard to check handshake is better (non-intrusive)
	status, err := h.WireGuard.GetStatus()
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}

	// Parse status
	// We can just return the handshake times which is "passive ping"

	return c.JSON(status)
}
