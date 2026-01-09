package services

import (
	"bytes"
	"encoding/json"
	"fmt"
	"kg-proxy-web-gui/backend/system"
	"net/http"
	"time"
)

// WebhookService handles Discord webhook notifications
type WebhookService struct {
	webhookURL string
	enabled    bool
	client     *http.Client
}

// DiscordEmbed represents a Discord embed object
type DiscordEmbed struct {
	Title       string              `json:"title,omitempty"`
	Description string              `json:"description,omitempty"`
	Color       int                 `json:"color,omitempty"`
	Fields      []DiscordEmbedField `json:"fields,omitempty"`
	Footer      *DiscordEmbedFooter `json:"footer,omitempty"`
	Timestamp   string              `json:"timestamp,omitempty"`
}

// DiscordEmbedField represents a field in a Discord embed
type DiscordEmbedField struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Inline bool   `json:"inline,omitempty"`
}

// DiscordEmbedFooter represents a footer in a Discord embed
type DiscordEmbedFooter struct {
	Text string `json:"text"`
}

// DiscordWebhookPayload represents a Discord webhook message
type DiscordWebhookPayload struct {
	Username  string         `json:"username,omitempty"`
	AvatarURL string         `json:"avatar_url,omitempty"`
	Content   string         `json:"content,omitempty"`
	Embeds    []DiscordEmbed `json:"embeds,omitempty"`
}

// NewWebhookService creates a new WebhookService
func NewWebhookService() *WebhookService {
	return &WebhookService{
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// SetWebhookURL sets the Discord webhook URL
func (w *WebhookService) SetWebhookURL(url string) {
	w.webhookURL = url
	w.enabled = url != ""
}

// IsEnabled returns whether the webhook is enabled
func (w *WebhookService) IsEnabled() bool {
	return w.enabled && w.webhookURL != ""
}

// Discord color constants
const (
	ColorRed    = 0xFF0000 // Attack/Error
	ColorOrange = 0xFFAA00 // Warning/Block
	ColorGreen  = 0x00FF00 // Success
	ColorBlue   = 0x00AAFF // Info
)

// SendAttackAlert sends an attack detection alert to Discord
func (w *WebhookService) SendAttackAlert(sourceIP, countryCode, attackType string, pps int64, action string) error {
	if !w.IsEnabled() {
		return nil
	}

	embed := DiscordEmbed{
		Title:       "🚨 Attack Detected",
		Description: fmt.Sprintf("Suspicious traffic detected from **%s**", sourceIP),
		Color:       ColorRed,
		Fields: []DiscordEmbedField{
			{Name: "Source IP", Value: fmt.Sprintf("`%s`", sourceIP), Inline: true},
			{Name: "Country", Value: countryCode, Inline: true},
			{Name: "Attack Type", Value: attackType, Inline: true},
			{Name: "PPS", Value: fmt.Sprintf("%d", pps), Inline: true},
			{Name: "Action", Value: action, Inline: true},
		},
		Footer: &DiscordEmbedFooter{
			Text: "KG-Proxy Security",
		},
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	return w.sendEmbed(embed)
}

// SendBlockAlert sends an IP block notification to Discord
func (w *WebhookService) SendBlockAlert(sourceIP, countryCode, reason string) error {
	if !w.IsEnabled() {
		return nil
	}

	embed := DiscordEmbed{
		Title:       "🛡️ IP Blocked",
		Description: fmt.Sprintf("IP address **%s** has been blocked", sourceIP),
		Color:       ColorOrange,
		Fields: []DiscordEmbedField{
			{Name: "Source IP", Value: fmt.Sprintf("`%s`", sourceIP), Inline: true},
			{Name: "Country", Value: countryCode, Inline: true},
			{Name: "Reason", Value: reason, Inline: false},
		},
		Footer: &DiscordEmbedFooter{
			Text: "KG-Proxy Security",
		},
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	return w.sendEmbed(embed)
}

// SendTestAlert sends a test notification to verify webhook connectivity
func (w *WebhookService) SendTestAlert() error {
	if !w.IsEnabled() {
		return fmt.Errorf("webhook not configured")
	}

	embed := DiscordEmbed{
		Title:       "✅ Webhook Test",
		Description: "Discord webhook is configured correctly!",
		Color:       ColorGreen,
		Fields: []DiscordEmbedField{
			{Name: "Status", Value: "Connected", Inline: true},
			{Name: "Server Time", Value: time.Now().Format("2006-01-02 15:04:05"), Inline: true},
		},
		Footer: &DiscordEmbedFooter{
			Text: "KG-Proxy Security",
		},
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	return w.sendEmbed(embed)
}

// sendEmbed sends a Discord embed message
func (w *WebhookService) sendEmbed(embed DiscordEmbed) error {
	payload := DiscordWebhookPayload{
		Username:  "KG-Proxy",
		AvatarURL: "https://i.imgur.com/4M34hi2.png", // Shield icon
		Embeds:    []DiscordEmbed{embed},
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal webhook payload: %w", err)
	}

	req, err := http.NewRequest("POST", w.webhookURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create webhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := w.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send webhook: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook returned error status: %d", resp.StatusCode)
	}

	system.Info("Discord webhook sent successfully")
	return nil
}
