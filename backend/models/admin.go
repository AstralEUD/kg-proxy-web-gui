package models

import (
	"time"
)

type Admin struct {
	ID                uint       `gorm:"primaryKey" json:"id"`
	Username          string     `gorm:"unique;not null" json:"username"`
	Password          string     `gorm:"not null" json:"-"` // Stored hashed
	CreatedAt         time.Time  `json:"created_at"`
	FailedAttempts    int        `gorm:"default:0" json:"-"`
	LastFailedAttempt *time.Time `json:"-"`
	LockedUntil       *time.Time `json:"-"`
}

// SecuritySettings for Policy/Firewall configuration
type SecuritySettings struct {
	ID                        uint       `gorm:"primaryKey" json:"id"`
	GlobalProtection          bool       `gorm:"default:true" json:"global_protection"`
	BlockVPN                  bool       `gorm:"default:false" json:"block_vpn"`
	BlockTOR                  bool       `gorm:"default:false" json:"block_tor"`
	SYNCookies                bool       `gorm:"default:true" json:"syn_cookies"`
	ProtectionLevel           int        `gorm:"default:2" json:"protection_level"`       // 0=low, 1=standard, 2=high
	GeoAllowCountries         string     `gorm:"default:'KR'" json:"geo_allow_countries"` // Comma-separated country codes
	SmartBanning              bool       `gorm:"default:false" json:"smart_banning"`
	SteamQueryBypass          bool       `gorm:"default:true" json:"steam_query_bypass"` // Allow Steam A2S queries globally
	EBPFEnabled               bool       `gorm:"default:false" json:"ebpf_enabled"`
	TrafficStatsResetInterval int        `gorm:"default:0" json:"traffic_stats_reset_interval"` // Hours, 0=disabled
	LastTrafficStatsReset     *time.Time `json:"last_traffic_stats_reset"`
	MaxMindLicenseKey         string     `json:"maxmind_license_key,omitempty"` // MaxMind GeoLite2 license key

	// XDP Advanced Settings
	XDPHardBlocking bool `gorm:"default:false" json:"xdp_hard_blocking"` // Drop packets at XDP level instead of passing to iptables
	XDPRateLimitPPS int  `gorm:"default:0" json:"xdp_rate_limit_pps"`    // Per-IP PPS limit, 0=disabled

	// Discord Webhook Notifications
	DiscordWebhookURL string `json:"discord_webhook_url,omitempty"`
	AlertOnAttack     bool   `gorm:"default:true" json:"alert_on_attack"` // Send alert when attack detected
	AlertOnBlock      bool   `gorm:"default:false" json:"alert_on_block"` // Send alert when IP blocked

	// IP Intelligence (VPN/Proxy Detection)
	IPIntelligenceEnabled bool   `gorm:"default:false" json:"ip_intelligence_enabled"`
	IPIntelligenceAPIKey  string `json:"ip_intelligence_api_key,omitempty"` // IPinfo.io API key

	// Data Retention
	AttackHistoryDays int `gorm:"default:30" json:"attack_history_days"` // Days to keep attack history

	// Maintenance Mode (Temporarily disable all blocking)
	MaintenanceUntil *time.Time `json:"maintenance_until,omitempty"` // If set and not expired, all blocking is disabled

	// === NEW FEATURE FLAGS (v1.15.0) ===
	// Block Map TTL: Auto-expire rate-limited IPs
	EnableBlockTTL  bool `gorm:"default:false" json:"enable_block_ttl"`
	BlockTTLMinutes int  `gorm:"default:5" json:"block_ttl_minutes"` // TTL for auto-blocked IPs (default 5 min)

	// 2-Stage UDP Rate Limit: Separate limits for NEW vs ESTABLISHED connections
	EnableTwoStageUDP bool `gorm:"default:false" json:"enable_two_stage_udp"`
	UDPNewPPSLimit    int  `gorm:"default:1000" json:"udp_new_pps_limit"`     // PPS limit for NEW UDP (default 1000)
	UDPEstablishedPPS int  `gorm:"default:100000" json:"udp_established_pps"` // PPS limit for ESTABLISHED UDP (default 100K)

	// Packet Validation: Drop invalid packets at XDP level
	EnablePacketValidation bool `gorm:"default:false" json:"enable_packet_validation"`

	UpdatedAt time.Time `json:"updated_at"`
}
