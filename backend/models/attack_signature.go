package models

import "time"

// AttackSignature represents a known attack pattern for classification
type AttackSignature struct {
	ID        uint       `gorm:"primaryKey" json:"id"`
	Name      string     `gorm:"unique;not null" json:"name"`     // e.g., "DNS Amplification"
	Category  string     `gorm:"not null" json:"category"`        // reflection, direct, application
	Protocol  string     `gorm:"not null" json:"protocol"`        // UDP, TCP, ICMP
	SrcPort   int        `gorm:"default:0" json:"src_port"`       // Source port (0 = any)
	DstPort   int        `gorm:"default:0" json:"dst_port"`       // Destination port (0 = any)
	Payload   string     `json:"payload,omitempty"`               // Hex pattern (e.g., "ffffffff")
	Action    string     `gorm:"default:'log'" json:"action"`     // log, rate_limit, block
	PPSLimit  int        `gorm:"default:100" json:"pps_limit"`    // PPS threshold for rate_limit action
	IsBuiltin bool       `gorm:"default:false" json:"is_builtin"` // True for default signatures
	Enabled   bool       `gorm:"default:true" json:"enabled"`
	HitCount  int64      `gorm:"default:0" json:"hit_count"` // Number of times matched
	LastHit   *time.Time `json:"last_hit,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
}

// SeedDefaultSignatures returns default attack signatures
func SeedDefaultSignatures() []AttackSignature {
	return []AttackSignature{
		{
			Name:      "DNS Amplification",
			Category:  "reflection",
			Protocol:  "UDP",
			SrcPort:   53,
			Action:    "rate_limit",
			PPSLimit:  100,
			IsBuiltin: true,
			Enabled:   true,
		},
		{
			Name:      "NTP Amplification",
			Category:  "reflection",
			Protocol:  "UDP",
			SrcPort:   123,
			Action:    "rate_limit",
			PPSLimit:  100,
			IsBuiltin: true,
			Enabled:   true,
		},
		{
			Name:      "SSDP Amplification",
			Category:  "reflection",
			Protocol:  "UDP",
			SrcPort:   1900,
			Action:    "rate_limit",
			PPSLimit:  50,
			IsBuiltin: true,
			Enabled:   true,
		},
		{
			Name:      "Memcached Amplification",
			Category:  "reflection",
			Protocol:  "UDP",
			SrcPort:   11211,
			Action:    "block",
			PPSLimit:  10,
			IsBuiltin: true,
			Enabled:   true,
		},
		{
			Name:      "CHARGEN Amplification",
			Category:  "reflection",
			Protocol:  "UDP",
			SrcPort:   19,
			Action:    "block",
			PPSLimit:  10,
			IsBuiltin: true,
			Enabled:   true,
		},
		{
			Name:      "Steam A2S Query",
			Category:  "game_query",
			Protocol:  "UDP",
			Payload:   "ffffffff",
			Action:    "log",
			PPSLimit:  500,
			IsBuiltin: true,
			Enabled:   true,
		},
	}
}
