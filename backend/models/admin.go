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
	ID                uint      `gorm:"primaryKey" json:"id"`
	GlobalProtection  bool      `gorm:"default:true" json:"global_protection"`
	BlockVPN          bool      `gorm:"default:false" json:"block_vpn"`
	BlockTOR          bool      `gorm:"default:false" json:"block_tor"`
	SYNCookies        bool      `gorm:"default:true" json:"syn_cookies"`
	ProtectionLevel   int       `gorm:"default:2" json:"protection_level"`       // 0=low, 1=standard, 2=high
	GeoAllowCountries string    `gorm:"default:'KR'" json:"geo_allow_countries"` // Comma-separated country codes
	SmartBanning      bool      `gorm:"default:false" json:"smart_banning"`
	EBPFEnabled       bool      `gorm:"default:false" json:"ebpf_enabled"`
	UpdatedAt         time.Time `json:"updated_at"`
}
