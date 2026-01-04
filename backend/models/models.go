package models

import (
	"time"
)

type Origin struct {
	ID                 uint      `gorm:"primaryKey" json:"id"`
	Name               string    `gorm:"unique;not null" json:"name"`
	WgIP               string    `gorm:"not null" json:"wg_ip"`
	ReforgerGamePort   int       `gorm:"default:20001" json:"reforger_game_port"`
	ReforgerBrowserPort int      `gorm:"default:17777" json:"reforger_browser_port"`
	ReforgerA2SPort    int       `gorm:"default:27016" json:"reforger_a2s_port"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
	Services           []Service `gorm:"foreignKey:OriginID" json:"services,omitempty"`
}

type Service struct {
	ID                uint      `gorm:"primaryKey" json:"id"`
	Name              string    `gorm:"unique;not null" json:"name"`
	OriginID          uint      `gorm:"not null" json:"origin_id"`
	Origin            Origin    `json:"-"`
	PublicGamePort    int       `gorm:"not null" json:"public_game_port"`
	PublicBrowserPort int       `gorm:"not null" json:"public_browser_port"`
	PublicA2SPort     int       `gorm:"not null" json:"public_a2s_port"`
	CreatedAt         time.Time `json:"created_at"`
}

type AllowForeign struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	IP        string    `gorm:"unique;not null" json:"ip"`
	Label     string    `json:"label"`
	ExpiresAt *time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

type BanIP struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	IP        string    `gorm:"unique;not null" json:"ip"`
	Reason    string    `json:"reason"`
	IsAuto    bool      `gorm:"default:false" json:"is_auto"`
	ExpiresAt *time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

type WireGuardPeer struct {
	ID            uint      `gorm:"primaryKey" json:"id"`
	OriginID      uint      `gorm:"unique;not null" json:"origin_id"`
	PublicKey     string    `gorm:"unique;not null" json:"public_key"`
	PrivateKey    string    `gorm:"not null" json:"-"` // Never expose private key JSON
	LastHandshake *time.Time `json:"last_handshake"`
	RxBytes       int64     `gorm:"default:0" json:"rx_bytes"`
	TxBytes       int64     `gorm:"default:0" json:"tx_bytes"`
	CreatedAt     time.Time `json:"created_at"`
}

// Config struct for non-db settings
type SystemConfig struct {
	AllowKREnabled bool `json:"allow_kr_enabled"`
	FloodProtection FloodConfig `json:"flood_protection"`
}

type FloodConfig struct {
	A2SPPSAbove     int `json:"a2s_pps_above"`
	A2SEBurst       int `json:"a2s_burst"`
	BrowserPPSAbove int `json:"browser_pps_above"`
	BrowserBurst    int `json:"browser_burst"`
	GamePPSAbove    int `json:"game_pps_above"`
	GameBurst       int `json:"game_burst"`
}
