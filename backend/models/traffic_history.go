package models

import (
	"time"
)

// TrafficSnapshot stores periodic traffic statistics for time-series analysis
type TrafficSnapshot struct {
	ID             uint      `gorm:"primaryKey" json:"id"`
	Timestamp      time.Time `gorm:"index" json:"timestamp"`
	TotalPPS       int64     `json:"total_pps"`       // Packets per second
	TotalBPS       int64     `json:"total_bps"`       // Bytes per second
	AllowedPPS     int64     `json:"allowed_pps"`     // Allowed packets per second
	BlockedPPS     int64     `json:"blocked_pps"`     // Blocked packets per second
	TotalPackets   int64     `json:"total_packets"`   // Cumulative total packets (at snapshot time)
	BlockedPackets int64     `json:"blocked_packets"` // Cumulative blocked packets (at snapshot time)
	UniqueIPs      int       `json:"unique_ips"`      // Number of unique source IPs
	TopCountry     string    `json:"top_country"`     // Most active country code
	NetworkRX      int64     `json:"network_rx"`      // Network RX bytes per second
	NetworkTX      int64     `json:"network_tx"`      // Network TX bytes per second
	CPUUsage       int       `json:"cpu_usage"`       // CPU usage percentage
	MemoryUsage    int       `json:"memory_usage"`    // Memory usage percentage
}

// AttackEvent records detected attacks and automatic responses
type AttackEvent struct {
	ID          uint      `gorm:"primaryKey" json:"id"`
	Timestamp   time.Time `gorm:"index" json:"timestamp"`
	SourceIP    string    `gorm:"index" json:"source_ip"`
	CountryCode string    `json:"country_code"`
	CountryName string    `json:"country_name"`
	AttackType  string    `json:"attack_type"` // "flood", "geoip_violation", "blacklist", "rate_limit"
	PPS         int64     `json:"pps"`         // Packets per second at detection
	BPS         int64     `json:"bps"`         // Bytes per second at detection
	Duration    int       `json:"duration"`    // Attack duration in seconds (if known)
	Action      string    `json:"action"`      // "blocked", "rate_limited", "warned"
	Details     string    `json:"details"`     // Additional details (JSON or text)
}

// AttackStats provides aggregated attack statistics
type AttackStats struct {
	TodayCount    int64  `json:"today_count"`
	WeekCount     int64  `json:"week_count"`
	MonthCount    int64  `json:"month_count"`
	TopAttackType string `json:"top_attack_type"`
	TopCountry    string `json:"top_country"`
	TopAttackerIP string `json:"top_attacker_ip"`
	TotalBlocked  int64  `json:"total_blocked"`
}
