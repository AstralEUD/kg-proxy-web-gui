package services

import (
	"encoding/binary"
	"kg-proxy-web-gui/backend/models"
	"net"
	"time"
)

// TrafficEntry represents a single traffic record
type TrafficEntry struct {
	SourceIP    string
	DestPort    int
	Protocol    string
	PacketCount int
	ByteCount   int64
	Timestamp   time.Time
	Blocked     bool
	CountryCode string
}

// ipToUint32 converts IP to uint32 in Big Endian (Network Byte Order)
func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return binary.BigEndian.Uint32(ip)
}

// uint32ToIP converts Big Endian uint32 back to IP
func uint32ToIP(n uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, n)
	return ip
}

// DetailedTrafficStats extends TrafficSnapshot with breakdown
type DetailedTrafficStats struct {
	models.TrafficSnapshot
	RateLimitedPPS int64 `json:"rate_limited_pps"`
	InvalidPPS     int64 `json:"invalid_pps"`
	GeoIPBlockPPS  int64 `json:"geoip_block_pps"`
	TotalPackets   int64 `json:"total_packets"`   // Cumulative
	BlockedPackets int64 `json:"blocked_packets"` // Cumulative
}

type RawTrafficStats struct {
	TotalPackets       int64
	BlockedPackets     int64
	RateLimitedPackets int64
	InvalidPackets     int64
	GeoIPPackets       int64
	NetworkRX          int64
	NetworkTX          int64
}

// BlockedIPInfo is the API response format
type BlockedIPInfo struct {
	IP        string    `json:"ip"`
	Reason    string    `json:"reason"`      // "manual", "rate_limit", "geoip", "flood"
	ExpiresAt time.Time `json:"expires_at"`  // Zero time if permanent
	TTL       int64     `json:"ttl_seconds"` // Remaining seconds, -1 if permanent
}
