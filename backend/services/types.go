package services

import (
	"encoding/binary"
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
