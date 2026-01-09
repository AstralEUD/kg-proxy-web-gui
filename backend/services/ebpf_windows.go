//go:build windows

package services

import (
	"time"

	"gorm.io/gorm"
)

// EBPFService stub for Windows (eBPF is Linux-only)
type EBPFService struct {
	enabled bool
}

// NewEBPFService creates a stub service on Windows
func NewEBPFService() *EBPFService {
	return &EBPFService{enabled: false}
}

func (e *EBPFService) SetGeoIPService(g *GeoIPService)                        {}
func (e *EBPFService) SetDatabase(db *gorm.DB)                                {}
func (e *EBPFService) Enable() error                                          { return nil }
func (e *EBPFService) Disable()                                               {}
func (e *EBPFService) IsEnabled() bool                                        { return false }
func (e *EBPFService) GetTrafficData() []TrafficEntry                         { return nil }
func (e *EBPFService) GetStats() map[string]interface{}                       { return nil }
func (e *EBPFService) AddBlockedIP(ip string, duration time.Duration) error   { return nil }
func (e *EBPFService) RemoveBlockedIP(ip string) error                        { return nil }
func (e *EBPFService) UpdateGeoIPData()                                       {}
func (e *EBPFService) StartAutoResetLoop(db *gorm.DB)                         {}
func (e *EBPFService) UpdateConfig(hardBlocking bool, rateLimitPPS int) error { return nil }
func (e *EBPFService) GetPortStats() []PortStats                              { return nil }
func (e *EBPFService) ResetTrafficStats() error                               { return nil }
func (e *EBPFService) UpdateAllowIPs(ips []string) error                      { return nil }

// PortStats dummy struct for method signature
type PortStats struct {
	Port    uint16
	Packets uint64
	Bytes   uint64
}
