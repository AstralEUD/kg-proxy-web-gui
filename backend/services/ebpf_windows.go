//go:build windows

package services

import (
	"time"
)

// EBPFService stub for Windows (eBPF is Linux-only)
type EBPFService struct {
	enabled bool
}

// NewEBPFService creates a stub service on Windows
func NewEBPFService() *EBPFService {
	return &EBPFService{enabled: false}
}

func (e *EBPFService) SetGeoIPService(g *GeoIPService)                      {}
func (e *EBPFService) Enable() error                                        { return nil }
func (e *EBPFService) Disable()                                             {}
func (e *EBPFService) IsEnabled() bool                                      { return false }
func (e *EBPFService) GetTrafficData() []TrafficEntry                       { return nil }
func (e *EBPFService) GetStats() map[string]interface{}                     { return nil }
func (e *EBPFService) AddBlockedIP(ip string, duration time.Duration) error { return nil }
func (e *EBPFService) RemoveBlockedIP(ip string) error                      { return nil }
func (e *EBPFService) UpdateGeoIPData()                                     {}
