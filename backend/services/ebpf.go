//go:build linux

package services

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"kg-proxy-web-gui/backend/models"
	"kg-proxy-web-gui/backend/system"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"gorm.io/gorm"
)

//go:generate bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" xdp ../ebpf/xdp_filter.c -- -I/usr/include/x86_64-linux-gnu
//go:generate bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" tc ../ebpf/tc_egress.c -- -I/usr/include/x86_64-linux-gnu

// PacketStats matches the C struct
type PacketStats struct {
	Packets  uint64
	Bytes    uint64
	LastSeen uint64
	Blocked  uint32
	_        uint32 // padding
}

// LpmKey matches the C struct lpm_key
type LpmKey struct {
	PrefixLen uint32
	Data      [4]uint8
}

// BlockEntry matches the C struct block_entry
type BlockEntry struct {
	ExpiresAt uint64
	Reason    uint32
	Pad       uint32
}

// AggregatedEvent for smart batching
type AggregatedEvent struct {
	SourceIP  uint32
	Reason    uint32
	Count     int64
	FirstSeen time.Time
	LastSeen  time.Time
}

// EBPFService manages eBPF/XDP traffic monitoring
type EBPFService struct {
	enabled     bool
	trafficData []TrafficEntry
	mu          sync.RWMutex
	stopChan    chan struct{}
	isRunning   bool

	// Event Aggregation
	eventChan chan AggregatedEvent
	// Real eBPF objects - using interface{} to avoid build errors when generated files are missing
	// In production (Linux build), this will hold *xdpObjects
	objs         interface{}
	link         link.Link
	geoIPService *GeoIPService

	// Interface name
	ifaceName string

	// Boot time for timestamp conversion
	bootTime time.Time

	// Database for snapshots
	db *gorm.DB

	// For snapshot calculations
	lastSnapshot           time.Time
	prevNetworkRX          int64
	prevNetworkTX          int64
	prevTotalPackets       int64
	prevBlockedPackets     int64
	prevRateLimitedPackets int64
	prevInvalidPackets     int64
	prevGeoIPPackets       int64

	// State for log suppression
	lastGeoIPCount int

	// TC egress connection tracking
	tcObjs           interface{}
	tcLink           link.Link
	tcLegacyAttached bool   // True if legacy tc command was used
	tcLegacyIface    string // Interface name for legacy cleanup
	bpfPinPath       string // Path to pinned BPF maps

	// RingBuffer
	ringBuf *ringbuf.Reader
}

func NewEBPFService() *EBPFService {
	// Calculate boot time to handle monotonic timestamps
	// We use the SysInfoService or just standard uptime

	now := time.Now()
	boot := now // Default fallback

	if runtime.GOOS == "linux" {
		// Read /proc/uptime
		// simplified for now, assuming uptime is roughly correct
		// If we can't read it, we use Now (last seen will be relative to now, which is wrong but safe)
		// We'll rely on the fact that value.LastSeen is monotonic ns
		// We need relative offset: Now - MonotonicNow
		// But getting MonotonicNow in Go is internal.
		// Approximating:
		// timestamp = bootTime + monotonic
	}

	// Better: Use a helper
	boot = GetBootTime()

	// Initial interface detection
	ifaceName := system.GetDefaultInterface()

	return &EBPFService{
		enabled:      false,
		trafficData:  make([]TrafficEntry, 0),
		stopChan:     make(chan struct{}),
		ifaceName:    ifaceName,
		bootTime:     boot,
		lastSnapshot: time.Now(),
		bpfPinPath:   "/sys/fs/bpf/kg_proxy",
		eventChan:    make(chan AggregatedEvent, 10000), // Buffer size for high PPS
	}
}

// SetGeoIPService sets the GeoIP service for country lookups
func (e *EBPFService) SetGeoIPService(geoip *GeoIPService) {
	e.geoIPService = geoip
}

// SetDatabase sets the database reference for snapshot storage
func (e *EBPFService) SetDatabase(db *gorm.DB) {
	e.db = db
}

// Enable starts eBPF monitoring
func (e *EBPFService) Enable() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.isRunning {
		return nil
	}

	// Only try real eBPF on Linux
	if runtime.GOOS != "linux" {
		return fmt.Errorf("eBPF is only supported on Linux")
	}

	// Try to load real eBPF program
	if err := e.loadEBPFProgram(); err != nil {
		return fmt.Errorf("failed to load eBPF program: %w", err)
	}

	e.enabled = true
	e.isRunning = true
	e.stopChan = make(chan struct{})

	// Start real traffic collection from eBPF maps
	go e.collectTrafficFromEBPF()

	// Start GeoIP map sync loop (retry initially to catch up with GeoIP DB load)
	go e.startGeoIPSyncLoop()

	// Start Event Aggregator (Smart Batching)
	go e.startEventAggregator()

	system.Info("eBPF XDP filter loaded and attached to %s", e.ifaceName)
	return nil
}

// ByteOrder converters
func intToIP(nn uint32) string {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, nn)
	return ip.String()
}

// startEventAggregator processes events from RingBuffer with smart batching
func (e *EBPFService) startEventAggregator() {
	// Aggregation Map: Key "IP-Reason" -> *AggregatedEvent
	// We use string key because we can't use struct as map key if it contains slices usually, but here struct is simple.
	// Using struct key directly is faster.
	type AggKey struct {
		SrcIP  uint32
		Reason uint32
	}

	aggMap := make(map[AggKey]*AggregatedEvent)

	// Batch Interval: 3 Seconds (per user request)
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	flush := func() {
		if len(aggMap) == 0 {
			return
		}

		batch := make([]models.AttackEvent, 0, len(aggMap))

		// Hard limit batch size to prevent DB choke (e.g., 2000 events per flush)
		// If more than 2000 unique IP+Reason pairs, we might need multiple flushes or drop some.
		// For now, we process all but use CreateInBatches.

		for _, agg := range aggMap {
			ipStr := intToIP(agg.SourceIP)

			// Get Country
			countryName := "Unknown"
			countryCode := "XX"
			if e.geoIPService != nil {
				countryName, countryCode = e.geoIPService.GetCountry(ipStr)
			}

			// Map Reason Code to String
			// #define BLOCK_REASON_MANUAL     1
			// #define BLOCK_REASON_RATE_LIMIT 2
			// #define BLOCK_REASON_GEOIP      3
			// #define BLOCK_REASON_FLOOD      4
			reasonStr := "unknown"
			switch agg.Reason {
			case 1:
				reasonStr = "blacklist"
			case 2:
				reasonStr = "rate_limit"
			case 3:
				reasonStr = "geoip_violation"
			case 4:
				reasonStr = "flood"
			}

			// Calculate PPS (Average over the batch interval, or just store count)
			// Storing total count in 'Count' field.
			// PPS = Count / 3 (since batch is 3s)
			pps := agg.Count / 3
			if pps == 0 && agg.Count > 0 {
				pps = 1
			}

			batch = append(batch, models.AttackEvent{
				Timestamp:   agg.FirstSeen, // Use first seen time for the record
				SourceIP:    ipStr,
				CountryCode: countryCode,
				CountryName: countryName,
				AttackType:  reasonStr,
				PPS:         pps,
				Count:       agg.Count,
				Action:      "blocked",
				Details:     fmt.Sprintf("Blocked %d packets in 3s batch", agg.Count),
			})
		}

		// Save to DB
		if e.db != nil && len(batch) > 0 {
			if err := e.db.CreateInBatches(batch, 100).Error; err != nil {
				system.Warn("Failed to save batched attack events: %v", err)
			}
		}

		// Reset map
		aggMap = make(map[AggKey]*AggregatedEvent)
	}

	for {
		select {
		case <-e.stopChan:
			flush() // Flush remaining before exit
			return
		case event := <-e.eventChan:
			key := AggKey{SrcIP: event.SourceIP, Reason: event.Reason}
			if agg, exists := aggMap[key]; exists {
				agg.Count++
				agg.LastSeen = event.LastSeen
			} else {
				// Safety: Prevent OOM if too many unique IPs
				if len(aggMap) > 50000 {
					continue // Drop event if map is too full (Under attack by >50k unique IPs)
				}
				aggMap[key] = &event
			}
		case <-ticker.C:
			flush()
		}
	}
}

// loadEBPFProgram loads the compiled eBPF program
func (e *EBPFService) loadEBPFProgram() error {
	// Detect network interface
	iface, err := e.detectInterface()
	if err != nil {
		return fmt.Errorf("failed to detect network interface: %w", err)
	}
	e.ifaceName = iface.Name

	// Create BPF pin directory for map sharing
	if err := os.MkdirAll(e.bpfPinPath, 0755); err != nil {
		system.Warn("Failed to create BPF pin directory %s: %v", e.bpfPinPath, err)
	}

	// Load pre-compiled eBPF objects with pinning support
	// Note: xdpObjects is generated by bpf2go.
	objs := &xdpObjects{}
	opts := &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: e.bpfPinPath,
		},
	}
	if err := loadXdpObjects(objs, opts); err != nil {
		return fmt.Errorf("loading eBPF objects: %w", err)
	}
	e.objs = objs

	// Initialize Ring Buffer
	if eventsMap := objs.xdpMaps.Events; eventsMap != nil {
		rb, err := ringbuf.NewReader(eventsMap)
		if err != nil {
			system.Warn("Failed to create ringbuf reader: %v", err)
		} else {
			e.ringBuf = rb
			go e.consumeRingBuffer()
		}
	}

	// Populate GeoIP map before attaching to avoid dropping all traffic in hard blocking mode
	if err := e.UpdateGeoIPData(); err != nil {
		system.Warn("Failed to populate GeoIP map initially: %v", err)
	}

	// Attach XDP program to interface
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpTrafficFilter,
		Interface: iface.Index,
	})
	if err != nil {
		objs.Close()
		return fmt.Errorf("attaching XDP program: %w", err)
	}
	e.link = l

	// Load and attach TC egress program for connection tracking
	if err := e.loadTCProgram(); err != nil {
		system.Warn("Failed to load TC egress program: %v (connection tracking disabled)", err)
	} else {
		system.Info("TC egress connection tracking enabled")
	}

	// Initialize BPF maps with GeoIP data
	if e.geoIPService != nil {
		e.UpdateGeoIPData()
	}

	// Sync Allowed Ports (Dynamic Game Ports)
	if err := e.SyncAllowedPorts(); err != nil {
		system.Warn("Failed to sync allowed ports on startup: %v", err)
	}

	// Sync Whitelist (DB + Critical DNS)
	if err := e.SyncWhitelist(); err != nil {
		system.Warn("Failed to sync whitelist on startup: %v", err)
	}

	return nil
}

// loadTCProgram loads the TC egress program for connection tracking
func (e *EBPFService) loadTCProgram() error {
	// Attach TC to the WAN interface (same as XDP)
	// Origin outbound: wg0 -> routing -> NAT -> WAN egress -> Internet
	// Internet inbound: WAN ingress (XDP) -> de-NAT -> wg0 -> Origin
	// So we track on WAN egress to catch Origin's outbound traffic

	// Use the same interface that XDP is attached to
	wanIface, err := net.InterfaceByName(e.ifaceName)
	if err != nil {
		return fmt.Errorf("WAN interface %s not found: %w", e.ifaceName, err)
	}

	// Load TC objects with same pin path to share active_connections map
	tcObjs := &tcObjects{}
	opts := &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: e.bpfPinPath,
		},
	}
	if err := loadTcObjects(tcObjs, opts); err != nil {
		return fmt.Errorf("loading TC objects: %w", err)
	}
	e.tcObjs = tcObjs

	// Try modern TCX first (kernel >= 6.6), then fallback to legacy netlink
	tcLink, err := link.AttachTCX(link.TCXOptions{
		Interface: wanIface.Index,
		Program:   tcObjs.TcEgressTrack,
		Attach:    ebpf.AttachTCXEgress,
	})
	if err == nil {
		e.tcLink = tcLink
		system.Info("TC egress attached to %s via TCX (kernel >= 6.6)", e.ifaceName)
		return nil
	}

	// Fallback: Use legacy netlink-based TC attachment for older kernels
	system.Warn("TCX not supported, trying legacy TC attachment: %v", err)

	if err := e.attachTCLegacy(wanIface.Index, tcObjs.TcEgressTrack); err != nil {
		tcObjs.Close()
		return fmt.Errorf("legacy TC attachment failed: %w", err)
	}

	system.Info("TC egress attached to %s via legacy netlink", e.ifaceName)
	return nil
}

// attachTCLegacy uses the tc command to attach the BPF program for older kernels
func (e *EBPFService) attachTCLegacy(ifIndex int, prog *ebpf.Program) error {
	// Get interface name from index
	iface, err := net.InterfaceByIndex(ifIndex)
	if err != nil {
		return fmt.Errorf("interface lookup failed: %w", err)
	}

	// Pin the program so tc can load it
	progPinPath := filepath.Join(e.bpfPinPath, "tc_egress_prog")
	// Clean up old pin file to prevent version mismatch on restart
	os.Remove(progPinPath)
	if err := prog.Pin(progPinPath); err != nil && !os.IsExist(err) {
		return fmt.Errorf("pinning TC program: %w", err)
	}

	// Create clsact qdisc if not exists (ignore error if already exists)
	exec.Command("tc", "qdisc", "del", "dev", iface.Name, "clsact").Run()
	if out, err := exec.Command("tc", "qdisc", "add", "dev", iface.Name, "clsact").CombinedOutput(); err != nil {
		return fmt.Errorf("creating clsact qdisc: %s: %w", string(out), err)
	}

	// Attach BPF program to egress
	out, err := exec.Command("tc", "filter", "add", "dev", iface.Name, "egress",
		"bpf", "direct-action", "pinned", progPinPath).CombinedOutput()
	if err != nil {
		return fmt.Errorf("attaching TC filter: %s: %w", string(out), err)
	}

	e.tcLegacyAttached = true
	e.tcLegacyIface = iface.Name
	return nil
}

// detectInterface finds the primary network interface
func (e *EBPFService) detectInterface() (*net.Interface, error) {
	// Try the primary detection method first
	name := system.GetDefaultInterface()
	iface, err := net.InterfaceByName(name)
	if err == nil && iface.Flags&net.FlagUp != 0 {
		return iface, nil
	}

	// Double check: find first non-loopback interface that is UP
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to list network interfaces: %w", err)
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagLoopback == 0 {
			name := strings.ToLower(iface.Name)
			// Skip known virtual/internal interfaces
			if !strings.HasPrefix(name, "lo") && !strings.HasPrefix(name, "wg") && !strings.HasPrefix(name, "docker") && !strings.HasPrefix(name, "veth") && !strings.HasPrefix(name, "br-") {
				return &iface, nil
			}
		}
	}

	return nil, fmt.Errorf("no suitable network interface found")
}

// UpdateGeoIPData populates the geo_allowed BPF map
func (e *EBPFService) UpdateGeoIPData() error {
	if e.objs == nil || e.geoIPService == nil {
		return nil
	}

	objs, ok := e.objs.(*xdpObjects)
	if !ok {
		return nil
	}

	// system.Info("Populating GeoIP BPF map...")
	count := 0

	allCIDRs := e.geoIPService.GetAllCountryCIDRs()

	for country, cidrs := range allCIDRs {
		if len(country) < 2 {
			continue
		}
		// Convert country code (e.g., "KR") to 16-bit int
		c0 := strings.ToUpper(country)[0]
		c1 := strings.ToUpper(country)[1]
		countryCode := uint32(c0)<<8 | uint32(c1)

		for _, cidr := range cidrs {
			_, ipNet, err := net.ParseCIDR(cidr)
			if err != nil {
				continue
			}
			ip := ipNet.IP.To4()
			if ip == nil {
				continue
			}

			// Use byte array for raw order to match network byte order in BPF
			ones, _ := ipNet.Mask.Size()

			// LPM Trie Key
			key := struct {
				PrefixLen uint32
				Data      [4]byte // Use [4]byte to ensure byte-perfect order
			}{
				PrefixLen: uint32(ones),
			}
			copy(key.Data[:], ip.To4())

			if err := objs.GeoAllowed.Put(key, countryCode); err != nil {
				system.Warn("Failed to add IP to geo_allowed map: %v", err)
				continue
			}
			count++

			// Limit to prevent map overflow
			if count >= 1000000 {
				system.Warn("GeoIP map limit reached, some IPs not added")
				return nil
			}
		}
	}

	if count > 0 && count != e.lastGeoIPCount {
		system.Info("GeoIP BPF map update: %d CIDRs loaded", count)
		e.lastGeoIPCount = count
	} else if count == 0 {
		system.Warn("⚠️ CRITICAL: No GeoIP data loaded! Disabling Hard Blocking to prevent lockout.")
		// Fail-Safe: Disable Hard Blocking if no countries are loaded
		// Index 0 is configuration for Hard Blocking
		configHardBlocking := uint32(0)
		if err := objs.Config.Put(configHardBlocking, uint32(0)); err != nil {
			system.Warn("Failed to apply fail-safe (disable hard blocking): %v", err)
		}
	}
	return nil
}

// collectTrafficFromEBPF reads real data from eBPF maps
func (e *EBPFService) collectTrafficFromEBPF() {
	// Optimization: Reduce polling to 5s to prevent syscall flooding during attacks
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	// Snapshot ticker (1 minute)
	snapshotTicker := time.NewTicker(1 * time.Minute)
	defer snapshotTicker.Stop()

	for {
		select {
		case <-e.stopChan:
			return
		case <-ticker.C:
			e.readEBPFMaps()
		case <-snapshotTicker.C:
			e.saveTrafficSnapshot()
		}
	}
}

// startGeoIPSyncLoop keeps the eBPF GeoIP map in sync with the GeoIP service
func (e *EBPFService) startGeoIPSyncLoop() {
	// Initial retry phase: try frequently for the first 30 seconds
	// directly after startup, GeoIP DB might still be downloading/loading.
	for i := 0; i < 30; i++ {
		time.Sleep(1 * time.Second)
		if !e.isRunning {
			return
		}
		// We blindly attempt update. If GeoIP service has data, it populates map.
		// If not, it does nothing or partial update. It's safe.
		e.UpdateGeoIPData()
	}

	// Long-term sync: update every hour to catch new DB updates
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-e.stopChan:
			return
		case <-ticker.C:
			e.UpdateGeoIPData()
		}
	}
}

// consumeRingBuffer reads events from the Ring Buffer
func (e *EBPFService) consumeRingBuffer() {
	if e.ringBuf == nil {
		return
	}

	// Match C struct event_data
	var event struct {
		SrcIP     uint32
		Reason    uint32
		Timestamp uint64
	}

	for {
		select {
		case <-e.stopChan:
			if e.ringBuf != nil {
				e.ringBuf.Close()
			}
			return
		default:
		}

		record, err := e.ringBuf.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			continue
		}

		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			continue
		}

		// Send to aggregator
		select {
		case e.eventChan <- AggregatedEvent{
			SourceIP:  event.SrcIP,
			Reason:    event.Reason,
			Count:     1,
			FirstSeen: time.Now(),
			LastSeen:  time.Now(),
		}:
		default:
			// Channel full, drop event (safe degradation)
		}
	}
}

// readEBPFMaps reads statistics from eBPF maps
func (e *EBPFService) readEBPFMaps() {
	if e.objs == nil {
		return
	}

	objs, ok := e.objs.(*xdpObjects)
	if !ok {
		return
	}

	// Create new local slice (Double Buffering)
	newTrafficData := make([]TrafficEntry, 0, 1000)

	// Iterate over the map (Per-CPU)
	var key [4]byte
	var values []PacketStats // Per-CPU means value is a slice

	iter := objs.IpStats.Iterate()
	for iter.Next(&key, &values) {
		// Sum up Per-CPU values
		var totalPackets uint64
		var totalBytes uint64
		var lastSeen uint64
		var blocked bool

		for _, v := range values {
			totalPackets += v.Packets
			totalBytes += v.Bytes
			if v.LastSeen > lastSeen {
				lastSeen = v.LastSeen
			}
			if v.Blocked > 0 {
				blocked = true
			}
		}

		// Convert key bytes directly to IP
		ip := net.IPv4(key[0], key[1], key[2], key[3])

		// Get country code
		countryCode := "XX"
		if e.geoIPService != nil {
			countryCode = e.geoIPService.GetCountryCode(ip.String())
		}

		// Create entry
		entry := TrafficEntry{
			SourceIP:    ip.String(),
			DestPort:    0,
			Protocol:    "IP",
			PacketCount: int(totalPackets),
			ByteCount:   int64(totalBytes),
			Timestamp:   e.bootTime.Add(time.Duration(lastSeen)),
			Blocked:     blocked,
			CountryCode: countryCode,
		}

		newTrafficData = append(newTrafficData, entry)

		// Limit entries
		if len(newTrafficData) >= 1000 {
			break
		}
	}

	if err := iter.Err(); err != nil {
		system.Warn("Error iterating ip_stats map: %v", err)
	}

	// Swap pointer (Atomic-like)
	e.mu.Lock()
	e.trafficData = newTrafficData
	e.mu.Unlock()

	// Save periodic snapshot (every 1 minute)
	e.saveTrafficSnapshot()
}

// saveTrafficSnapshot saves traffic statistics to the database for historical analysis
func (e *EBPFService) saveTrafficSnapshot() {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.db == nil {
		return
	}

	now := time.Now()
	if now.Sub(e.lastSnapshot) < 1*time.Minute {
		return
	}

	// Calculate current totals
	var totalPackets, blockedPackets int64
	var totalBytes int64
	countryCount := make(map[string]int)

	// TRY Global Stats first (more accurate)
	usedGlobalStats := false
	if e.objs != nil {
		if objs, ok := e.objs.(*xdpObjects); ok {
			// Helper to sum PerCPU values
			sumPerCPU := func(m *ebpf.Map, key uint32) (int64, error) {
				var values []uint64
				if err := m.Lookup(key, &values); err != nil {
					// Fallback for non-PerCPU maps
					var val uint64
					if err2 := m.Lookup(key, &val); err2 == nil {
						return int64(val), nil
					}
					return 0, err
				}
				var sum int64
				for _, v := range values {
					sum += int64(v)
				}
				return sum, nil
			}

			// STAT_TOTAL_PACKETS = 0
			if val, err := sumPerCPU(objs.GlobalStats, 0); err == nil {
				totalPackets = val
				usedGlobalStats = true
			}
			// STAT_BLOCKED = 2
			if val, err := sumPerCPU(objs.GlobalStats, 2); err == nil {
				blockedPackets = val
			}
			// STAT_TOTAL_BYTES = 1
			if val, err := sumPerCPU(objs.GlobalStats, 1); err == nil {
				totalBytes = val
			}
		}
	}

	// Fallback to iterating trafficData (less accurate, limited to 1000 entries)
	if !usedGlobalStats {
		for _, entry := range e.trafficData {
			totalPackets += int64(entry.PacketCount)
			totalBytes += entry.ByteCount
			if entry.Blocked {
				blockedPackets += int64(entry.PacketCount)
			}
			countryCount[entry.CountryCode]++
		}
	} else {
		// Just for country stats
		for _, entry := range e.trafficData {
			countryCount[entry.CountryCode]++
		}
	}

	// Calculate PPS (packets per second) based on time elapsed
	elapsed := now.Sub(e.lastSnapshot).Seconds()
	if elapsed <= 0 {
		elapsed = 1
	}

	// Calculate delta from previous snapshot
	deltaTotalPackets := totalPackets - e.prevTotalPackets
	deltaBlockedPackets := blockedPackets - e.prevBlockedPackets
	if deltaTotalPackets < 0 {
		deltaTotalPackets = totalPackets // Reset occurred
	}
	if deltaBlockedPackets < 0 {
		deltaBlockedPackets = blockedPackets
	}

	totalPPS := int64(float64(deltaTotalPackets) / elapsed)
	blockedPPS := int64(float64(deltaBlockedPackets) / elapsed)
	allowedPPS := totalPPS - blockedPPS
	if allowedPPS < 0 {
		allowedPPS = 0
	}

	// Get network stats
	sysInfo := NewSysInfoService()
	rxBytes, txBytes := sysInfo.GetNetworkIO()
	networkRX := int64(float64(rxBytes-uint64(e.prevNetworkRX)) / elapsed)
	networkTX := int64(float64(txBytes-uint64(e.prevNetworkTX)) / elapsed)
	if networkRX < 0 {
		networkRX = 0
	}
	if networkTX < 0 {
		networkTX = 0
	}

	// Find top country
	topCountry := "XX"
	maxCount := 0
	for country, count := range countryCount {
		if count > maxCount {
			maxCount = count
			topCountry = country
		}
	}

	// Create snapshot
	snapshot := models.TrafficSnapshot{
		Timestamp:      now,
		TotalPPS:       totalPPS,
		TotalBPS:       int64(float64(totalBytes) / elapsed),
		AllowedPPS:     allowedPPS,
		BlockedPPS:     blockedPPS,
		TotalPackets:   totalPackets,
		BlockedPackets: blockedPackets,
		UniqueIPs:      len(e.trafficData),
		TopCountry:     topCountry,
		NetworkRX:      networkRX,
		NetworkTX:      networkTX,
		CPUUsage:       sysInfo.GetCPUUsage(),
		MemoryUsage:    sysInfo.GetMemoryUsage(),
	}

	// Save to database
	if err := e.db.Create(&snapshot).Error; err != nil {
		system.Warn("Failed to save traffic snapshot: %v", err)
	}

	// Update previous values for next calculation
	e.lastSnapshot = now
	e.prevTotalPackets = totalPackets
	e.prevBlockedPackets = blockedPackets
	e.prevNetworkRX = int64(rxBytes)
	e.prevNetworkTX = int64(txBytes)

	// Cleanup old snapshots (older than 7 days)
	e.cleanupOldSnapshots()
}

// cleanupOldSnapshots removes traffic snapshots older than 7 days
func (e *EBPFService) cleanupOldSnapshots() {
	if e.db == nil {
		return
	}

	cutoff := time.Now().AddDate(0, 0, -7)
	e.db.Where("timestamp < ?", cutoff).Delete(&models.TrafficSnapshot{})
}

// Disable stops eBPF monitoring
func (e *EBPFService) Disable() {
	e.mu.Lock()
	defer e.mu.Unlock()

	if !e.isRunning {
		return
	}

	e.enabled = false
	e.isRunning = false
	close(e.stopChan)

	// Detach eBPF program if loaded
	e.detachEBPF()
}

func (e *EBPFService) detachEBPF() {
	// Detach legacy TC first (if using tc command)
	if e.tcLegacyAttached && e.tcLegacyIface != "" {
		exec.Command("tc", "filter", "del", "dev", e.tcLegacyIface, "egress").Run()
		exec.Command("tc", "qdisc", "del", "dev", e.tcLegacyIface, "clsact").Run()
		e.tcLegacyAttached = false
		system.Info("Legacy TC egress program detached from %s", e.tcLegacyIface)
	}

	// Detach TC egress program (TCX method)
	if e.tcLink != nil {
		e.tcLink.Close()
		e.tcLink = nil
		system.Info("TC egress program detached")
	}

	if e.tcObjs != nil {
		if tcObjs, ok := e.tcObjs.(*tcObjects); ok {
			tcObjs.Close()
		}
		e.tcObjs = nil
	}

	// Detach XDP program
	if e.link != nil {
		e.link.Close()
		e.link = nil
		system.Info("eBPF XDP program detached")
	}

	if e.objs != nil {
		if objs, ok := e.objs.(*xdpObjects); ok {
			objs.Close()
		}
		e.objs = nil
	}

	// Clean up pinned maps
	if e.bpfPinPath != "" {
		os.RemoveAll(e.bpfPinPath)
	}
}

// GetTrafficData returns current traffic data
func (e *EBPFService) GetTrafficData() []TrafficEntry {
	e.mu.RLock()
	defer e.mu.RUnlock()

	data := make([]TrafficEntry, len(e.trafficData))
	copy(data, e.trafficData)
	return data
}

// GetStats returns aggregated statistics
func (e *EBPFService) GetStats() DetailedTrafficStats {
	e.mu.RLock()
	defer e.mu.RUnlock()

	stats, _ := e.getStatsInternal()
	return stats
}

// getStatsInternal calculates current traffic statistics
func (e *EBPFService) getStatsInternal() (DetailedTrafficStats, RawTrafficStats) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	now := time.Now()
	var raw RawTrafficStats
	var totalBytes int64
	countryCount := make(map[string]int)

	if e.objs != nil {
		if objs, ok := e.objs.(*xdpObjects); ok {
			// Helper to sum PerCPU values
			sumPerCPU := func(m *ebpf.Map, key uint32) (int64, error) {
				var values []uint64
				if err := m.Lookup(key, &values); err != nil {
					// Fallback
					var val uint64
					if err2 := m.Lookup(key, &val); err2 == nil {
						return int64(val), nil
					}
					return 0, err
				}
				var sum int64
				for _, v := range values {
					sum += int64(v)
				}
				return sum, nil
			}

			// STAT_TOTAL_PACKETS = 0
			if val, err := sumPerCPU(objs.GlobalStats, 0); err == nil {
				raw.TotalPackets = val
			}
			// STAT_TOTAL_BYTES = 1
			if val, err := sumPerCPU(objs.GlobalStats, 1); err == nil {
				totalBytes = val
			}
			// STAT_BLOCKED = 2
			if val, err := sumPerCPU(objs.GlobalStats, 2); err == nil {
				raw.BlockedPackets = val
			}
			// STAT_RATE_LIMITED = 4
			if val, err := sumPerCPU(objs.GlobalStats, 4); err == nil {
				raw.RateLimitedPackets = val
			}
			// STAT_GEOIP_BLOCKED = 6
			if val, err := sumPerCPU(objs.GlobalStats, 6); err == nil {
				raw.GeoIPPackets = val
			}
			// STAT_PKT_INVALID = 7
			if val, err := sumPerCPU(objs.GlobalStats, 7); err == nil {
				raw.InvalidPackets = val
			}
		}
	}

	for _, entry := range e.trafficData {
		countryCount[entry.CountryCode]++
	}

	elapsed := now.Sub(e.lastSnapshot).Seconds()
	if elapsed <= 0 {
		elapsed = 1
	}

	// Calculate deltas
	deltaTotal := raw.TotalPackets - e.prevTotalPackets
	deltaBlocked := raw.BlockedPackets - e.prevBlockedPackets
	deltaRateLimited := raw.RateLimitedPackets - e.prevRateLimitedPackets
	deltaInvalid := raw.InvalidPackets - e.prevInvalidPackets
	deltaGeoIP := raw.GeoIPPackets - e.prevGeoIPPackets

	if deltaTotal < 0 {
		deltaTotal = raw.TotalPackets
	}
	if deltaBlocked < 0 {
		deltaBlocked = raw.BlockedPackets
	}
	if deltaRateLimited < 0 {
		deltaRateLimited = raw.RateLimitedPackets
	}
	if deltaInvalid < 0 {
		deltaInvalid = raw.InvalidPackets
	}
	if deltaGeoIP < 0 {
		deltaGeoIP = raw.GeoIPPackets
	}

	totalPPS := int64(float64(deltaTotal) / elapsed)
	baseBlockedPPS := int64(float64(deltaBlocked) / elapsed)
	rlPPS := int64(float64(deltaRateLimited) / elapsed)
	invalidPPS := int64(float64(deltaInvalid) / elapsed)
	geoipPPS := int64(float64(deltaGeoIP) / elapsed)

	finalBlockedPPS := baseBlockedPPS + rlPPS + invalidPPS

	allowedPPS := totalPPS - finalBlockedPPS
	if allowedPPS < 0 {
		allowedPPS = 0
	}

	sysInfo := NewSysInfoService()
	rxBytes, txBytes := sysInfo.GetNetworkIO()
	raw.NetworkRX = int64(rxBytes)
	raw.NetworkTX = int64(txBytes)

	networkRX := int64(float64(rxBytes-uint64(e.prevNetworkRX)) / elapsed)
	networkTX := int64(float64(txBytes-uint64(e.prevNetworkTX)) / elapsed)
	if networkRX < 0 {
		networkRX = 0
	}
	if networkTX < 0 {
		networkTX = 0
	}

	topCountry := "XX"
	maxCount := 0
	for country, count := range countryCount {
		if count > maxCount {
			maxCount = count
			topCountry = country
		}
	}

	snapshot := models.TrafficSnapshot{
		Timestamp:   now,
		TotalPPS:    totalPPS,
		TotalBPS:    int64(float64(totalBytes) / elapsed),
		AllowedPPS:  allowedPPS,
		BlockedPPS:  finalBlockedPPS,
		UniqueIPs:   len(e.trafficData),
		TopCountry:  topCountry,
		NetworkRX:   networkRX,
		NetworkTX:   networkTX,
		CPUUsage:    sysInfo.GetCPUUsage(),
		MemoryUsage: sysInfo.GetMemoryUsage(),
	}

	return DetailedTrafficStats{
		TrafficSnapshot: snapshot,
		RateLimitedPPS:  rlPPS,
		InvalidPPS:      invalidPPS,
		GeoIPBlockPPS:   geoipPPS,
		TotalPackets:    raw.TotalPackets,
		BlockedPackets:  raw.BlockedPackets,
	}, raw
}

// LookupBlockedIP checks if an IP is blocked and returns the details
func (e *EBPFService) LookupBlockedIP(ipStr string) *BlockedIPInfo {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.objs == nil {
		return nil
	}

	objs, ok := e.objs.(*xdpObjects)
	if !ok {
		return nil
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil
	}
	ip = ip.To4()
	if ip == nil {
		return nil
	}

	// Construct Key
	key := LpmKey{
		PrefixLen: 32,
	}
	copy(key.Data[:], ip)

	var value BlockEntry
	if err := objs.BlockedIps.Lookup(key, &value); err != nil {
		return nil
	}

	// Found - Parse details
	reason := "unknown"
	switch value.Reason {
	case 1:
		reason = "manual"
	case 2:
		reason = "rate_limit"
	case 3:
		reason = "geoip"
	case 4:
		reason = "flood"
	}

	var expiresAt time.Time
	var ttl int64 = -1

	if value.ExpiresAt > 0 {
		expiresAt = e.bootTime.Add(time.Duration(value.ExpiresAt) * time.Nanosecond)
		remaining := time.Until(expiresAt)
		if remaining > 0 {
			ttl = int64(remaining.Seconds())
		} else {
			ttl = 0
		}
	}

	// Get Country Info
	countryName := "Unknown"
	countryCode := "XX"
	if e.geoIPService != nil {
		countryName, countryCode = e.geoIPService.GetCountry(ipStr)
	}

	return &BlockedIPInfo{
		IP:          ipStr,
		Reason:      reason,
		ExpiresAt:   expiresAt,
		TTL:         ttl,
		CountryCode: countryCode,
		CountryName: countryName,
	}
}

// IterateBlockedIPs returns a list of currently blocked IPs from the eBPF map
func (e *EBPFService) IterateBlockedIPs() ([]BlockedIPInfo, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.objs == nil {
		return nil, nil
	}

	objs, ok := e.objs.(*xdpObjects)
	if !ok {
		return nil, nil
	}

	var blockedList []BlockedIPInfo
	var key LpmKey
	var value BlockEntry

	iter := objs.BlockedIps.Iterate()
	for iter.Next(&key, &value) {
		ip := net.IP(key.Data[:]).String()

		reason := "unknown"
		switch value.Reason {
		case 1:
			reason = "manual"
		case 2:
			reason = "rate_limit"
		case 3:
			reason = "geoip"
		case 4:
			reason = "flood"
		}

		var expiresAt time.Time
		var ttl int64 = -1
		if value.ExpiresAt > 0 {
			expiresAt = e.bootTime.Add(time.Duration(value.ExpiresAt) * time.Nanosecond)
			remaining := time.Until(expiresAt)
			if remaining > 0 {
				ttl = int64(remaining.Seconds())
			} else {
				ttl = 0
			}
		}

		// Get Country Info
		countryName := "Unknown"
		countryCode := "XX"
		if e.geoIPService != nil {
			countryName, countryCode = e.geoIPService.GetCountry(ip)
		}

		blockedList = append(blockedList, BlockedIPInfo{
			IP:          ip,
			Reason:      reason,
			ExpiresAt:   expiresAt,
			TTL:         ttl,
			CountryCode: countryCode,
			CountryName: countryName,
		})

		if len(blockedList) >= 1000 {
			break
		}
	}

	return blockedList, iter.Err()
}

// IsEnabled returns whether eBPF is currently enabled
func (e *EBPFService) IsEnabled() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.enabled
}

// Helper functions - Corrected for Endianness

// CriticalDNS list - always allowed
var CriticalDNS = []string{
	"108.61.10.10", "9.9.9.9", "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1",
}

// SyncWhitelist reloads allowed IPs from DB, adds Origins, and Critical DNS
func (e *EBPFService) SyncWhitelist() error {
	if e.db == nil {
		return fmt.Errorf("database not connected")
	}

	var ips []string

	// 1. Add DB allowed IPs
	var allowed []models.AllowIP
	if err := e.db.Find(&allowed).Error; err != nil {
		system.Warn("Failed to find allowed IPs: %v", err)
	} else {
		for _, a := range allowed {
			ips = append(ips, a.IP)
		}
	}

	// 2. Add Origin IPs (Critical for WireGuard connectivity)
	// Even though Origins are on private IPs (10.200.0.x), their PUBLIC IPs
	// occasionally hit the WAN interface if WireGuard is not fully encapsulating or for discovery.
	// Actually, the user specifically mentioned blocking the "game server's IP".
	// Since Origins don't have public IPs in models.Origin, we should check AllowForeign or similar?
	// Wait, if the Origin connects to us, its public IP should be whitelisted.
	// We'll also check AllowForeign table.
	var foreign []models.AllowForeign
	if err := e.db.Find(&foreign).Error; err != nil {
		system.Warn("Failed to find foreign allowed IPs: %v", err)
	} else {
		for _, f := range foreign {
			ips = append(ips, f.IP)
		}
	}

	// 3. Add Critical DNS
	ips = append(ips, CriticalDNS...)

	system.Info("Syncing whitelist with %d total entries", len(ips))

	// Also sync ports whenever whitelist is synced
	if err := e.SyncAllowedPorts(); err != nil {
		system.Warn("Failed to sync allowed ports: %v", err)
	}

	return e.UpdateAllowIPs(ips)
}

// UpdateBlockedIPs updates the blocked_ips BPF map
func (e *EBPFService) UpdateBlockedIPs(ips []string) error {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.objs == nil {
		return nil // Not in eBPF mode
	}

	objs, ok := e.objs.(*xdpObjects)
	if !ok {
		return nil
	}

	for _, ipStr := range ips {
		// Try single IP first
		ip := net.ParseIP(ipStr)
		prefixLen := uint32(32)
		if ip == nil {
			// Try CIDR
			var ipNet *net.IPNet
			var err error
			ip, ipNet, err = net.ParseCIDR(ipStr)
			if err == nil {
				ones, _ := ipNet.Mask.Size()
				prefixLen = uint32(ones)
			} else {
				continue
			}
		}

		// Use LPM Key Structure
		key := struct {
			PrefixLen uint32
			Data      [4]byte
		}{
			PrefixLen: prefixLen,
		}
		copy(key.Data[:], ip.To4())

		blocked := uint32(1)
		if err := objs.BlockedIps.Put(key, blocked); err != nil {
			system.Warn("Failed to add blocked IP %s: %v", ipStr, err)
		}
	}

	system.Info("Updated %d blocked IPs in eBPF map", len(ips))
	return nil
}

// UpdateGeoAllowed updates the geo_allowed BPF map
func (e *EBPFService) UpdateGeoAllowed(allowedCountries []string) error {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.objs == nil {
		return nil // Not in eBPF mode
	}

	// Repopulate with new countries (simplified clear approach)
	e.UpdateGeoIPData()

	system.Info("Updated geo-allowed countries: %v", allowedCountries)
	return nil
}

// UpdateAllowIPs updates the white_list BPF map
func (e *EBPFService) UpdateAllowIPs(ips []string) error {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.objs == nil {
		return nil // Not in eBPF mode
	}

	objs, ok := e.objs.(*xdpObjects)
	if !ok {
		return nil
	}

	// Simple approach: Clear map (if possible) or just add new.
	// Since we don't track old keys here easily, we rely on handlers to pass full list?
	// Or we just add. For deletion, we might need a full overwrite or explicit delete.
	// Assuming `ips` is the FULL list of allowed IPs.

	// Better approach for full sync: read all keys, diff, or nuke and rebuild.
	// HASH map doesn't support "Clear".
	// We will just add for now. Proper sync requires more code.
	// Let's iterate and delete all first? Expensive if large.
	// Given manual whitelist is usually small (<100), iterate-delete is fine.

	var key [4]byte
	var value uint32
	var keysToDelete [][4]byte

	iter := objs.WhiteList.Iterate()
	for iter.Next(&key, &value) {
		keysToDelete = append(keysToDelete, key)
	}

	for _, k := range keysToDelete {
		objs.WhiteList.Delete(k)
	}

	for _, ipStr := range ips {
		// Try single IP first
		ip := net.ParseIP(ipStr)
		prefixLen := uint32(32)
		if ip == nil {
			// Try CIDR
			var ipNet *net.IPNet
			var err error
			ip, ipNet, err = net.ParseCIDR(ipStr)
			if err == nil {
				ones, _ := ipNet.Mask.Size()
				prefixLen = uint32(ones)
			} else {
				continue
			}
		}

		// Use LPM Key Structure
		key := struct {
			PrefixLen uint32
			Data      [4]byte
		}{
			PrefixLen: prefixLen,
		}
		copy(key.Data[:], ip.To4())

		val := uint32(1)
		if err := objs.WhiteList.Put(key, val); err != nil {
			system.Warn("Failed to add whitelist IP %s: %v", ipStr, err)
		}
	}

	system.Info("Updated whitelist in eBPF map: %d entries", len(ips))
	return nil
}

// ResetTrafficStats clears all traffic statistics from eBPF maps and memory
func (e *EBPFService) ResetTrafficStats() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// 1. Clear local cache
	e.trafficData = make([]TrafficEntry, 0)

	// 2. Clear eBPF Map (ip_stats)
	if e.objs != nil {
		objs, ok := e.objs.(*xdpObjects)
		if ok {
			// Iterate and delete all keys
			// Note: Deleting while iterating can be tricky in some kernels/implementations,
			// but for hash maps it's generally supported or we collect keys first.
			// Ideally, we could just close and recreate the map, but that requires reloading the program or using map-in-map.
			// Simple approach: Delete keys one by one.

			var key [4]byte
			var values []PacketStats
			var keysToDelete [][4]byte

			iter := objs.IpStats.Iterate()
			for iter.Next(&key, &values) {
				keysToDelete = append(keysToDelete, key)
			}
			if err := iter.Err(); err != nil {
				system.Warn("Error iterating ip_stats for reset: %v", err)
			}

			count := 0
			for _, k := range keysToDelete {
				if err := objs.IpStats.Delete(k); err != nil {
					// system.Warn("Failed to delete key: %v", err)
				} else {
					count++
				}
			}
			system.Info("Reset %d traffic stats entries from eBPF map", count)
		}
	}

	return nil
}

// SyncAllowedPorts is deprecated - simplified XDP filter doesn't use allowed_ports map
// Traffic is now controlled by Whitelist, Blacklist, Connection Tracking, and GeoIP
func (e *EBPFService) SyncAllowedPorts() error {
	// No-op: Simplified XDP filter passes all traffic that:
	// 1. Is whitelisted
	// 2. Is from a tracked connection (response)
	// 3. Passes GeoIP check
	// Game ports are implicitly allowed if they pass GeoIP.
	return nil
}

// StartAutoResetLoop starts the background task to reset stats periodically
func (e *EBPFService) StartAutoResetLoop(db *gorm.DB) {
	// Initialize the channel if not already (should be done in Enable/New, but safe guard)
	if e.stopChan == nil {
		e.stopChan = make(chan struct{})
	}

	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-e.stopChan:
				return
			case <-ticker.C:
				var settings models.SecuritySettings
				if err := db.First(&settings, 1).Error; err != nil {
					continue
				}

				if settings.TrafficStatsResetInterval <= 0 {
					continue
				}

				// If never reset before, set to now to start the cycle
				if settings.LastTrafficStatsReset == nil {
					now := time.Now()
					settings.LastTrafficStatsReset = &now
					db.Save(&settings)
					continue
				}

				// Check interval
				interval := time.Duration(settings.TrafficStatsResetInterval) * time.Hour
				if time.Since(*settings.LastTrafficStatsReset) >= interval {
					system.Info("Auto-resetting traffic stats (Interval: %dh)", settings.TrafficStatsResetInterval)
					e.ResetTrafficStats()

					now := time.Now()
					settings.LastTrafficStatsReset = &now
					db.Save(&settings)
				}
			}
		}
	}()
}

// PortStats represents per-port traffic statistics
type PortStats struct {
	Port    uint16 `json:"port"`
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

// UpdateConfig updates the eBPF config map with current settings
func (e *EBPFService) UpdateConfig(hardBlocking bool, rateLimitPPS int) error {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.objs == nil {
		return nil
	}

	objs, ok := e.objs.(*xdpObjects)
	if !ok {
		return nil
	}

	// Config map indices
	const (
		configHardBlocking    = uint32(0)
		configRateLimitPPS    = uint32(1)
		configMaintenanceMode = uint32(2)
	)

	// Set hard blocking mode
	hardBlockVal := uint32(0)
	if hardBlocking {
		hardBlockVal = 1
	}
	if err := objs.Config.Put(configHardBlocking, hardBlockVal); err != nil {
		system.Warn("Failed to update hard blocking config: %v", err)
	}

	// Set rate limit PPS
	rateLimitVal := uint32(rateLimitPPS)
	if err := objs.Config.Put(configRateLimitPPS, rateLimitVal); err != nil {
		system.Warn("Failed to update rate limit config: %v", err)
	}

	system.Info("Updated eBPF config: hard_blocking=%v, rate_limit_pps=%d", hardBlocking, rateLimitPPS)
	return nil
}

// UpdateMaintenanceMode updates the eBPF bypass for maintenance mode
func (e *EBPFService) UpdateMaintenanceMode(enabled bool) error {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.objs == nil {
		return nil
	}

	objs, ok := e.objs.(*xdpObjects)
	if !ok {
		return nil
	}

	const configMaintenanceMode = uint32(2)
	val := uint32(0)
	if enabled {
		val = 1
	}

	if err := objs.Config.Put(configMaintenanceMode, val); err != nil {
		system.Warn("Failed to update maintenance mode config: %v", err)
		return err
	}

	return nil
}

// GetPortStats returns per-port traffic statistics
func (e *EBPFService) GetPortStats() []PortStats {
	if e.objs == nil {
		return nil
	}

	objs, ok := e.objs.(*xdpObjects)
	if !ok {
		return nil
	}

	var stats []PortStats
	var key uint16
	var value []struct {
		Packets uint64
		Bytes   uint64
	}

	iter := objs.PortStats.Iterate()
	for iter.Next(&key, &value) {
		var totalPackets, totalBytes uint64
		for _, v := range value {
			totalPackets += v.Packets
			totalBytes += v.Bytes
		}

		stats = append(stats, PortStats{
			Port:    key,
			Packets: totalPackets,
			Bytes:   totalBytes,
		})

		// Limit
		if len(stats) >= 100 {
			break
		}
	}

	// Sort by packets descending
	for i := 0; i < len(stats); i++ {
		for j := i + 1; j < len(stats); j++ {
			if stats[j].Packets > stats[i].Packets {
				stats[i], stats[j] = stats[j], stats[i]
			}
		}
	}

	return stats
}

// AddBlockedIP adds an IP to the blocklist with a duration
func (e *EBPFService) AddBlockedIP(ipStr string, duration time.Duration) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.objs == nil {
		return nil
	}

	objs, ok := e.objs.(*xdpObjects)
	if !ok {
		return nil
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return fmt.Errorf("invalid IP: %s", ipStr)
	}

	// Construct Key
	key := LpmKey{
		PrefixLen: 32,
	}
	copy(key.Data[:], ip.To4())

	// Construct Value
	var expiresAt uint64 = 0
	if duration > 0 {
		// Use monotonic time for BPF compatibility
		// We use boot time offset
		expiresAt = uint64(time.Since(e.bootTime).Nanoseconds() + duration.Nanoseconds())
	}

	value := BlockEntry{
		ExpiresAt: expiresAt,
		Reason:    1, // manual
	}

	if err := objs.BlockedIps.Put(key, value); err != nil {
		return fmt.Errorf("failed to add blocked IP %s: %w", ipStr, err)
	}

	system.Info("Added blocked IP: %s (Duration: %s)", ipStr, duration)
	return nil
}

// RemoveBlockedIP removes an IP from the blocklist
func (e *EBPFService) RemoveBlockedIP(ipStr string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.objs == nil {
		return nil
	}

	objs, ok := e.objs.(*xdpObjects)
	if !ok {
		return nil
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return fmt.Errorf("invalid IP: %s", ipStr)
	}

	// Construct Key
	key := LpmKey{
		PrefixLen: 32,
	}
	copy(key.Data[:], ip.To4())

	if err := objs.BlockedIps.Delete(key); err != nil {
		// Verify if it actually failed or just didn't exist
		// For BPF maps, delete on non-existent key returns error, which is fine to ignore or report as "not found"
		// But for now we just return error if it's strictly a system error
		return fmt.Errorf("failed to remove blocked IP %s: %w", ipStr, err)
	}

	system.Info("Removed blocked IP: %s", ipStr)
	return nil
}
