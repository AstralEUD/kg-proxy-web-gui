# eBPF XDP Traffic Filter

This directory contains the eBPF/XDP program for high-performance packet filtering.

## Features

- **Kernel-level packet filtering** - Processes packets before they reach the network stack
- **Per-IP statistics** - Tracks packets, bytes, and last seen time for each source IP
- **GeoIP filtering** - Allows only traffic from specified countries
- **Blocked IP list** - Instantly drops packets from blocked IPs
- **Zero-copy performance** - XDP processes packets in the driver, avoiding kernel overhead

## Building

### Prerequisites

On Linux:
```bash
sudo apt-get install clang llvm linux-headers-$(uname -r) libbpf-dev
```

### Compile

```bash
chmod +x build-ebpf.sh
./build-ebpf.sh
```

This will create `backend/ebpf/build/xdp_filter.o`

## How It Works

1. **XDP Hook**: The program attaches to a network interface at the XDP (eXpress Data Path) layer
2. **Packet Inspection**: Each incoming packet is parsed to extract source IP and protocol
3. **Filtering Logic**:
   - Check if IP is in blocked list → DROP
   - Check if IP is in allowed GeoIP ranges → PASS
   - Otherwise → DROP
4. **Statistics**: All decisions are recorded in BPF maps for real-time monitoring

## BPF Maps

- `ip_stats` - Per-IP packet/byte counters (LRU hash, 100k entries)
- `blocked_ips` - Manually blocked IPs (hash, 10k entries)
- `geo_allowed` - Allowed country IP ranges (hash, 1M entries)
- `global_stats` - Total packets/bytes/blocked/allowed counters

## Performance

- **Line-rate filtering**: Processes packets at wire speed (10+ Gbps)
- **Low CPU usage**: Offloads filtering to NIC driver layer
- **Scalable**: Handles millions of packets per second

## Integration

The Go backend automatically:
1. Loads the compiled eBPF program on startup (if available)
2. Populates BPF maps with GeoIP data and blocked IPs
3. Reads statistics from BPF maps every 2 seconds
4. Updates the Traffic Analysis dashboard in real-time

## Fallback Mode

If eBPF is not available (Windows, or no root privileges), the system automatically falls back to simulation mode for development/testing.
