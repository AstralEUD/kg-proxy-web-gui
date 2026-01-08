//go:build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Packet statistics per source IP
// Packet statistics per source IP
struct packet_stats {
    __u64 packets;
    __u64 bytes;
    __u64 last_seen;
    __u32 blocked;
    __u32 pad; // Explicit padding to match 64-bit alignment and satisfy verifier
};

// BPF map to store per-IP statistics
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 100000);
    __type(key, __u32);   // Source IP address
    __type(value, struct packet_stats);
} ip_stats SEC(".maps");

// BPF map for blocked IPs
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32);   // IP address
    __type(value, __u32); // 1 = blocked
} blocked_ips SEC(".maps");

// BPF map for allowed countries (GeoIP)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1000000);
    __type(key, __u32);   // IP address
    __type(value, __u32); // Country code (as integer)
} geo_allowed SEC(".maps");

// Global statistics
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 10);
    __type(key, __u32);
    __type(value, __u64);
} global_stats SEC(".maps");

#define STAT_TOTAL_PACKETS 0
#define STAT_TOTAL_BYTES   1
#define STAT_BLOCKED       2
#define STAT_ALLOWED       3

static __always_inline int parse_ip_packet(struct xdp_md *ctx, __u32 *src_ip, __u16 *protocol) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return -1;

    // Check if it's an IP packet
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return -1;

    // Parse IP header
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return -1;

    *src_ip = ip->saddr;
    *protocol = ip->protocol;

    return 0;
}

SEC("xdp")
int xdp_traffic_filter(struct xdp_md *ctx) {
    __u32 src_ip = 0;
    __u16 protocol = 0;

    // Parse packet
    if (parse_ip_packet(ctx, &src_ip, &protocol) < 0)
        return XDP_PASS;

    // Update global stats
    __u32 key = STAT_TOTAL_PACKETS;
    __u64 *total_packets = bpf_map_lookup_elem(&global_stats, &key);
    if (total_packets)
        __sync_fetch_and_add(total_packets, 1);

    key = STAT_TOTAL_BYTES;
    __u64 *total_bytes = bpf_map_lookup_elem(&global_stats, &key);
    if (total_bytes) {
        __u64 pkt_size = (void *)(long)ctx->data_end - (void *)(long)ctx->data;
        __sync_fetch_and_add(total_bytes, pkt_size);
    }

    // --- 1. Track Statistics for ALL IPs (including Private) ---
    struct packet_stats *stats = bpf_map_lookup_elem(&ip_stats, &src_ip);
    __u64 pkt_size = (void *)(long)ctx->data_end - (void *)(long)ctx->data;
    
    if (stats) {
        __sync_fetch_and_add(&stats->packets, 1);
        __sync_fetch_and_add(&stats->bytes, pkt_size);
        stats->last_seen = bpf_ktime_get_ns();
    } else {
        struct packet_stats new_stats = {
            .packets = 1,
            .bytes = pkt_size,
            .last_seen = bpf_ktime_get_ns(),
            .blocked = 0,
            .pad = 0, // Initialize padding
        };
        bpf_map_update_elem(&ip_stats, &src_ip, &new_stats, BPF_ANY);
    }

    // --- 2. Safety Bypass for Private/Local Networks ---
    __u32 ip_h = bpf_ntohl(src_ip);
    // 10.0.0.0/8
    if ((ip_h & 0xFF000000) == 0x0A000000) return XDP_PASS;
    // 172.16.0.0/12
    if ((ip_h & 0xFFF00000) == 0xAC100000) return XDP_PASS;
    // 192.168.0.0/16
    if ((ip_h & 0xFFFF0000) == 0xC0A80000) return XDP_PASS;
    // 127.0.0.0/8
    if ((ip_h & 0xFF000000) == 0x7F000000) return XDP_PASS;

    // --- 3. Check Blocked List ---
    __u32 *blocked = bpf_map_lookup_elem(&blocked_ips, &src_ip);
    if (blocked && *blocked == 1) {
        // Mark as blocked in stats (need to update again or set flag? re-lookup is safest for concurrent map access if not using spinlocks)
        // Since we already updated stats, we just need to set the blocked flag.
        // However, updating existing element is tricky without race.
        // We will just assume it's set on next packet or try valid lookup.
        if (stats) stats->blocked = 1;

        // Update global blocked count
        key = STAT_BLOCKED;
        __u64 *blocked_count = bpf_map_lookup_elem(&global_stats, &key);
        if (blocked_count)
            __sync_fetch_and_add(blocked_count, 1);

        return XDP_DROP;
    }

    // --- 4. Check GeoIP ---
    __u32 *country = bpf_map_lookup_elem(&geo_allowed, &src_ip);
    if (!country) {
        // IP not in allowed list - DON'T DROP in XDP for safety yet.
        // But we tracked it.
        return XDP_PASS; 
    }

    // --- 5. Allowed ---
    key = STAT_ALLOWED;
    __u64 *allowed_count = bpf_map_lookup_elem(&global_stats, &key);
    if (allowed_count)
        __sync_fetch_and_add(allowed_count, 1);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
