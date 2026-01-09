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

// LPM Trie Key
struct lpm_key {
    __u32 prefixlen;
    __u32 data;
};

// BPF map for allowed countries (GeoIP)
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 600000);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct lpm_key);
    __type(value, __u32); // Country code (as integer)
} geo_allowed SEC(".maps");

// BPF map for manually allowed IPs (White List)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32);   // IP address
    __type(value, __u32); // 1 = allowed
} white_list SEC(".maps");

// Global statistics
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 10);
    __type(key, __u32);
    __type(value, __u64);
} global_stats SEC(".maps");

// Configuration map (index 0 = hard_blocking, index 1 = rate_limit_pps)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u32);
} config SEC(".maps");

#define CONFIG_HARD_BLOCKING 0
#define CONFIG_RATE_LIMIT_PPS 1

// Rate limiting per-IP (token bucket)
struct rate_limit_entry {
    __u64 tokens;       // Current tokens
    __u64 last_update;  // Last update timestamp (ns)
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 100000);
    __type(key, __u32);   // Source IP
    __type(value, struct rate_limit_entry);
} rate_limits SEC(".maps");

// Per-destination-port statistics
struct port_stats {
    __u64 packets;
    __u64 bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u16);   // Destination port
    __type(value, struct port_stats);
} port_stats SEC(".maps");

#define STAT_TOTAL_PACKETS 0
#define STAT_TOTAL_BYTES   1
#define STAT_BLOCKED       2
#define STAT_ALLOWED       3
#define STAT_RATE_LIMITED  4

static __always_inline int parse_ip_packet(struct xdp_md *ctx, __u32 *src_ip, __u16 *protocol, __u16 *dst_port) {
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
    *dst_port = 0;

    // Extract destination port for TCP/UDP
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) <= data_end) {
            *dst_port = bpf_ntohs(tcp->dest);
        }
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        if ((void *)(udp + 1) <= data_end) {
            *dst_port = bpf_ntohs(udp->dest);
        }
    }

    return 0;
}

SEC("xdp")
int xdp_traffic_filter(struct xdp_md *ctx) {
    __u32 src_ip = 0;
    __u16 protocol = 0;
    __u16 dst_port = 0;

    // Parse packet
    if (parse_ip_packet(ctx, &src_ip, &protocol, &dst_port) < 0)
        return XDP_PASS;

    __u64 pkt_size = (void *)(long)ctx->data_end - (void *)(long)ctx->data;

    // Update global stats
    __u32 key = STAT_TOTAL_PACKETS;
    __u64 *total_packets = bpf_map_lookup_elem(&global_stats, &key);
    if (total_packets)
        __sync_fetch_and_add(total_packets, 1);

    key = STAT_TOTAL_BYTES;
    __u64 *total_bytes = bpf_map_lookup_elem(&global_stats, &key);
    if (total_bytes)
        __sync_fetch_and_add(total_bytes, pkt_size);

    // Update per-port statistics
    if (dst_port > 0) {
        struct port_stats *pstats = bpf_map_lookup_elem(&port_stats, &dst_port);
        if (pstats) {
            __sync_fetch_and_add(&pstats->packets, 1);
            __sync_fetch_and_add(&pstats->bytes, pkt_size);
        } else {
            struct port_stats new_pstats = {
                .packets = 1,
                .bytes = pkt_size,
            };
            bpf_map_update_elem(&port_stats, &dst_port, &new_pstats, BPF_ANY);
        }
    }

    // --- 1. Track Statistics for ALL IPs (including Private) ---
    struct packet_stats *stats = bpf_map_lookup_elem(&ip_stats, &src_ip);
    
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
        // Refresh pointer after update
        stats = bpf_map_lookup_elem(&ip_stats, &src_ip);
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

    // --- 3. Check Manual Whitelist (AllowIPs) ---
    __u32 *whitelisted = bpf_map_lookup_elem(&white_list, &src_ip);
    if (whitelisted) {
        // Explicitly Allowed
        key = STAT_ALLOWED;
        __u64 *allowed_count = bpf_map_lookup_elem(&global_stats, &key);
        if (allowed_count)
            __sync_fetch_and_add(allowed_count, 1);
        return XDP_PASS;
    }

    // --- 3.5 Rate Limiting Check ---
    __u32 cfg_key = CONFIG_RATE_LIMIT_PPS;
    __u32 *rate_limit_pps = bpf_map_lookup_elem(&config, &cfg_key);
    if (rate_limit_pps && *rate_limit_pps > 0) {
        __u64 now = bpf_ktime_get_ns();
        struct rate_limit_entry *rl = bpf_map_lookup_elem(&rate_limits, &src_ip);
        
        if (rl) {
            // Token bucket algorithm
            __u64 elapsed = now - rl->last_update;
            __u64 tokens_per_ns = (*rate_limit_pps) / 1000000000ULL; // Tokens per nanosecond
            if (tokens_per_ns == 0) tokens_per_ns = 1;
            
            __u64 new_tokens = rl->tokens + (elapsed * tokens_per_ns);
            if (new_tokens > *rate_limit_pps) {
                new_tokens = *rate_limit_pps; // Cap at max
            }
            
            if (new_tokens < 1) {
                // No tokens, rate limited - DROP
                if (stats) stats->blocked = 1;
                key = STAT_RATE_LIMITED;
                __u64 *rl_count = bpf_map_lookup_elem(&global_stats, &key);
                if (rl_count)
                    __sync_fetch_and_add(rl_count, 1);
                return XDP_DROP;
            }
            
            // Consume token
            rl->tokens = new_tokens - 1;
            rl->last_update = now;
        } else {
            // New entry, initialize with full bucket
            struct rate_limit_entry new_rl = {
                .tokens = *rate_limit_pps - 1,
                .last_update = now,
            };
            bpf_map_update_elem(&rate_limits, &src_ip, &new_rl, BPF_ANY);
        }
    }

    // --- 4. Check Blocked List (Blacklist) ---
    __u32 *blocked = bpf_map_lookup_elem(&blocked_ips, &src_ip);
    if (blocked && *blocked == 1) {
        if (stats) stats->blocked = 1;

        // Update global blocked count
        key = STAT_BLOCKED;
        __u64 *blocked_count = bpf_map_lookup_elem(&global_stats, &key);
        if (blocked_count)
            __sync_fetch_and_add(blocked_count, 1);

        return XDP_DROP;
    }

    // --- 4.5 Steam Query Bypass ---
    // Allow A2S_INFO and other query packets (Payload starts with 0xFFFFFFFF) regardless of GeoIP
    if (protocol == IPPROTO_UDP) {
        void *data = (void *)(long)ctx->data;
        void *data_end = (void *)(long)ctx->data_end;
        struct ethhdr *eth = data;
        struct iphdr *ip = (void *)(eth + 1);
        
        // Ensure IP header is valid (already checked but needed for verifier)
        if ((void *)(ip + 1) <= data_end && ip->protocol == IPPROTO_UDP) {
             // Calculate UDP header position safely
             // ip->ihl is 4-bit, multiply by 4 to get bytes
             struct udphdr *udp = (void *)ip + (ip->ihl * 4);
             
             // Ensure UDP header is within bounds
             if ((void *)(udp + 1) <= data_end) {
                 // Payload follows UDP header
                 unsigned char *payload = (void *)(udp + 1);
                 
                 // Check if at least 4 bytes of payload exist
                 if ((void *)(payload + 4) <= data_end) {
                     // Check for Steam Query Header: 0xFF 0xFF 0xFF 0xFF
                     // This covers A2S_INFO, A2S_PLAYER, A2S_RULES, etc.
                     if (*(__u32*)payload == 0xFFFFFFFF) {
                         // Valid Steam Query - Allow
                         // Increment allowed stats
                         key = STAT_ALLOWED;
                         __u64 *allowed_count = bpf_map_lookup_elem(&global_stats, &key);
                         if (allowed_count)
                             __sync_fetch_and_add(allowed_count, 1);
                             
                         return XDP_PASS;
                     }
                 }
             }
        }
    }

    // --- 5. Check GeoIP ---
    struct lpm_key geo_key = { .prefixlen = 32, .data = src_ip };
    __u32 *country = bpf_map_lookup_elem(&geo_allowed, &geo_key);
    if (!country) {
        // IP not in allowed country list
        // Mark as BLOCKED in stats so Dashboard shows it correctly.
        if (stats) stats->blocked = 1;

        key = STAT_BLOCKED;
        __u64 *blocked_count = bpf_map_lookup_elem(&global_stats, &key);
        if (blocked_count)
            __sync_fetch_and_add(blocked_count, 1);

        // Check if hard blocking is enabled
        cfg_key = CONFIG_HARD_BLOCKING;
        __u32 *hard_blocking = bpf_map_lookup_elem(&config, &cfg_key);
        if (hard_blocking && *hard_blocking == 1) {
            // Hard blocking mode: Drop at XDP level
            return XDP_DROP;
        }
        
        // Soft blocking mode: Pass to iptables for handling
        return XDP_PASS; 
    }

    // --- 6. Allowed ---
    key = STAT_ALLOWED;
    __u64 *allowed_count = bpf_map_lookup_elem(&global_stats, &key);
    if (allowed_count)
        __sync_fetch_and_add(allowed_count, 1);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
