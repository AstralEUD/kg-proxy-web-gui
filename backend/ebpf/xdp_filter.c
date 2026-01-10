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

// LPM Trie Key - Standardized for IPv4
struct lpm_key {
    __u32 prefixlen;
    __u8  data[4]; // Use byte array to match network byte order exactly
};

// BPF map for blocked IPs (using LPM Trie for CIDR support)
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 10000);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct lpm_key);
    __type(value, __u32); // 1 = blocked
} blocked_ips SEC(".maps");

// BPF map for allowed countries (GeoIP)
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 600000);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct lpm_key);
    __type(value, __u32); // Country code (as integer)
} geo_allowed SEC(".maps");

// BPF map for manually allowed IPs (White List - using LPM Trie for CIDR support)
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 10000);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct lpm_key);
    __type(value, __u32); // 1 = allowed
} white_list SEC(".maps");

// ... (stats maps remain same)

// Help to copy IP to key
static __always_inline void set_key_ipv4(struct lpm_key *key, __u32 ip) {
    key->prefixlen = 32;
    __u8 *bytes = (__u8 *)&ip;
    key->data[0] = bytes[0];
    key->data[1] = bytes[1];
    key->data[2] = bytes[2];
    key->data[3] = bytes[3];
}

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

#define CONFIG_HARD_BLOCKING    0
#define CONFIG_RATE_LIMIT_PPS   1
#define CONFIG_MAINTENANCE_MODE 2

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

static __always_inline int parse_ip_packet(void *data, void *data_end, __u32 *src_ip, __u16 *protocol, __u16 *dst_port) {
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
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    __u32 src_ip = 0;
    __u16 protocol = 0;
    __u16 dst_port = 0;

    // Parse packet
    if (parse_ip_packet(data, data_end, &src_ip, &protocol, &dst_port) < 0)
        return XDP_PASS;

    __u64 pkt_size = data_end - data;
    __u32 key;
    __u32 cfg_key;

    // ============================================================
    // OPTIMIZATION: Early Bypass for Private/Local Networks
    // No stats, no checks. Just pass. (Saves ~4 map lookups)
    // ============================================================
    __u32 ip_h = bpf_ntohl(src_ip);
    // 10.0.0.0/8
    if ((ip_h & 0xFF000000) == 0x0A000000) return XDP_PASS;
    // 172.16.0.0/12
    if ((ip_h & 0xFFF00000) == 0xAC100000) return XDP_PASS;
    // 192.168.0.0/16
    if ((ip_h & 0xFFFF0000) == 0xC0A80000) return XDP_PASS;
    // 127.0.0.0/8
    if ((ip_h & 0xFF000000) == 0x7F000000) return XDP_PASS;


    // ============================================================
    // OPTIMIZATION: Check Maintenance Mode
    // ============================================================
    cfg_key = CONFIG_MAINTENANCE_MODE;
    __u32 *m_mode = bpf_map_lookup_elem(&config, &cfg_key);
    if (m_mode && *m_mode == 1) return XDP_PASS;


    // ============================================================
    // OPTIMIZATION: Check Blacklist EARLY (with LPM support)
    // ============================================================
    struct lpm_key b_key;
    set_key_ipv4(&b_key, src_ip);
    __u32 *blocked = bpf_map_lookup_elem(&blocked_ips, &b_key);
    if (blocked && *blocked == 1) {
        // Still count global stats to know we are under attack
        key = STAT_TOTAL_PACKETS;
        __u64 *total_packets = bpf_map_lookup_elem(&global_stats, &key);
        if (total_packets) __sync_fetch_and_add(total_packets, 1);

        key = STAT_TOTAL_BYTES;
        __u64 *total_bytes = bpf_map_lookup_elem(&global_stats, &key);
        if (total_bytes) __sync_fetch_and_add(total_bytes, pkt_size);

        key = STAT_BLOCKED;
        __u64 *blocked_count = bpf_map_lookup_elem(&global_stats, &key);
        if (blocked_count) __sync_fetch_and_add(blocked_count, 1);

        return XDP_DROP;
    }


    // ============================================================
    // OPTIMIZATION: Check Whitelist EARLY (with LPM support)
    // ============================================================
    struct lpm_key w_key;
    set_key_ipv4(&w_key, src_ip);
    __u32 *whitelisted = bpf_map_lookup_elem(&white_list, &w_key);
    if (whitelisted) {
        // Count global stats
        key = STAT_TOTAL_PACKETS;
        __u64 *total_packets = bpf_map_lookup_elem(&global_stats, &key);
        if (total_packets) __sync_fetch_and_add(total_packets, 1);

        key = STAT_TOTAL_BYTES;
        __u64 *total_bytes = bpf_map_lookup_elem(&global_stats, &key);
        if (total_bytes) __sync_fetch_and_add(total_bytes, pkt_size);

        key = STAT_ALLOWED;
        __u64 *allowed_count = bpf_map_lookup_elem(&global_stats, &key);
        if (allowed_count) __sync_fetch_and_add(allowed_count, 1);

        // We DO update IP stats for whitelisted users so we can see their traffic usage
        struct packet_stats *stats = bpf_map_lookup_elem(&ip_stats, &src_ip);
        if (stats) {
            __sync_fetch_and_add(&stats->packets, 1);
            __sync_fetch_and_add(&stats->bytes, pkt_size);
            stats->last_seen = bpf_ktime_get_ns();
        } else {
            struct packet_stats new_stats = {
                .packets = 1, .bytes = pkt_size, .last_seen = bpf_ktime_get_ns(), .blocked = 0, .pad = 0,
            };
            bpf_map_update_elem(&ip_stats, &src_ip, &new_stats, BPF_ANY);
        }

        return XDP_PASS;
        // SKIPPING: Rate Limit, GeoIP
    }


    // ============================================================
    // STANDARD TRAFFIC PROCESSING
    // (Only for non-local, non-blacklisted, non-whitelisted IPs)
    // ============================================================

    // 1. Update Global Stats
    key = STAT_TOTAL_PACKETS;
    __u64 *total_packets = bpf_map_lookup_elem(&global_stats, &key);
    if (total_packets) __sync_fetch_and_add(total_packets, 1);

    key = STAT_TOTAL_BYTES;
    __u64 *total_bytes = bpf_map_lookup_elem(&global_stats, &key);
    if (total_bytes) __sync_fetch_and_add(total_bytes, pkt_size);


    // 2. Update Port Stats
    if (dst_port > 0) {
        struct port_stats *pstats = bpf_map_lookup_elem(&port_stats, &dst_port);
        if (pstats) {
            __sync_fetch_and_add(&pstats->packets, 1);
            __sync_fetch_and_add(&pstats->bytes, pkt_size);
        } else {
            struct port_stats new_pstats = { .packets = 1, .bytes = pkt_size };
            bpf_map_update_elem(&port_stats, &dst_port, &new_pstats, BPF_ANY);
        }
    }


    // 3. Update IP Stats (LRU)
    struct packet_stats *stats = bpf_map_lookup_elem(&ip_stats, &src_ip);
    if (stats) {
        __sync_fetch_and_add(&stats->packets, 1);
        __sync_fetch_and_add(&stats->bytes, pkt_size);
        stats->last_seen = bpf_ktime_get_ns();
    } else {
        struct packet_stats new_stats = {
            .packets = 1, .bytes = pkt_size, .last_seen = bpf_ktime_get_ns(), .blocked = 0, .pad = 0,
        };
        bpf_map_update_elem(&ip_stats, &src_ip, &new_stats, BPF_ANY);
        // Refresh pointer
        stats = bpf_map_lookup_elem(&ip_stats, &src_ip);
    }


    // 4. Rate Limiting Check
    cfg_key = CONFIG_RATE_LIMIT_PPS;
    __u32 *rate_limit_pps = bpf_map_lookup_elem(&config, &cfg_key);
    if (rate_limit_pps && *rate_limit_pps > 0) {
        __u64 now = bpf_ktime_get_ns();
        struct rate_limit_entry *rl = bpf_map_lookup_elem(&rate_limits, &src_ip);
        
        if (rl) {
            __u64 elapsed = now - rl->last_update;
            __u64 new_tokens;
            if (elapsed > 1000000000ULL) {
                new_tokens = *rate_limit_pps;
            } else {
                // Refill tokens: (elapsed_ns * rate_pps) / 1e9
                // Safe from overflow because elapsed <= 1s
                __u64 tokens_to_add = (elapsed * (*rate_limit_pps)) / 1000000000ULL;
                new_tokens = rl->tokens + tokens_to_add;
                if (new_tokens > *rate_limit_pps) new_tokens = *rate_limit_pps;
            }
            
            if (new_tokens < 1) {
                // Rate Limited
                if (stats) stats->blocked = 1;
                key = STAT_RATE_LIMITED;
                __u64 *rl_count = bpf_map_lookup_elem(&global_stats, &key);
                if (rl_count) __sync_fetch_and_add(rl_count, 1);
                return XDP_DROP;
            }
            rl->tokens = new_tokens - 1;
            rl->last_update = now;
        } else {
            struct rate_limit_entry new_rl = { .tokens = *rate_limit_pps - 1, .last_update = now };
            bpf_map_update_elem(&rate_limits, &src_ip, &new_rl, BPF_ANY);
        }
    }


    // 5. TCP Outbound Response Bypass
    if (protocol == IPPROTO_TCP) {
        // Reuse 'data' pointer which is already validated by verifier as part of packet range via parse_ip_packet
        // We know we have at least an Ethernet + IP header.
        
        // RE-CALCULATION IS FINE, BUT RE-LOADING data FROM ctx IS BAD.
        // We use the initial 'data' variable.
        struct ethhdr *eth = data;
        struct iphdr *ip = (void *)(eth + 1);
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);

        if ((void *)(tcp + 1) <= data_end) {
             if (tcp->ack || tcp->rst) {
                 key = STAT_ALLOWED;
                 __u64 *allowed_count = bpf_map_lookup_elem(&global_stats, &key);
                 if (allowed_count) __sync_fetch_and_add(allowed_count, 1);
                 return XDP_PASS;
             }
        }
    }


    // 6. Steam Query Bypass
    if (protocol == IPPROTO_UDP) {
        struct ethhdr *eth = data;
        struct iphdr *ip = (void *)(eth + 1);
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        
        if ((void *)(udp + 1) <= data_end) {
             unsigned char *payload = (void *)(udp + 1);
             if ((void *)(payload + 4) <= data_end) {
                 if (*(__u32*)payload == 0xFFFFFFFF) {
                     key = STAT_ALLOWED;
                     __u64 *allowed_count = bpf_map_lookup_elem(&global_stats, &key);
                     if (allowed_count) __sync_fetch_and_add(allowed_count, 1);
                     return XDP_PASS;
                 }
             }
        }
    }


    // 7. GeoIP Check (Most Expensive - Last)
    struct lpm_key geo_key;
    set_key_ipv4(&geo_key, src_ip);
    __u32 *country = bpf_map_lookup_elem(&geo_allowed, &geo_key);
    if (!country) {
        // Debug logging (only enabled if needed via compile flag, but kept simple here)
        // bpf_printk("GeoIP Block: %x", src_ip);
        
        if (stats) stats->blocked = 1;
        key = STAT_BLOCKED;
        __u64 *blocked_count = bpf_map_lookup_elem(&global_stats, &key);
        if (blocked_count) __sync_fetch_and_add(blocked_count, 1);

        cfg_key = CONFIG_HARD_BLOCKING;
        __u32 *hard_blocking = bpf_map_lookup_elem(&config, &cfg_key);
        if (hard_blocking && *hard_blocking == 1) return XDP_DROP;
        
        return XDP_PASS; // Soft blocking
    }


    // 8. Allowed (GeoIP Passed)
    key = STAT_ALLOWED;
    __u64 *allowed_count = bpf_map_lookup_elem(&global_stats, &key);
    if (allowed_count) __sync_fetch_and_add(allowed_count, 1);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
