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

// BPF map for allowed destination ports (Dynamic Game Port Whitelist)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024); // Support up to 1024 game ports
    __type(key, __u16);   // Destination Port
    __type(value, __u32); // 1 = allowed
} allowed_ports SEC(".maps");

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

static __always_inline int parse_ip_packet(struct xdp_md *ctx, __u32 *src_ip, __u16 *protocol, __u16 *dst_port, __u16 *src_port, int *is_fragment) {
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
    *src_port = 0;
    *is_fragment = 0;

    // Check for fragmentation (More Fragments flag or Offset > 0)
    // 0x2000 is More Fragments flag, 0x1FFF is Fragment Offset mask
    if ((ip->frag_off & bpf_htons(0x2000 | 0x1FFF)) != 0) {
        *is_fragment = 1;
        // For fragments, we can't always parse L4 headers securely, so we stop here.
        // But for FIRST fragment (Offset 0), we MIGHT see L4 header, but let's treat all as special.
        return 0;
    }

    // Extract destination port for TCP/UDP
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) <= data_end) {
            *dst_port = bpf_ntohs(tcp->dest);
            *src_port = bpf_ntohs(tcp->source);
        }
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        if ((void *)(udp + 1) <= data_end) {
            *dst_port = bpf_ntohs(udp->dest);
            *src_port = bpf_ntohs(udp->source);
        }
    }

    return 0;
}

SEC("xdp")
int xdp_traffic_filter(struct xdp_md *ctx) {
    __u32 src_ip = 0;
    __u16 protocol = 0;
    __u16 dst_port = 0;
    __u16 src_port = 0;
    int is_fragment = 0;

    // 1. Parse Packet
    if (parse_ip_packet(ctx, &src_ip, &protocol, &dst_port, &src_port, &is_fragment) < 0)
        return XDP_PASS;

    __u64 pkt_size = (void *)(long)ctx->data_end - (void *)(long)ctx->data;
    __u32 key;
    __u32 cfg_key;

    // ============================================================
    // 2. ESSENTIAL OPTIMIZATIONS (Fast Pass)
    // ============================================================
    
    // 2.1 Private Networks (Bypass All)
    __u32 ip_h = bpf_ntohl(src_ip);
    // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8
    if ((ip_h & 0xFF000000) == 0x0A000000) return XDP_PASS;
    if ((ip_h & 0xFFF00000) == 0xAC100000) return XDP_PASS;
    if ((ip_h & 0xFFFF0000) == 0xC0A80000) return XDP_PASS;
    if ((ip_h & 0xFF000000) == 0x7F000000) return XDP_PASS;

    // 2.2 Maintenance / Essential Ports (SSH, WireGuard, Mangement)
    // Always allow these regardless of rules
    if (dst_port == 22 || dst_port == 51820 || dst_port == 8080) return XDP_PASS;

    // 2.3 Fragmented Packets
    // Arma Reforger relies heavily on UDP fragmentation.
    // If we drop these, the game breaks. Allow them explicitly.
    // (Attack surface: Fragment floods are possible, but less risk than breaking game)
    if (is_fragment) return XDP_PASS;

    
    // ============================================================
    // 3. WHITELIST CHECK (Priority 1 - v1.6.3 Logic)
    // Absolute trust. Bypasses Rate Limit & Blacklist.
    // ============================================================
    struct lpm_key w_key;
    set_key_ipv4(&w_key, src_ip);
    __u32 *whitelisted = bpf_map_lookup_elem(&white_list, &w_key);
    if (whitelisted) {
        // Stats: Allowed
        key = STAT_ALLOWED;
        __u64 *cnt = bpf_map_lookup_elem(&global_stats, &key);
        if (cnt) __sync_fetch_and_add(cnt, 1);
        
        // Stats: Total (Increment for accurate dashboard)
        key = STAT_TOTAL_PACKETS;
        cnt = bpf_map_lookup_elem(&global_stats, &key);
        if (cnt) __sync_fetch_and_add(cnt, 1);
        
        return XDP_PASS; 
        // FAST EXIT - skip rate limits, skip blacklists, skip heavy stats
    }


    // ============================================================
    // 4. BLACKLIST CHECK (Priority 2 - Early Drop Optimization)
    // Stop attackers here before they consume Rate Limit tokens.
    // ============================================================
    struct lpm_key b_key;
    set_key_ipv4(&b_key, src_ip);
    __u32 *blocked = bpf_map_lookup_elem(&blocked_ips, &b_key);
    if (blocked && *blocked == 1) {
        // Stats: Blocked
        key = STAT_BLOCKED;
        __u64 *cnt = bpf_map_lookup_elem(&global_stats, &key);
        if (cnt) __sync_fetch_and_add(cnt, 1);

        // Stats: Total
        key = STAT_TOTAL_PACKETS;
        cnt = bpf_map_lookup_elem(&global_stats, &key);
        if (cnt) __sync_fetch_and_add(cnt, 1);
        
        return XDP_DROP;
        // FAST EXIT - drop immediately
    }


    // ============================================================
    // 5. RATE LIMIT CHECK (Priority 3 - v1.6.3 Logic - DDoS Gate)
    // Protected behind Whitelist, but protects everything else.
    // ============================================================
    cfg_key = CONFIG_RATE_LIMIT_PPS;
    __u32 *rate_limit_pps = bpf_map_lookup_elem(&config, &cfg_key);
    if (rate_limit_pps && *rate_limit_pps > 0) {
        __u64 now = bpf_ktime_get_ns();
        struct rate_limit_entry *rl = bpf_map_lookup_elem(&rate_limits, &src_ip);
        
        if (rl) {
            __u64 elapsed = now - rl->last_update;
            // Refill tokens: (elapsed_ns * rate_pps) / 1e9
            // Max elapsed check to prevent overflow
            if (elapsed > 1000000000ULL) elapsed = 1000000000ULL;
            
            __u64 tokens_to_add = (elapsed * (*rate_limit_pps)) / 1000000000ULL;
            __u64 new_tokens = rl->tokens + tokens_to_add;
            if (new_tokens > *rate_limit_pps) new_tokens = *rate_limit_pps;
            
            if (new_tokens < 1) {
                // Rate Limited!
                key = STAT_RATE_LIMITED;
                __u64 *cnt = bpf_map_lookup_elem(&global_stats, &key);
                if (cnt) __sync_fetch_and_add(cnt, 1);

                // We must also count this as blocked globally
                key = STAT_BLOCKED;
                cnt = bpf_map_lookup_elem(&global_stats, &key);
                if (cnt) __sync_fetch_and_add(cnt, 1);
                
                // Do NOT update per-IP stats here (Deferred Stats optimization)
                // Just drop it to save heavy map operations
                return XDP_DROP;
            }
            rl->tokens = new_tokens - 1;
            rl->last_update = now;
        } else {
            // New entry
            struct rate_limit_entry new_rl = { .tokens = *rate_limit_pps - 1, .last_update = now };
            bpf_map_update_elem(&rate_limits, &src_ip, &new_rl, BPF_ANY);
        }
    }


    // ============================================================
    // 6. DEFERRED STATS UPDATE (v1.8.0 Optimization)
    // Only update heavy LRU maps for valid traffic that passed Rate Limit & Blacklist.
    // ============================================================
    
    // 6.1 Update Global Packet/Byte Counts
    key = STAT_TOTAL_PACKETS;
    __u64 *total_packets = bpf_map_lookup_elem(&global_stats, &key);
    if (total_packets) __sync_fetch_and_add(total_packets, 1);

    key = STAT_TOTAL_BYTES;
    __u64 *total_bytes = bpf_map_lookup_elem(&global_stats, &key);
    if (total_bytes) __sync_fetch_and_add(total_bytes, pkt_size);

    // 6.2 Update Port Stats
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

    // 6.3 Update IP Stats (LRU - Expensive)
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


    // ============================================================
    // 7. SAFE BYPASSES (Passed Rate Limit - Safe to Allow)
    // ============================================================

    // 7.1 TCP Outbound Response Bypass
    // Use DIRECT byte inspection to avoid bitfield endianness issues.
    // Offset 13 (0-based) contains flags: CWR, ECE, URG, ACK, PSH, RST, SYN, FIN
    // We want ACK (0x10) or RST (0x04).
    if (protocol == IPPROTO_TCP) {
        // Re-read data pointers for strict verifier
        void *data_now = (void *)(long)ctx->data;
        struct ethhdr *eth = data_now;
        struct iphdr *ip = (void *)(eth + 1);
        // Calculate TCP header position carefully
        // ip->ihl is length in 32-bit words. *4 for bytes.
        // We know ParsePacket validated IP header, so this calculation is safe-ish,
        // but verify bounds again for verifier.
        if ((void *)ip + 20 > (void *)(long)ctx->data_end) return XDP_PASS; // Should already be checked

        int ip_len = ip->ihl * 4;
        if (ip_len < 20) ip_len = 20; // sanity
        
        // Pointer to TCP header start
        __u8 *tcp_start = (void *)ip + ip_len;
        
        // We need byte 13 of TCP header.
        // Bounds check: TCP header is at least 20 bytes.
        if ((void *)(tcp_start + 14) <= (void *)(long)ctx->data_end) {
             __u8 flags = *(tcp_start + 13);
             
             // Check if ACK (0x10) or RST (0x04) is set
             if ((flags & 0x14) != 0) {
                 key = STAT_ALLOWED;
                 __u64 *cnt = bpf_map_lookup_elem(&global_stats, &key);
                 if (cnt) __sync_fetch_and_add(cnt, 1);
                 return XDP_PASS;
             }
        }
    }

    // 7.2 Steam Query Bypass (A2S_INFO)
    if (protocol == IPPROTO_UDP) {
        void *data_now = (void *)(long)ctx->data;
        struct ethhdr *eth = data_now;
        struct iphdr *ip = (void *)(eth + 1);
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        void *data_end_now = (void *)(long)ctx->data_end;
        
        if ((void *)(udp + 1) <= data_end_now) {
             unsigned char *payload = (void *)(udp + 1);
             if ((void *)(payload + 4) <= data_end_now) {
                 // 0xFFFFFFFF split for verifier safety if needed, but direct check is usually fine
                 if (*(__u32*)payload == 0xFFFFFFFF) {
                     key = STAT_ALLOWED;
                     __u64 *cnt = bpf_map_lookup_elem(&global_stats, &key);
                     if (cnt) __sync_fetch_and_add(cnt, 1);
                     return XDP_PASS;
                 }
             }
        }
    }
    
    // 7.3 UDP Response Bypass (Origin Internet Fix)
    // ALLOW RESPONSE TRAFFIC from common services (DNS, HTTP, NTP)
    // This is safe because it's AFTER Rate Limiting. Spoofed source ports will hit rate limit first.
    if (protocol == IPPROTO_UDP) {
        if (src_port == 53 || src_port == 80 || src_port == 443 || src_port == 123) {
             key = STAT_ALLOWED;
             __u64 *cnt = bpf_map_lookup_elem(&global_stats, &key);
             if (cnt) __sync_fetch_and_add(cnt, 1);
             return XDP_PASS;
        }
    }

    // 7.4 Dynamic Game Port Bypass
    if (dst_port > 0) {
        __u32 *p_allowed = bpf_map_lookup_elem(&allowed_ports, &dst_port);
        if (p_allowed && *p_allowed == 1) {
            key = STAT_ALLOWED;
            __u64 *cnt = bpf_map_lookup_elem(&global_stats, &key);
            if (cnt) __sync_fetch_and_add(cnt, 1);
            return XDP_PASS;
        }
    }

    // 7.5 ICMP Bypass (Ping)
    // Protected by Rate Limit above, so safe to allow generic ICMP.
    // Critical for connectivity checks (Ping 8.8.8.8).
    if (protocol == IPPROTO_ICMP) {
        key = STAT_ALLOWED;
        __u64 *cnt = bpf_map_lookup_elem(&global_stats, &key);
        if (cnt) __sync_fetch_and_add(cnt, 1);
        return XDP_PASS;
    }


    // ============================================================
    // 8. GEOIP CHECK (Last Line of Defense)
    // Most expensive check, done last.
    // ============================================================
    struct lpm_key geo_key;
    set_key_ipv4(&geo_key, src_ip);
    __u32 *country = bpf_map_lookup_elem(&geo_allowed, &geo_key);
    
    // If NOT found in Allowed GeoIP Map
    if (!country) {
        // FAIL-SAFE:
        // Only DROP if "Hard Blocking" is explicitly enabled via config map.
        cfg_key = CONFIG_HARD_BLOCKING;
        __u32 *hard_blocking = bpf_map_lookup_elem(&config, &cfg_key);
        
        if (hard_blocking && *hard_blocking == 1) {
            // Blocked by GeoIP
            key = STAT_BLOCKED;
            __u64 *cnt = bpf_map_lookup_elem(&global_stats, &key);
            if (cnt) __sync_fetch_and_add(cnt, 1);
            
            // Mark IP stats as blocked
             struct packet_stats *s = bpf_map_lookup_elem(&ip_stats, &src_ip);
             if (s) s->blocked = 1;

            return XDP_DROP;
        }
        
        // Soft Blocking (Default): Allow but don't mark as "Allowed" explicitly
        return XDP_PASS; 
    }


    // ============================================================
    // 9. FINAL PASS (GeoIP Allowed)
    // ============================================================
    key = STAT_ALLOWED;
    __u64 *final_cnt = bpf_map_lookup_elem(&global_stats, &key);
    if (final_cnt) __sync_fetch_and_add(final_cnt, 1);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
