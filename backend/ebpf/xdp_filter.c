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
    __u32 pad; // Explicit padding
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
    __type(value, __u32); // Country code
} geo_allowed SEC(".maps");

// BPF map for manually allowed IPs (White List)
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
    __uint(max_entries, 1024);
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

// Configuration map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u32);
} config SEC(".maps");

#define CONFIG_HARD_BLOCKING    0
#define CONFIG_RATE_LIMIT_PPS   1

// Rate limiting per-IP
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

// ============================================================
// Safe Byte-Oriented Packet Parser (Avoids Bitfield Endianness Issues)
// ============================================================
static __always_inline int parse_ip_packet(struct xdp_md *ctx, __u32 *src_ip, __u16 *protocol, __u16 *dst_port, __u16 *src_port, int *is_fragment) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end)
        return -1;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return -1;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return -1;

    // Manual extraction of IHL to avoid bitfield endianness issues
    // Byte 0: Version(4) | IHL(4)
    __u8 ver_ihl = *((__u8 *)ip);
    __u8 ihl = ver_ihl & 0x0F;
    
    // Minimum IHL is 5 (20 bytes)
    if (ihl < 5) return -1;
    
    *src_ip = ip->saddr;
    *protocol = ip->protocol;
    *dst_port = 0;
    *src_port = 0;
    *is_fragment = 0;

    // Check for fragmentation
    // Offset 6: Flags(3) | Fragment Offset(13)
    // We access bytes manually to avoid endianness confusion
    // Byte 6 (Network Order) = Flags + High bits of Offset
    // Byte 7 = Low bits of Offset
    __u8 frag_high = *((__u8 *)ip + 6);
    __u8 frag_low = *((__u8 *)ip + 7);
    
    // MF (0x20) | Offset part in high byte (0x1F) | or any Low byte offset
    if ((frag_high & 0x3F) != 0 || frag_low != 0) {
        *is_fragment = 1;
        // Treating all fragments as opaque for now (pass them in filter)
        return 0;
    }

    // Parse Ports
    int ip_len = ihl * 4;
    void *l4_header = (void *)ip + ip_len;

    if (l4_header > data_end) return 0; // Should not happen given ihl check

    if (ip->protocol == IPPROTO_TCP) {
        // TCP Header: Src(2), Dst(2). Total 4 bytes needed.
        if (l4_header + 4 > data_end) return 0;
        
        // Manual Port Extraction (Big Endian on wire)
        __u8 *ports = (__u8 *)l4_header;
        // Src Port: Byte 0, 1 -> (b0 << 8) | b1
        *src_port = ((__u16)ports[0] << 8) | ports[1];
        // Dst Port: Byte 2, 3 -> (b2 << 8) | b3
        *dst_port = ((__u16)ports[2] << 8) | ports[3];
        
    } else if (ip->protocol == IPPROTO_UDP) {
        // UDP Header: Src(2), Dst(2). Total 8 bytes usually, but we need 4.
        if (l4_header + 4 > data_end) return 0;
        
        __u8 *ports = (__u8 *)l4_header;
        *src_port = ((__u16)ports[0] << 8) | ports[1];
        *dst_port = ((__u16)ports[2] << 8) | ports[3];
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
    // Uses the new manual byte-parser
    if (parse_ip_packet(ctx, &src_ip, &protocol, &dst_port, &src_port, &is_fragment) < 0)
        return XDP_PASS;

    __u64 pkt_size = (void *)(long)ctx->data_end - (void *)(long)ctx->data;
    __u32 key;
    __u32 cfg_key;

    // ============================================================
    // 2. ESSENTIAL OPTIMIZATIONS (Fast Pass)
    // ============================================================
    
    // 2.1 FAILSWITCH: Hardcoded Whitelist (Debug/Recovery)
    // Ensures connectivity to Critical DNS/Gateways regardless of Map Sync status.
    // IPs are in Network Byte Order (Big Endian).
    // 8.8.8.8 = 0x08080808 (Symmetric)
    // 1.1.1.1 = 0x01010101 (Symmetric)
    // 8.8.4.4 = 0x04040808 (LE view) -> BE 8.8.4.4 is 0x08080404?
    // Let's use specific hex values.
    // 8.8.8.8
    if (src_ip == 0x08080808) return XDP_PASS;
    // 1.1.1.1
    if (src_ip == 0x01010101) return XDP_PASS;
    
    // Private Networks
    __u32 ip_h = bpf_ntohl(src_ip);
    if ((ip_h & 0xFF000000) == 0x0A000000) return XDP_PASS; // 10.0.0.0/8
    if ((ip_h & 0xFFF00000) == 0xAC100000) return XDP_PASS; // 172.16.0.0/12
    if ((ip_h & 0xFFFF0000) == 0xC0A80000) return XDP_PASS; // 192.168.0.0/16
    if ((ip_h & 0xFF000000) == 0x7F000000) return XDP_PASS; // 127.0.0.0/8

    // 2.2 Maintenance / Essential Ports
    if (dst_port == 22 || dst_port == 51820 || dst_port == 8080) return XDP_PASS;

    // 2.3 Fragmented Packets
    if (is_fragment) return XDP_PASS;
    
    
    // ============================================================
    // 3. WHITELIST CHECK (Priority 1)
    // ============================================================
    struct lpm_key w_key;
    set_key_ipv4(&w_key, src_ip);
    __u32 *whitelisted = bpf_map_lookup_elem(&white_list, &w_key);
    if (whitelisted) {
        key = STAT_ALLOWED;
        __u64 *cnt = bpf_map_lookup_elem(&global_stats, &key);
        if (cnt) __sync_fetch_and_add(cnt, 1);
        
        key = STAT_TOTAL_PACKETS;
        cnt = bpf_map_lookup_elem(&global_stats, &key);
        if (cnt) __sync_fetch_and_add(cnt, 1);
        return XDP_PASS; 
    }


    // ============================================================
    // 4. BLACKLIST CHECK (Priority 2)
    // ============================================================
    struct lpm_key b_key;
    set_key_ipv4(&b_key, src_ip);
    __u32 *blocked = bpf_map_lookup_elem(&blocked_ips, &b_key);
    if (blocked && *blocked == 1) {
        key = STAT_BLOCKED;
        __u64 *cnt = bpf_map_lookup_elem(&global_stats, &key);
        if (cnt) __sync_fetch_and_add(cnt, 1);

        key = STAT_TOTAL_PACKETS;
        cnt = bpf_map_lookup_elem(&global_stats, &key);
        if (cnt) __sync_fetch_and_add(cnt, 1);
        
        return XDP_DROP;
    }


    // ============================================================
    // 5. RATE LIMIT CHECK (Priority 3)
    // ============================================================
    cfg_key = CONFIG_RATE_LIMIT_PPS;
    __u32 *rate_limit_pps = bpf_map_lookup_elem(&config, &cfg_key);
    if (rate_limit_pps && *rate_limit_pps > 0) {
        __u64 now = bpf_ktime_get_ns();
        struct rate_limit_entry *rl = bpf_map_lookup_elem(&rate_limits, &src_ip);
        
        if (rl) {
            __u64 elapsed = now - rl->last_update;
            if (elapsed > 1000000000ULL) elapsed = 1000000000ULL;
            
            __u64 tokens_to_add = (elapsed * (*rate_limit_pps)) / 1000000000ULL;
            __u64 new_tokens = rl->tokens + tokens_to_add;
            if (new_tokens > *rate_limit_pps) new_tokens = *rate_limit_pps;
            
            if (new_tokens < 1) {
                key = STAT_RATE_LIMITED;
                __u64 *cnt = bpf_map_lookup_elem(&global_stats, &key);
                if (cnt) __sync_fetch_and_add(cnt, 1);

                key = STAT_BLOCKED;
                cnt = bpf_map_lookup_elem(&global_stats, &key);
                if (cnt) __sync_fetch_and_add(cnt, 1);
                
                return XDP_DROP;
            }
            rl->tokens = new_tokens - 1;
            rl->last_update = now;
        } else {
            struct rate_limit_entry new_rl = { .tokens = *rate_limit_pps - 1, .last_update = now };
            bpf_map_update_elem(&rate_limits, &src_ip, &new_rl, BPF_ANY);
        }
    }


    // ============================================================
    // 6. DEFERRED STATS UPDATE
    // ============================================================
    key = STAT_TOTAL_PACKETS;
    __u64 *total_packets = bpf_map_lookup_elem(&global_stats, &key);
    if (total_packets) __sync_fetch_and_add(total_packets, 1);

    key = STAT_TOTAL_BYTES;
    __u64 *total_bytes = bpf_map_lookup_elem(&global_stats, &key);
    if (total_bytes) __sync_fetch_and_add(total_bytes, pkt_size);

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
    // 7. SAFE BYPASSES (Passed Rate Limit)
    // ============================================================

    // 7.1 TCP Outbound Response Bypass (Manual Byte Check)
    // Offset 13 (0-based) contains flags: CWR, ECE, URG, ACK, PSH, RST, SYN, FIN
    // We want ACK (0x10) or RST (0x04).
    if (protocol == IPPROTO_TCP) {
        // We need to re-calc offset using manual IHL extraction again?
        // No, we can rely on our manual IHL from parse_ip_packet which was valid.
        // We need to access data again.
        struct iphdr *ip = (void *)(long)ctx->data + sizeof(struct ethhdr);
        // Validated in parse_ip_packet, but verifier forgets.
        if ((void *)(ip + 1) > (void *)(long)ctx->data_end) return XDP_PASS; 
        
        __u8 ver_ihl = *((__u8 *)ip);
        __u8 ihl = ver_ihl & 0x0F;
        int ip_len = ihl * 4;
        
        __u8 *tcp_start = (void *)ip + ip_len;
        
        // Bounds check: TCP header byte 13
        if ((void *)(tcp_start + 14) <= (void *)(long)ctx->data_end) {
             __u8 flags = *(tcp_start + 13);
             if ((flags & 0x14) != 0) { // ACK or RST
                 key = STAT_ALLOWED;
                 __u64 *cnt = bpf_map_lookup_elem(&global_stats, &key);
                 if (cnt) __sync_fetch_and_add(cnt, 1);
                 return XDP_PASS;
             }
        }
    }

    // 7.2 Steam Query Bypass (A2S_INFO)
    if (protocol == IPPROTO_UDP) {
         // Re-calc offset
        struct iphdr *ip = (void *)(long)ctx->data + sizeof(struct ethhdr);
        if ((void *)(ip + 1) > (void *)(long)ctx->data_end) return XDP_PASS;
        __u8 ver_ihl = *((__u8 *)ip);
        __u8 ihl = ver_ihl & 0x0F;
        int ip_len = ihl * 4;
        
        void *udp_hdr = (void *)ip + ip_len;
        if (udp_hdr + 8 > (void *)(long)ctx->data_end) return XDP_PASS; // too short
        
        unsigned char *payload = udp_hdr + 8;
        if ((void *)(payload + 4) <= (void *)(long)ctx->data_end) {
             if (*(__u32*)payload == 0xFFFFFFFF) {
                 key = STAT_ALLOWED;
                 __u64 *cnt = bpf_map_lookup_elem(&global_stats, &key);
                 if (cnt) __sync_fetch_and_add(cnt, 1);
                 return XDP_PASS;
             }
        }
    }
    
    // 7.3 UDP Response Bypass (Origin Internet Fix)
    // ALLOW RESPONSE TRAFFIC from common services (DNS, HTTP, NTP)
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
    if (protocol == IPPROTO_ICMP) {
        key = STAT_ALLOWED;
        __u64 *cnt = bpf_map_lookup_elem(&global_stats, &key);
        if (cnt) __sync_fetch_and_add(cnt, 1);
        return XDP_PASS;
    }


    // ============================================================
    // 8. GEOIP CHECK (Last Line of Defense)
    // ============================================================
    struct lpm_key geo_key;
    set_key_ipv4(&geo_key, src_ip);
    __u32 *country = bpf_map_lookup_elem(&geo_allowed, &geo_key);
    
    // If NOT found in Allowed GeoIP Map
    if (!country) {
        // FAIL-SAFE: Only DROP if "Hard Blocking" is explicitly enabled
        cfg_key = CONFIG_HARD_BLOCKING;
        __u32 *hard_blocking = bpf_map_lookup_elem(&config, &cfg_key);
        
        if (hard_blocking && *hard_blocking == 1) {
            key = STAT_BLOCKED;
            __u64 *cnt = bpf_map_lookup_elem(&global_stats, &key);
            if (cnt) __sync_fetch_and_add(cnt, 1);
            
             struct packet_stats *s = bpf_map_lookup_elem(&ip_stats, &src_ip);
             if (s) s->blocked = 1;

            return XDP_DROP;
        }
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
