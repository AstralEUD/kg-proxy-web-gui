//go:build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// ============================================================
// SIMPLIFIED XDP FILTER (v2.0)
// ============================================================
// Flow:
// 1. Private Network + Management Ports (SSH, WireGuard) -> PASS
// 2. Whitelist -> PASS
// 3. Blacklist -> DROP
// 4. Connection Tracking (Response from servers we connected to) -> PASS
// 5. Steam A2S Query -> PASS
// 6. PPS Rate Limit -> DROP if exceeded
// 7. GeoIP -> DROP if not in allowed countries
// 8. Otherwise -> PASS
// ============================================================

// Packet statistics per source IP
struct packet_stats {
    __u64 packets;
    __u64 bytes;
    __u64 last_seen;
    __u32 blocked;
    __u32 pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 100000);
    __type(key, __u32);
    __type(value, struct packet_stats);
} ip_stats SEC(".maps");

// LPM Trie Key
struct lpm_key {
    __u32 prefixlen;
    __u8  data[4];
};

static __always_inline void set_key_ipv4(struct lpm_key *key, __u32 ip) {
    key->prefixlen = 32;
    __u8 *bytes = (__u8 *)&ip;
    key->data[0] = bytes[0];
    key->data[1] = bytes[1];
    key->data[2] = bytes[2];
    key->data[3] = bytes[3];
}

// Whitelist (allow)
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 10000);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct lpm_key);
    __type(value, __u32);
} white_list SEC(".maps");

// Blacklist (block)
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 10000);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct lpm_key);
    __type(value, __u32);
} blocked_ips SEC(".maps");

// GeoIP allowed countries
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 600000);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct lpm_key);
    __type(value, __u32);
} geo_allowed SEC(".maps");

// Active connections (TC egress tracking)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 50000);
    __type(key, __u32);
    __type(value, __u64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} active_connections SEC(".maps");

#define CONN_TRACK_TTL_NS (60ULL * 1000000000ULL)

// Rate limiting
struct rate_limit_entry {
    __u64 tokens;
    __u64 last_update;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 100000);
    __type(key, __u32);
    __type(value, struct rate_limit_entry);
} rate_limits SEC(".maps");

// Global statistics
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, __u64);
} global_stats SEC(".maps");

#define STAT_TOTAL_PACKETS 0
#define STAT_TOTAL_BYTES   1
#define STAT_BLOCKED       2
#define STAT_ALLOWED       3
#define STAT_RATE_LIMITED  4
#define STAT_CONN_BYPASS   5
#define STAT_GEOIP_BLOCKED 6

// Configuration
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u32);
} config SEC(".maps");

#define CONFIG_HARD_BLOCKING  0
#define CONFIG_RATE_LIMIT_PPS 1

// Port stats (optional, for monitoring)
struct port_stats {
    __u64 packets;
    __u64 bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u16);
    __type(value, struct port_stats);
} port_stats SEC(".maps");

// ============================================================
// PACKET PARSER
// ============================================================
static __always_inline int parse_ip_packet(struct xdp_md *ctx, __u32 *src_ip, __u16 *protocol, __u16 *dst_port, __u16 *src_port) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end) return -1;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return -1;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return -1;

    __u8 ihl = (*((__u8 *)ip)) & 0x0F;
    if (ihl < 5) return -1;

    *src_ip = ip->saddr;
    *protocol = ip->protocol;
    *dst_port = 0;
    *src_port = 0;

    int ip_len = ihl * 4;
    void *l4_header = (void *)ip + ip_len;
    if (l4_header > data_end) return 0;

    if (ip->protocol == IPPROTO_TCP || ip->protocol == IPPROTO_UDP) {
        if (l4_header + 4 > data_end) return 0;
        __u8 *ports = (__u8 *)l4_header;
        *src_port = ((__u16)ports[0] << 8) | ports[1];
        *dst_port = ((__u16)ports[2] << 8) | ports[3];
    }
    return 0;
}

// ============================================================
// MAIN XDP FILTER
// ============================================================
SEC("xdp")
int xdp_traffic_filter(struct xdp_md *ctx) {
    __u32 src_ip = 0;
    __u16 protocol = 0;
    __u16 dst_port = 0;
    __u16 src_port = 0;
    __u32 key;

    if (parse_ip_packet(ctx, &src_ip, &protocol, &dst_port, &src_port) < 0)
        return XDP_PASS;

    __u64 pkt_size = (void *)(long)ctx->data_end - (void *)(long)ctx->data;

    // ============================================================
    // 0. WIREGUARD BYPASS (HIGHEST PRIORITY)
    // ============================================================
    // WireGuard MUST work regardless of any other filter
    if (protocol == IPPROTO_UDP) {
        if (dst_port == 51820 || src_port == 51820) {
            return XDP_PASS;
        }
    }

    // ============================================================
    // 1. ESSENTIAL BYPASSES (Always Pass)
    // ============================================================
    // Private Networks
    __u32 ip_h = bpf_ntohl(src_ip);
    if ((ip_h & 0xFF000000) == 0x0A000000) return XDP_PASS; // 10.0.0.0/8
    if ((ip_h & 0xFFF00000) == 0xAC100000) return XDP_PASS; // 172.16.0.0/12
    if ((ip_h & 0xFFFF0000) == 0xC0A80000) return XDP_PASS; // 192.168.0.0/16
    if ((ip_h & 0xFF000000) == 0x7F000000) return XDP_PASS; // 127.0.0.0/8

    // Management Ports (SSH, Admin Panel)
    if (dst_port == 22 || dst_port == 8080) return XDP_PASS;

    // ============================================================
    // 2. WHITELIST -> PASS
    // ============================================================
    struct lpm_key w_key;
    set_key_ipv4(&w_key, src_ip);
    if (bpf_map_lookup_elem(&white_list, &w_key)) {
        key = STAT_ALLOWED;
        __u64 *cnt = bpf_map_lookup_elem(&global_stats, &key);
        if (cnt) __sync_fetch_and_add(cnt, 1);
        return XDP_PASS;
    }

    // ============================================================
    // 3. BLACKLIST -> DROP
    // ============================================================
    struct lpm_key b_key;
    set_key_ipv4(&b_key, src_ip);
    __u32 *blocked = bpf_map_lookup_elem(&blocked_ips, &b_key);
    if (blocked && *blocked == 1) {
        key = STAT_BLOCKED;
        __u64 *cnt = bpf_map_lookup_elem(&global_stats, &key);
        if (cnt) __sync_fetch_and_add(cnt, 1);
        return XDP_DROP;
    }

    // ============================================================
    // 4. CONNECTION TRACKING (Response Bypass)
    // ============================================================
    // If source IP is a server we recently connected to, bypass
    __u64 *conn_last_seen = bpf_map_lookup_elem(&active_connections, &src_ip);
    if (conn_last_seen) {
        __u64 now = bpf_ktime_get_ns();
        if ((now - *conn_last_seen) < CONN_TRACK_TTL_NS) {
            key = STAT_CONN_BYPASS;
            __u64 *cnt = bpf_map_lookup_elem(&global_stats, &key);
            if (cnt) __sync_fetch_and_add(cnt, 1);
            return XDP_PASS;
        }
    }

    // ============================================================
    // 5. STEAM A2S QUERY BYPASS
    // ============================================================
    if (protocol == IPPROTO_UDP) {
        struct iphdr *ip = (void *)(long)ctx->data + sizeof(struct ethhdr);
        if ((void *)(ip + 1) <= (void *)(long)ctx->data_end) {
            __u8 ihl = (*((__u8 *)ip)) & 0x0F;
            void *udp_hdr = (void *)ip + (ihl * 4);
            if (udp_hdr + 8 <= (void *)(long)ctx->data_end) {
                unsigned char *payload = udp_hdr + 8;
                if ((void *)(payload + 4) <= (void *)(long)ctx->data_end) {
                    if (*(__u32*)payload == 0xFFFFFFFF) { // Steam A2S signature
                        key = STAT_ALLOWED;
                        __u64 *cnt = bpf_map_lookup_elem(&global_stats, &key);
                        if (cnt) __sync_fetch_and_add(cnt, 1);
                        return XDP_PASS;
                    }
                }
            }
        }
    }

    // ============================================================
    // 6. PPS RATE LIMIT -> DROP if exceeded
    // ============================================================
    __u32 cfg_key = CONFIG_RATE_LIMIT_PPS;
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
    // 7. GEOIP -> DROP if not in allowed countries
    // ============================================================
    cfg_key = CONFIG_HARD_BLOCKING;
    __u32 *hard_blocking = bpf_map_lookup_elem(&config, &cfg_key);
    
    if (hard_blocking && *hard_blocking == 1) {
        struct lpm_key geo_key;
        set_key_ipv4(&geo_key, src_ip);
        if (!bpf_map_lookup_elem(&geo_allowed, &geo_key)) {
            key = STAT_GEOIP_BLOCKED;
            __u64 *cnt = bpf_map_lookup_elem(&global_stats, &key);
            if (cnt) __sync_fetch_and_add(cnt, 1);
            
            key = STAT_BLOCKED;
            cnt = bpf_map_lookup_elem(&global_stats, &key);
            if (cnt) __sync_fetch_and_add(cnt, 1);
            return XDP_DROP;
        }
    }

    // ============================================================
    // 8. UPDATE STATS & PASS
    // ============================================================
    key = STAT_TOTAL_PACKETS;
    __u64 *cnt = bpf_map_lookup_elem(&global_stats, &key);
    if (cnt) __sync_fetch_and_add(cnt, 1);

    key = STAT_TOTAL_BYTES;
    cnt = bpf_map_lookup_elem(&global_stats, &key);
    if (cnt) __sync_fetch_and_add(cnt, pkt_size);

    // Per-IP stats
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

    // Per-port stats
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

    key = STAT_ALLOWED;
    cnt = bpf_map_lookup_elem(&global_stats, &key);
    if (cnt) __sync_fetch_and_add(cnt, 1);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
