//go:build ignore

// TC Egress Connection Tracking
// Tracks outbound connections from Origin servers (via WireGuard tunnel)
// so that XDP can bypass filtering for their responses.

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Active connections map - shared with XDP via pinning
// Key: destination IP (external server)
// Value: last_seen timestamp (nanoseconds, monotonic)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 50000);
    __type(key, __u32);    // dest_ip (network byte order)
    __type(value, __u64);  // last_seen (ns)
    __uint(pinning, LIBBPF_PIN_BY_NAME);  // Pin to /sys/fs/bpf/
} active_connections SEC(".maps");

// Statistics for monitoring
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} tc_stats SEC(".maps");

#define STAT_TRACKED_CONNECTIONS 0
#define STAT_TCP_TRACKED         1
#define STAT_UDP_TRACKED         2
#define STAT_TOTAL_PACKETS       3

SEC("tc")
int tc_egress_track(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    
    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;
    
    // Only process IPv4
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;
    
    // Parse IP header
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;
    
    // Get destination IP (the external server we're connecting to)
    __u32 dest_ip = ip->daddr;
    
    // Skip private/local destinations (no need to track)
    // These won't come from external sources anyway
    __u32 dest_h = bpf_ntohl(dest_ip);
    
    // 10.0.0.0/8
    if ((dest_h & 0xFF000000) == 0x0A000000)
        return TC_ACT_OK;
    // 172.16.0.0/12
    if ((dest_h & 0xFFF00000) == 0xAC100000)
        return TC_ACT_OK;
    // 192.168.0.0/16
    if ((dest_h & 0xFFFF0000) == 0xC0A80000)
        return TC_ACT_OK;
    // 127.0.0.0/8 (loopback)
    if ((dest_h & 0xFF000000) == 0x7F000000)
        return TC_ACT_OK;
    
    // Update statistics
    __u32 stat_key = STAT_TOTAL_PACKETS;
    __u64 *cnt = bpf_map_lookup_elem(&tc_stats, &stat_key);
    if (cnt) __sync_fetch_and_add(cnt, 1);
    
    // Track based on protocol
    __u8 protocol = ip->protocol;
    
    if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP) {
        // Record this destination IP as an active connection
        __u64 now = bpf_ktime_get_ns();
        
        // Update or insert the connection
        bpf_map_update_elem(&active_connections, &dest_ip, &now, BPF_ANY);
        
        // Update protocol-specific stats
        stat_key = STAT_TRACKED_CONNECTIONS;
        cnt = bpf_map_lookup_elem(&tc_stats, &stat_key);
        if (cnt) __sync_fetch_and_add(cnt, 1);
        
        if (protocol == IPPROTO_TCP) {
            stat_key = STAT_TCP_TRACKED;
            cnt = bpf_map_lookup_elem(&tc_stats, &stat_key);
            if (cnt) __sync_fetch_and_add(cnt, 1);
        } else {
            stat_key = STAT_UDP_TRACKED;
            cnt = bpf_map_lookup_elem(&tc_stats, &stat_key);
            if (cnt) __sync_fetch_and_add(cnt, 1);
        }
    }
    
    // Always allow the packet to pass (we're just tracking)
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
