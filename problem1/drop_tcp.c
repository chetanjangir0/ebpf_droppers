//go:build ignore
#include <linux/in.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Map to store the port number (configurable from userspace)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u16);
} port_map SEC(".maps");

SEC("tc")
int drop_tcp_port(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    
    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;
    
    // Check if it's IP packet
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;
    
    // Parse IP header
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;
    
    // Check if it's TCP
    if (ip->protocol != IPPROTO_TCP)
        return TC_ACT_OK;
    
    // Parse TCP header
    struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
    if ((void *)(tcp + 1) > data_end)
        return TC_ACT_OK;
    
    // Get the port to drop from map
    __u32 key = 0;
    __u16 *port_to_drop = bpf_map_lookup_elem(&port_map, &key);
    if (!port_to_drop)
        return TC_ACT_OK;
    
    // Check destination port
    __u16 dest_port = bpf_ntohs(tcp->dest);
    
    if (dest_port == *port_to_drop) {
        bpf_printk("Dropping TCP packet on port %d\n", dest_port);
        return TC_ACT_SHOT;  // Drop the packet
    }
    
    return TC_ACT_OK;  // Allow the packet
}

char _license[] SEC("license") = "GPL";
