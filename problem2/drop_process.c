//go:build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/pkt_cls.h>

#define TASK_COMM_LEN 16
#define MAX_PROCESSES 100

// Config map to store allowed port and process name
struct config {
    __u16 allowed_port;
    char process_name[TASK_COMM_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct config);
} config_map SEC(".maps");

// Map to track PIDs of the target process
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_PROCESSES);
    __type(key, __u32);    // PID
    __type(value, __u8);   // dummy value
} pid_map SEC(".maps");

SEC("cgroup/sock_create")
int track_process(struct bpf_sock *sk) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));
    
    __u32 key = 0;
    struct config *cfg = bpf_map_lookup_elem(&config_map, &key);
    if (!cfg)
        return 1;
    
    // Check if current process matches target
    for (int i = 0; i < TASK_COMM_LEN; i++) {
        if (comm[i] != cfg->process_name[i]) {
            if (comm[i] == '\0' && cfg->process_name[i] == '\0')
                break;
            return 1;
        }
        if (comm[i] == '\0')
            break;
    }
    
    // Add PID to tracking map
    __u8 val = 1;
    bpf_map_update_elem(&pid_map, &pid, &val, BPF_ANY);
    bpf_printk("Tracking process: %s (PID: %d)\n", comm, pid);
    
    return 1;
}

SEC("cgroup/connect4")
int filter_connect(struct bpf_sock_addr *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    // Check if this PID is being tracked
    __u8 *tracked = bpf_map_lookup_elem(&pid_map, &pid);
    if (!tracked)
        return 1;  // Not our target process, allow
    
    __u32 key = 0;
    struct config *cfg = bpf_map_lookup_elem(&config_map, &key);
    if (!cfg)
        return 1;
    
    __u16 port = bpf_ntohs(ctx->user_port);
    
    // Allow traffic on allowed_port, drop everything else
    if (port == cfg->allowed_port) {
        bpf_printk("Allowing port %d for PID %d\n", port, pid);
        return 1;  // Allow
    }
    
    bpf_printk("Blocking port %d for PID %d\n", port, pid);
    return 0;  // Deny
}

char _license[] SEC("license") = "GPL";
