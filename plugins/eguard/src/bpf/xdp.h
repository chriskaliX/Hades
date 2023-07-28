/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#include "../../../libs/core/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

// configuration
struct redirect_value {
    struct  in6_addr addr;
    __u16   port;
};

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, u16);                   // port
	__type(value, struct redirect_value); // count
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, POLICY_MAP_SIZE);
} redirect_map SEC(".maps");

// from katran
__attribute__((__always_inline__)) static inline __u16 csum_fold_helper(__u64 csum) {
    int i;
#pragma unroll
    for (i = 0; i < 4; i++) {
    if (csum >> 16)
        csum = (csum & 0xffff) + (csum >> 16);
    }
    return ~csum;
}


SEC("xdp")
int xdp_prog(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if (eth + 1 > (struct ethhdr *)data_end)
        return XDP_DROP;

    struct iphdr *iph = (data + sizeof(struct ethhdr));
    if (iph + 1 > (struct iphdr *)data_end)
        return XDP_DROP;
    
    if (iph->protocol == IPPROTO_TCP) { // only cope with tcp
        struct tcphdr *tcph = (data + sizeof(struct ethhdr) + sizeof(struct iphdr));
        if (tcph + 1 > (struct tcphdr *)data_end)
            return XDP_DROP;
    }
};