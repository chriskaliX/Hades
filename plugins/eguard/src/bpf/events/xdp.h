/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#include "../../../libs/core/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

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
int filter_dns(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if (eth + 1 > (struct ethhdr *)data_end)
        return XDP_DROP;

    struct iphdr *iph = (data + sizeof(struct ethhdr));
    if (iph + 1 > (struct iphdr *)data_end)
        return XDP_DROP;
    
    if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (struct udphdr *)(iph + 1);
        if (udp->dest != bpf_htons(53))
            return XDP_DROP;
    }
    return XDP_PASS;
};