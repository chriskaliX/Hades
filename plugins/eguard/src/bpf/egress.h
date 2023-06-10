/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "../../../libs/core/vmlinux.h"

#define ETH_P_IP    0x0800
#define ETH_P_IPV6  0x86DD

#define TC_ACT_UNSPEC	(-1)
#define TC_ACT_SHOT

#define s6_addr16 in6_u.u6_addr16
#define s6_addr32 in6_u.u6_addr32

#define EGRESS_POLICY_MAP_SIZE 16384

// send out the perf event
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

struct policy_key {
    __u32   prefixlen;
    struct  in6_addr addr;
};

// Dump the skeleton
struct policy_key _policy_key = {0};

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct policy_key);
	__type(value, u64); // count
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, EGRESS_POLICY_MAP_SIZE);
} EGRESS_POLICY_MAP SEC(".maps");

static __always_inline bool
skb_revalidate_data(struct __sk_buff *skb, uint8_t **head, uint8_t **tail, const u32 offset)
{
    if (*head + offset > *tail) {
        if (bpf_skb_pull_data(skb, offset) < 0) {
            return false;
        }
        *head = (uint8_t *) (long) skb->data;
        *tail = (uint8_t *) (long) skb->data_end;
        if (*head + offset > *tail) {
            return false;
        }
    }
    return true;
}

typedef struct net_packet {
    uint64_t ts;
    u32 len;
    u32 ifindex;
    struct in6_addr src_addr, dst_addr;
    __be16 src_port, dst_port;
    u8 protocol;
} net_packet_t;

// Dump the skeleton
struct net_packet _net_packet = {0};

/*
 * handle TC(traffic controll) function
 *
 * @param - skb - the bpf socket buffer mirror, defined in include/uapi/linux.bpf.h
            __sk_buff is the security access method of bpf to sk_buff
 * @param - ingress - true for ingress, false for egress
 *
 */
static __always_inline int tc_probe(struct __sk_buff *skb, int ingress)
{
    uint8_t *start = (uint8_t *) (long) skb->data;
    uint8_t *end = (uint8_t *) (long) skb->data_end;
    // packet pre check
    if (start + sizeof(struct ethhdr) > end)
        return TC_ACT_UNSPEC;
    struct ethhdr *eth = (struct ethhdr *)start;

    net_packet_t pkt = {0};
    pkt.ts = bpf_ktime_get_ns();
    pkt.len = skb->len;
    pkt.ifindex = skb->ifindex;
    uint32_t l4_hdr_off;

    // getting iphdr, keep protocol and sip and dip
    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        l4_hdr_off = sizeof(struct ethhdr) + sizeof(struct iphdr);
        if (!skb_revalidate_data(skb, &start, &end, l4_hdr_off))
            return TC_ACT_UNSPEC;
        // create a IPv4-Mapped IPv6 Address
        struct iphdr *ip = (void *) start + sizeof(struct ethhdr);
        pkt.src_addr.s6_addr32[3] = ip->saddr;
        pkt.dst_addr.s6_addr32[3] = ip->daddr;
        pkt.src_addr.s6_addr16[5] = 0xffff;
        pkt.dst_addr.s6_addr16[5] = 0xffff;
        pkt.protocol = ip->protocol;
    } else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
        l4_hdr_off = sizeof(struct ethhdr) + sizeof(struct ipv6hdr);
        if (!skb_revalidate_data(skb, &start, &end, l4_hdr_off))
            return TC_ACT_UNSPEC;

        struct ipv6hdr *ip6 = (void *) start + sizeof(struct ethhdr);
        pkt.src_addr = ip6->saddr;
        pkt.dst_addr = ip6->daddr;
        pkt.protocol = ip6->nexthdr;
    }

    // to parse the protocol and get the port
    //
    switch (pkt.protocol) {
        case IPPROTO_TCP:
            if (!skb_revalidate_data(skb, &start, &end, l4_hdr_off + sizeof(struct tcphdr)))
                return TC_ACT_UNSPEC;
            struct tcphdr *tcp = (void *) start + l4_hdr_off;
            pkt.src_port = tcp->source;
            pkt.dst_port = tcp->dest;
            break;
        default:
            return TC_ACT_UNSPEC;
    }
    // fill up the key
    struct policy_key key = { 
        .prefixlen = 128,
        .addr = pkt.dst_addr
    };
    if (bpf_map_lookup_elem(&EGRESS_POLICY_MAP, &key)) {
        size_t pkt_size = sizeof(pkt);
        bpf_perf_event_output(skb, &events, BPF_F_CURRENT_CPU, &pkt, pkt_size);
    }
    return TC_ACT_UNSPEC;
};

