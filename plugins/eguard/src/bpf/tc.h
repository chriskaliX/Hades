/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "../../../libs/core/vmlinux.h"

#define ETH_P_IP    0x0800
#define ETH_P_IPV6  0x86DD

#define TC_ACT_UNSPEC       (-1)
#define TC_ACT_OK		    0
#define TC_ACT_RECLASSIFY	1
#define TC_ACT_SHOT		    2

#define s6_addr16 in6_u.u6_addr16
#define s6_addr32 in6_u.u6_addr32

#define POLICY_MAP_SIZE  16384
#define ACTION_DENY     0
#define ACTION_LOG      1
#define PROTOCOL_ALL    0

#define MAX_PORT_ARR    32

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

struct policy_value {
    __u32   action;
    __u32   protocol;
    __u16   ports[MAX_PORT_ARR];       // 32
    __u16   ports_range[MAX_PORT_ARR]; // 16 range only
    __u8    ingress;
};

// Dump the skeleton
struct policy_key _policy_key = {0};
struct policy_value _policy_value = {0};

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct policy_key);
	__type(value, struct policy_value); // count
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, POLICY_MAP_SIZE);
} policy_map SEC(".maps");

// check the port
// true: matched
// false: not matched
static __always_inline bool
port_check(struct policy_value *policy, __u16 port)
{
    int empty = false;
#pragma unroll
    for (int i = 0; i < MAX_PORT_ARR; i++) {
        // if the port not set, return true;
        if (policy->ports[i] == 0) {
            // if empty, means match all
            if (i == 0)
                empty = true;
            break;
        }
        if (policy->ports[i] == port) {
            return true;
        }
    }
#pragma unroll
    for (int i = 0; i < MAX_PORT_ARR; i+=2) {
        if (policy->ports_range[i] == 0 || policy->ports_range[i+1] == 0) {
            if (i == 0)
                return empty;
            return false;
        }
        if (policy->ports_range[i] <= bpf_ntohs(port) && policy->ports_range[i+1] >= bpf_ntohs(port))
            return true;
    }
    return false;
}

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
    u8 action;
    u8 ingress;
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
    pkt.action = ACTION_LOG;

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

    // get protocol through the packet, icmp & icmpv6 will be supported in the feature
    // 
    switch (pkt.protocol) {
        case IPPROTO_TCP:
            if (!skb_revalidate_data(skb, &start, &end, l4_hdr_off + sizeof(struct tcphdr)))
                return TC_ACT_UNSPEC;
            struct tcphdr *tcp = (void *) start + l4_hdr_off;
            pkt.src_port = tcp->source;
            pkt.dst_port = tcp->dest;
            break;
        case IPPROTO_UDP:
            if (!skb_revalidate_data(skb, &start, &end, l4_hdr_off + sizeof(struct udphdr)))
                return TC_ACT_UNSPEC;
            struct udphdr *udp = (void *) start + l4_hdr_off;
            pkt.src_port = udp->source;
            pkt.dst_port = udp->dest;
    }

    struct policy_key key = {0};
    // egress
    if(ingress == false) {
        pkt.ingress = 0;
        key.prefixlen = 128;
        key.addr = pkt.dst_addr;
    // ingress
    } else {
        pkt.ingress = 1;
        key.prefixlen = 128;
        key.addr = pkt.src_addr;
    }
    struct policy_value *value = bpf_map_lookup_elem(&policy_map, &key);
    if (value && value->ingress == pkt.ingress) {
        size_t pkt_size = sizeof(pkt);
        // protocol match, port is ignored
        if (value->protocol != PROTOCOL_ALL && value->protocol != pkt.protocol) {
            return TC_ACT_UNSPEC;
        }
        // for now, only support udp & tcp
        if (pkt.protocol == IPPROTO_TCP || pkt.protocol == IPPROTO_UDP) {
            if (port_check(value, pkt.dst_port) == false) {
                return TC_ACT_UNSPEC;
            }
        }
        if (value->action == ACTION_DENY) {
            pkt.action = ACTION_DENY;
            bpf_perf_event_output(skb, &events, BPF_F_CURRENT_CPU, &pkt, pkt_size);
            return TC_ACT_SHOT;
        } else {
            bpf_perf_event_output(skb, &events, BPF_F_CURRENT_CPU, &pkt, pkt_size);
        }
    }
    return TC_ACT_UNSPEC;
};
