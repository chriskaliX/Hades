/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "vmlinux.h"
#include "rules/acl.h"
#include "common/general.h"

#define ETH_P_IP    0x0800
#define ETH_P_IPV6  0x86DD

#define s6_addr16 in6_u.u6_addr16
#define s6_addr32 in6_u.u6_addr32

#define TYPE_TC         3200

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
    pkt.event_type = TYPE_TC;
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
    pkt.ingress = ingress;

    return tc_rule(pkt, skb);
};
