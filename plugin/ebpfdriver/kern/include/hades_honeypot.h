/* Hades-ePot(Experimental)
 * ePot monitor all ingress for filters. It detects all port scan actions.
 * TCP: maybe tcp_send_reset is a better choice.
 * IMCP: maybe icmp_rcv
 * UDP: will send ICMP unreachable, hook icmp send and grep unreachable
 *
 * ePot in driver for temporary, this will be moved into honeyPot plugin
 * Authors: chriskalix@protonmail.com
 */

#ifndef CORE
#include <linux/bpf.h>
#include <linux/socket.h>
#include <linux/ip.h>
#endif

#include "define.h"
#include "utils_buf.h"
#include "utils.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"
#include "bpf_tracing.h"

// from tracee
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

static __always_inline int tc_probe(struct __sk_buff *skb, bool ingress)
{
    uint8_t *start = (uint8_t *) (long) skb->data;
    uint8_t *end = (uint8_t *) (long) skb->data_end;
    // packet pre check
    if (start + sizeof(struct ethhdr) > end)
        return TC_ACT_UNSPEC;

    // eth headers
    struct ethhdr *eth = (struct ethhdr *)start;
    net_packet_t pkt = {0};
    pkt.ts = bpf_ktime_get_ns();
    pkt.len = skb->len;
    pkt.ifindex = skb->ifindex;
    uint32_t l4_hdr_off;
    // For internal network, for now, only ipv4
    switch (bpf_ntohs(eth->h_proto))
    {
        case ETH_P_IP:
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
            break;

        case ETH_P_IPV6:
            l4_hdr_off = sizeof(struct ethhdr) + sizeof(struct ipv6hdr);
            if (!skb_revalidate_data(skb, &start, &end, l4_hdr_off))
                return TC_ACT_UNSPEC;

            struct ipv6hdr *ip6 = (void *) start + sizeof(struct ethhdr);
            pkt.src_addr = ip6->saddr;
            pkt.dst_addr = ip6->daddr;
            pkt.protocol = ip6->nexthdr;
            break;
        default:
            return TC_ACT_UNSPEC;
    }
    // skip binded port, but how?
    // For tcp:
    // 1. security_socket_connect
    // 2. security_socket_bind
    // for now, we only care for TCP
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
    // TODO: filter
    size_t pkt_size = sizeof(pkt);
    // switch to net_events
    bpf_perf_event_output(skb, &net_events, BPF_F_CURRENT_CPU, &pkt, pkt_size);
    return TC_ACT_UNSPEC;
};

// Initially, we handle TC & XDP with port scanning attack
// We attach to the eth0 or other physical interfaces rather than docker0
//
// This hook is Experimental, under performance check. Be careful using this in
// production environment.
SEC("classifier/ingress")
int hades_ingress(struct __sk_buff *skb)
{
    return tc_probe(skb, true);
}

SEC("classifier/egress")
int hades_egress(struct __sk_buff *skb)
{
    return tc_probe(skb, false);
}

struct _tcp_send_reset {
    unsigned long long unused;
    long syscall_nr;
    const void * skbaddr;
    const void * skaddr; 
    int state;
    __u16 sport;
    __u16 dport;
    __u16 family;
    __u8 saddr[4];
    __u8 daddr[4];
    __u8 saddr_v6[16];
    __u8 daddr_v6[16];
};

// Below here, not tc used, under work
SEC("kprobe/tcp_v4_send_reset")
int BPF_KPROBE(kprobe_tcp_reset)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;
    // if (context_filter(&data.context))
    //     return 0;
    data.context.type = 3000;

    net_packet_t pkt = {0};
    pkt.ts = bpf_ktime_get_ns();
    // struct sock *sk = PT_REGS_PARM1(ctx);
    size_t pkt_size = sizeof(pkt);
    save_to_submit_buf(&data, &pkt, pkt_size, 1);
    return events_perf_submit(&data);
}