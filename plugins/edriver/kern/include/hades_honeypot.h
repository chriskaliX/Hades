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
#include <uapi/linux/in.h>
#include <uapi/linux/in6.h>
#include <uapi/linux/icmp.h>
#include <uapi/linux/icmpv6.h>
#else
#include <vmlinux.h>
#include <missing_definitions.h>
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

static inline int get_skb_info_v4(net_conn_v4_t* pdata, struct sk_buff *skb)
{
    struct iphdr *ip_header =
        (struct iphdr *) (READ_KERN(skb->head) + READ_KERN(skb->network_header));
    pdata->remote_address = READ_KERN(ip_header->daddr);
    pdata->local_address = READ_KERN(ip_header->saddr);
    u16 protocol = READ_KERN(ip_header->protocol);
    // check the protocol
    if (protocol == IPPROTO_TCP) {
        struct tcphdr *tcp_hdr = 
            (struct tcphdr *)(READ_KERN(skb->head) + READ_KERN(skb->transport_header));
        pdata->local_port = READ_KERN(tcp_hdr->source);
        pdata->remote_port = READ_KERN(tcp_hdr->dest);
    } else if (protocol == IPPROTO_UDP) {
        struct udphdr *udp_hdr = 
            (struct udphdr *)(READ_KERN(skb->head) + READ_KERN(skb->transport_header));
        pdata->local_port = READ_KERN(udp_hdr->source);
        pdata->remote_port = READ_KERN(udp_hdr->dest);
    } else if (protocol == IPPROTO_ICMP) {
        struct icmphdr *icmph =
            (struct icmphdr *) (READ_KERN(skb->head) + READ_KERN(skb->transport_header));
        pdata->remote_port = READ_KERN(icmph->un.echo.id);
    }
    return 0;
}

static inline int get_skb_info_v6(net_conn_v6_t* pdata, struct sk_buff *skb)
{
    struct ipv6hdr *ip_header =
        (struct ipv6hdr *) (READ_KERN(skb->head) + READ_KERN(skb->network_header));
    pdata->remote_address = READ_KERN(ip_header->daddr);
    pdata->local_address = READ_KERN(ip_header->saddr);
    u16 protocol = READ_KERN(ip_header->nexthdr);
    // check the protocol
    if (protocol == IPPROTO_TCP) {
        struct tcphdr *tcp_hdr = 
            (struct tcphdr *)(READ_KERN(skb->head) + READ_KERN(skb->transport_header));
        pdata->local_port = READ_KERN(tcp_hdr->source);
        pdata->remote_port = READ_KERN(tcp_hdr->dest);
    } else if (protocol == IPPROTO_UDP) {
        struct udphdr *udp_hdr = 
            (struct udphdr *)(READ_KERN(skb->head) + READ_KERN(skb->transport_header));
        pdata->local_port = READ_KERN(udp_hdr->source);
        pdata->remote_port = READ_KERN(udp_hdr->dest);
    } else if (protocol == IPPROTO_ICMP) {}
    return 0;
}

// Experimental and not that incorrect
SEC("kprobe/tcp_v4_send_reset")
int BPF_KPROBE(kprobe_tcp_reset)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;
    data.context.type = HONEYPOT_PORTSCAN_DETECT;
    u16 family = AF_INET6;
    save_to_submit_buf(&data, &family, sizeof(u16), 0);
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    net_conn_v4_t net_details = {};
    if (sk == NULL) {
        struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM2(ctx);
        get_skb_info_v4(&net_details, skb);
        save_to_submit_buf(&data, &net_details, sizeof(struct network_connection_v4), 1);
    } else {
        get_network_details_from_sock_v4(sk, &net_details, 0);
        save_to_submit_buf(&data, &net_details, sizeof(struct network_connection_v4), 1);
    }
    u8 protocol = IPPROTO_TCP;
    save_to_submit_buf(&data, &protocol, sizeof(protocol), 2);
    return events_perf_submit(&data);
}

#define HADES_ICMP_DEST_UNREACH 3

// Detection of UDP port scanning
// UDP is connectionless, it sends back the error msgs with ICMP
// look into __udp4_lib_rcv, the skb is an udp skb
SEC("kprobe/__icmp_send")
int BPF_KPROBE(kprobe_icmp_send)
{
    int type = PT_REGS_PARM2(ctx);
    if (type != HADES_ICMP_DEST_UNREACH)
        return 0;
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;
    data.context.type = HONEYPOT_PORTSCAN_DETECT;
    u16 family = AF_INET;
    save_to_submit_buf(&data, &family, sizeof(u16), 0);
    struct sk_buff *skb = (struct sk_buff *) PT_REGS_PARM1(ctx);
    net_conn_v4_t net_details = {};
    get_skb_info_v4(&net_details, skb);
    save_to_submit_buf(&data, &net_details, sizeof(struct network_connection_v4), 1);
    // Actually, it's UDP
    u8 protocol = IPPROTO_UDP;
    save_to_submit_buf(&data, &protocol, sizeof(protocol), 2);
    return events_perf_submit(&data);
}

SEC("kprobe/icmp6_send")
int BPF_KPROBE(krpobe_icmp6_send)
{
    int type = PT_REGS_PARM2(ctx);
    if (type != HADES_ICMP_DEST_UNREACH)
        return 0;
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;
    data.context.type = HONEYPOT_PORTSCAN_DETECT;
    u16 family = AF_INET6;
    save_to_submit_buf(&data, &family, sizeof(u16), 0);
    struct sk_buff *skb = (struct sk_buff *) PT_REGS_PARM1(ctx);
    net_conn_v6_t net_details = {};
    get_skb_info_v6(&net_details, skb);
    save_to_submit_buf(&data, &net_details, sizeof(struct network_connection_v6), 1);
    u8 protocol = IPPROTO_UDP;
    save_to_submit_buf(&data, &protocol, sizeof(protocol), 2);
    return events_perf_submit(&data);
}

SEC("kprobe/icmp_rcv")
int BPF_KPROBE(krpobe_icmp_rcv)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;
    data.context.type = HONEYPOT_PORTSCAN_DETECT;
    u16 family = AF_INET;
    save_to_submit_buf(&data, &family, sizeof(u16), 0);
    struct sk_buff *skb = (struct sk_buff *) PT_REGS_PARM1(ctx);
    net_conn_v4_t net_details = {};
    get_skb_info_v4(&net_details, skb);
    save_to_submit_buf(&data, &net_details, sizeof(struct network_connection_v4), 1);
    u8 protocol = IPPROTO_ICMP;
    save_to_submit_buf(&data, &protocol, sizeof(protocol), 2);
    return events_perf_submit(&data);
}

// May not export
SEC("kprobe/icmpv6_rcv")
int BPF_KPROBE(krpobe_icmpv6_rcv)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;
    data.context.type = HONEYPOT_PORTSCAN_DETECT;
    u16 family = AF_INET6;
    save_to_submit_buf(&data, &family, sizeof(u16), 0);
    struct sk_buff *skb = (struct sk_buff *) PT_REGS_PARM1(ctx);
    net_conn_v6_t net_details = {};
    get_skb_info_v6(&net_details, skb);
    save_to_submit_buf(&data, &net_details, sizeof(struct network_connection_v6), 1);
    u8 protocol = IPPROTO_ICMP;
    save_to_submit_buf(&data, &protocol, sizeof(protocol), 2);
    return events_perf_submit(&data);
}