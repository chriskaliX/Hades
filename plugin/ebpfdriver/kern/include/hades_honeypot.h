/* Hades-ePot(Experimental)
 *
 * ePot in driver for temporary, this will be moved into honeyPot plugin
 * Authors: chriskalix@protonmail.com
 */

#ifndef CORE
#include <linux/bpf.h>
#include <sys/socket.h>
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
    u32 sip;
    u16 sport;
} net_packet_t;

static __always_inline int tc_probe(struct __sk_buff *skb, bool ingress)
{
    uint8_t *start = (uint8_t *) (long) skb->data;
    uint8_t *end = (uint8_t *) (long) skb->data_end;
    
    // eth headers
    struct ethhdr *eth = (struct ethhdr *)start;
    // IP headers
    struct iphdr *iph = (struct iphdr *)(start + sizeof(struct ethhdr));

    net_packet_t pkt = {0};
    uint32_t l4_hdr_off;
    // For internal network, for now, only ipv4
    switch (bpf_ntohs(eth->h_proto))
    {
        case ETH_P_IP:
            l4_hdr_off = sizeof(struct ethhdr) + sizeof(struct iphdr);
            if (!skb_revalidate_data(skb, &start, &end, l4_hdr_off))
                return TC_ACT_UNSPEC;
            // get eth from
            pkt.sip = ip->saddr;
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
    // net
    u64 flags = BPF_F_CURRENT_CPU;
    // TODO: filter
    bpf_perf_event_output(skb, &net_events, flags, &pkt, pkt_size);
    return TC_ACT_UNSPEC;
}

// Initially, we handle TC & XDP with port scanning attack
// We attach to the eth0 or other physical interfaces rather than docker0
//
// This hook is Experimental, under performance check. Be careful using this in
// production environment.
SEC("classifier/ingress")
int classifier_ingress(struct __sb_buff *skb)
{
    return tc_probe(skb, true);
}


// SEC("xdp/ingress")
// int hades_xdp(struct xdp_md *ctx)
// {
//     int ipsize = 0;
//     void *data = (void *)(long)ctx->data;
//     void *data_end = (void *)(long)ctx->data_end;
//     struct ethhdr *eth = data;
//     struct iphdr *ip;
 
//     ipsize = sizeof(*eth);
//     ip = data + ipsize;
 
//     ipsize += sizeof(struct iphdr);
//     if (data + ipsize > data_end) {
//         return XDP_DROP;
//     }
 
//     if (ip->protocol == IPPROTO_TCP) {
//         struct tcphdr *tcp = (void *)ip + sizeof(*ip);
//         ipsize += sizeof(struct tcphdr);
//         if (data + ipsize > data_end) {
//             return XDP_DROP;
//         }
        
//         if (tcp->dest == bpf_ntohs(8000)) {
//             return XDP_DROP;
//         }
//     }

//     return XDP_PASS;
// }


// Test for 180.101.49.12 baidu
// struct hades_socket {
//     __u32 sip;
//     __u32 dip;
//     __u32 sport;
//     __u32 dport;
//     __u32 family;
// };

// BPF_SOCKHASH(sock_ops_map, struct hades_socket, int, 65535);

// SEC("sockops")
// int hades_sockops(struct bpf_sock_ops *skops)
// {
//     if (skops->family != AF_INET)
//         return BPF_OK;
//     if (skops->op != BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB
//         && skops->op != BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB) {
//         return BPF_OK;
//     }
//     struct hades_socket key = {
//         .dip = skops->remote_ip4,
//         .sip = skops->local_ip4,
//         /* convert to network byte order */
//         .sport = bpf_htonl(skops->local_port),
//         .dport = skops->remote_port,
//         .family = skops->family,
//     };
//     bpf_printk("dip: %d, sip:%d\n", key.dip, key.sip);

//     // bpf_sock_hash_update(skops, &sock_ops_map, &key, BPF_NOEXIST);
//     return BPF_OK;
// };

// SEC("sk_msg")
// int bpf_redir(struct sk_msg_md *msg)
// {
//     if (msg->family != AF_INET) {
//         return SK_PASS;
//     }

//     struct sock_key key = {
//         .sip = msg->remote_ip4,
//         .dip = msg->local_ip4,
//         .dport = bpf_htonl(msg->local_port),
//         .sport = msg->remote_port,
//         .family = msg->family,
//     };
//     bpf_msg_redirect_hash(msg, &sock_ops_map, &key, BPF_F_INGRESS);
//     return SK_PASS;
// }
