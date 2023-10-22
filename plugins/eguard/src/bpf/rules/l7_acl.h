#ifndef __L7_ACL_H
#define __L7_ACL_H
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "common/general.h"
#include "vmlinux.h"

#define DNS_OFFSET    (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr))
#define TYPE_DNS      3201
#define MAX_DNS_NAME  255

// The header contains the following fields:
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                      ID                       |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                    QDCOUNT                    |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                    ANCOUNT                    |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                    NSCOUNT                    |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                    ARCOUNT                    |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
struct dnshdr {
    u16 id;
    u16 flags;
    u16 qdcount;
    u16 ancount;
    u16 nscount;
    u16 arcount;
};
struct dnshdr _dnshdr = {0};

#define SIZE_DNSHDR         sizeof(struct dnshdr)
#define SIZE_CONTEXT        sizeof(net_context_t)
#define DNS_MAX_LEN         255
#define DNS_MAX_READ_LEN    256
#define MID_WAY             8192

static __always_inline int tc_context_fill(net_packet_t pkt);
static __always_inline int load_dns(net_packet_t pkt, struct __sk_buff *skb);

/* l7_acl_rule
 *
 * The L7 ACL rule would deny or record the application layer packet differ from 
 * the protocol. The function for now is under development, only DNS is planned.
 * Others is also considered.
 */
static __always_inline int l7_acl_rule(net_packet_t pkt, struct __sk_buff *skb) {
    // process dns
    if ((pkt.ctx.ingress == 0) && (pkt.ctx.protocol == IPPROTO_UDP) && (pkt.ctx.dst_port == 13568)) {
        struct dnshdr dns_header = {0};
        if (pkt.buf_p == NULL)
            return TC_ACT_UNSPEC;

        pkt.ctx.event_type = TYPE_DNS;
        // set ctx into buffer
        tc_context_fill(pkt);

        bpf_skb_load_bytes(skb, DNS_OFFSET, (void *)&pkt.buf_p->buf[SIZE_CONTEXT], SIZE_DNSHDR);
        int offset = load_dns(pkt, skb);
        void *output_data = pkt.buf_p->buf;
        return bpf_perf_event_output(skb, &events, BPF_F_CURRENT_CPU, output_data, SIZE_CONTEXT + SIZE_DNSHDR + offset + 2);
    }
    
    return TC_ACT_UNSPEC;
}

static __always_inline int tc_context_fill(net_packet_t pkt)
{
    __builtin_memcpy(&pkt.buf_p->buf[0], &pkt.ctx.event_type, sizeof(uint32_t));
    __builtin_memcpy(&pkt.buf_p->buf[8], &pkt.ctx.ts, sizeof(uint64_t));
    __builtin_memcpy(&pkt.buf_p->buf[16], &pkt.ctx.len, sizeof(uint32_t));
    __builtin_memcpy(&pkt.buf_p->buf[20], &pkt.ctx.ifindex, sizeof(uint32_t));
    __builtin_memcpy(&pkt.buf_p->buf[24], &pkt.ctx.src_addr, sizeof(struct in6_addr));
    __builtin_memcpy(&pkt.buf_p->buf[40], &pkt.ctx.dst_addr, sizeof(struct in6_addr));
    __builtin_memcpy(&pkt.buf_p->buf[56], &pkt.ctx.src_port, sizeof(uint16_t));
    __builtin_memcpy(&pkt.buf_p->buf[58], &pkt.ctx.dst_port, sizeof(uint16_t));
    pkt.buf_p->buf[60] = pkt.ctx.protocol;
    pkt.buf_p->buf[61] = pkt.ctx.action;
    pkt.buf_p->buf[62] = pkt.ctx.ingress;
}

/* 
 * | total_length(2) | domain(total_length) | query_type |
 */

static __always_inline int load_dns(net_packet_t pkt, struct __sk_buff *skb)
{
    int i = 0;
    int point_offset = 0;
#pragma unroll
    for (i = 0; i < DNS_MAX_LEN; i++) {
        u32 buf_index = (SIZE_CONTEXT + SIZE_DNSHDR + i + 1) & (MAX_PERCPU_BUFSIZE - 1);
        bpf_skb_load_bytes(skb, DNS_OFFSET + SIZE_DNSHDR + i, (void *)&(pkt.buf_p->buf[buf_index]), sizeof(u8));
        if (pkt.buf_p->buf[buf_index] == 0x00)
            break;
        if (i == point_offset) {
            point_offset += pkt.buf_p->buf[buf_index] + 1;
            if (i != 0)
                pkt.buf_p->buf[buf_index] = 46;
        }
    }

    u16 dns_offset = i - 1;
    __builtin_memcpy(&(pkt.buf_p->buf[SIZE_CONTEXT + SIZE_DNSHDR]), &dns_offset, sizeof(u16));
    return i;
}

#endif