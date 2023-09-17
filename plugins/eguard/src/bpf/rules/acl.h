/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __ACL_H
#define __ACL_H
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "../common/general.h"
#include "vmlinux.h"

#define MAX_PORT_ARR    32
#define ACTION_DENY     0
#define ACTION_LOG      1
#define POLICY_MAP_SIZE  16384
#define PROTOCOL_ALL    0

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

static __always_inline int acl_rule(net_packet_t pkt, struct __sk_buff *skb) {
    struct policy_key key = {0};
    key.prefixlen = 128;

    if (pkt.ingress == 0) {
        key.addr = pkt.dst_addr;
    } else {
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
}

#endif