/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __GENERAL_H
#define __GENERAL_H
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "vmlinux.h"
#include "define.h"

#define TC_ACT_UNSPEC       (-1)
#define TC_ACT_OK		    0
#define TC_ACT_RECLASSIFY	1
#define TC_ACT_SHOT		    2

// events
// The only perf of the eguard
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

// net context
typedef struct net_context {
    u32 event_type;
    uint64_t ts;
    u32 len;
    u32 ifindex;
    struct in6_addr src_addr, dst_addr;
    __be16 src_port, dst_port;
    u8 protocol;
    u8 action;
    u8 ingress;
} net_context_t;

// net packet
typedef struct net_packet {
    net_context_t ctx;
    buf_t *buf_p;
    u32 buf_off;
} net_packet_t;

// Dump the skeleton
struct net_packet _net_packet = {0};

struct data_context _context = {0};

struct net_context _net_context = {0};

#endif