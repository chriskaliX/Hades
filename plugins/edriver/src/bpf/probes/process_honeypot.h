// SPDX-License-Identifier: GPL-2.0-or-later

#ifndef __PROBES_PROCESS_HONEYPOT_H__
#define __PROBES_PROCESS_HONEYPOT_H__

#include <vmlinux.h>
#include <missing_definitions.h>
#include "runtime/constants.h"
#include "runtime/task_helpers.h"
#include "bpf_core_read.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"

#define HADES_ICMP_DEST_UNREACH 3

static __always_inline int honeypot_emit_sock(void *ctx, __u16 family, __u8 proto, struct sock *sk)
{
    struct hds_socket_info sinfo = {};
    struct hds_socket_info_v6 sinfo_v6 = {};
    if (sk) {
        if (family == AF_INET)
            get_sock_v4(sk, &sinfo);
        else if (family == AF_INET6)
            get_sock_v6(sk, &sinfo_v6);
    }

    struct hds_context event_ctx = init_context(ctx, HONEYPOT_PORTSCAN_DETECT);
    EVT_SUBMIT(&event_ctx,
        &event_ctx.data_type,
        &family,
        &proto,
        &sinfo,
        &sinfo_v6);
    return report_event(&event_ctx);
}

SEC("kprobe/tcp_v4_send_reset")
int BPF_KPROBE(kprobe_tcp_v4_send_reset)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    __u8 proto = IPPROTO_TCP;
    return honeypot_emit_sock(ctx, AF_INET, proto, sk);
}

SEC("kprobe/__icmp_send")
int BPF_KPROBE(kprobe___icmp_send)
{
    int type = (int)PT_REGS_PARM2(ctx);
    if (type != HADES_ICMP_DEST_UNREACH)
        return 0;

    __u8 proto = IPPROTO_UDP;
    return honeypot_emit_sock(ctx, AF_INET, proto, NULL);
}

SEC("kprobe/icmp6_send")
int BPF_KPROBE(kprobe_icmp6_send)
{
    int type = (int)PT_REGS_PARM2(ctx);
    if (type != HADES_ICMP_DEST_UNREACH)
        return 0;

    __u8 proto = IPPROTO_UDP;
    return honeypot_emit_sock(ctx, AF_INET6, proto, NULL);
}

#endif