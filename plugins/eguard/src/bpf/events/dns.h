/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "vmlinux.h"
#include "define.h"
#include "../rules/acl.h"
#include "../common/general.h"

SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(kprobe_udp_sendmsg)
{
    u16 dport, sport;
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2(ctx);
    // convert
    struct inet_sock *inet = (struct inet_sock *) sk;
    struct sockaddr_in *sin = READ_KERN(msg->msg_name);
    if (sin)
        dport = READ_KERN(sin->sin_port);
    else
        dport = READ_KERN(inet->inet_dport);
    sport = READ_KERN(inet->inet_num);
    if (dport == 13568 || dport == 59668 || dport == 0)
    {

    }
    return 0;
}