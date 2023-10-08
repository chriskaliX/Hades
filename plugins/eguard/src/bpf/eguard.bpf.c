// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2023 chriskali
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "events/tc.h"
#include "events/dns.h"
// #include "events/xdp.h"

SEC("tc")
int hades_egress(struct __sk_buff *skb)
{
    return tc_probe(skb, false);
}

SEC("tc")
int hades_ingress(struct __sk_buff *skb)
{
    return tc_probe(skb, true);
}

SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(kprobe_udp_sendmsg)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2(ctx);
    struct inet_sock *inet = (struct inet_sock *) sk;
    struct sockaddr_in *sin = READ_KERN(msg->msg_name);

    u16 dport;
    if (sin)
        dport = READ_KERN(sin->sin_port);
    else
        dport = READ_KERN(inet->inet_dport);    
    if (dport != 13568 && dport != 59668 && dport != 0)
        return 0;
    return dns_resolve(ctx, sk, msg);
}


// DNS-based packet drop
char LICENSE[] SEC("license") = "GPL";
