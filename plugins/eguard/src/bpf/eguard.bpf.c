// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2023 chriskali
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "events/tc.h"
#include "events/dns.h"

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

// DNS-based packet drop
char LICENSE[] SEC("license") = "GPL";
