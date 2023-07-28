// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2023 chriskali
#include "../../../libs/core/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "tc.h"
// #include "xdp.h"

// Egress-based packet drop
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
