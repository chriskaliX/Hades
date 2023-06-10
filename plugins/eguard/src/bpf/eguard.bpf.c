// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2023 chriskali
#include "../../../libs/core/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "egress.h"

// Egress-based packet drop
SEC("tc")
int hades_egress(struct __sk_buff *skb)
{
    return tc_probe(skb, false);
}

// DNS-based packet drop
char LICENSE[] SEC("license") = "GPL";
