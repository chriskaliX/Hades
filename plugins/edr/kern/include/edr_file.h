// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Authors: chriskalix@protonmail.com
 */
#ifndef CORE
#else
    #include <vmlinux.h>
    #include <missing_definitions.h>
#endif

#include "define.h"
#include "utils.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"
#include "bpf_tracing.h"
#include "helpers.h"

#define EPERM 1

// FOR NOW, ONLY A DEMO TO PREVENT /etc/passwd
SEC("kprobe/openat")
int BPF_KPROBE(kprobe_openat)
{
    struct pt_regs *__ctx = (struct pt_regs *)PT_REGS_PARM1(ctx);
    char __user *filename;
    bpf_probe_read_kernel(&filename, sizeof(filename), &(PT_REGS_PARM2(__ctx)));
    char cache[256];
    bpf_probe_read_str(cache, sizeof(cache), filename);
    if (has_prefix("/etc/passwd", cache, 12)) {
        bpf_override_return(ctx, -EPERM);
        return 0;
    }

    return 0;
}