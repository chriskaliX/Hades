// SPDX-License-Identifier: GPL-2.0-or-later

#ifndef __PROBES_PROCESS_ROOTKIT_H__
#define __PROBES_PROCESS_ROOTKIT_H__

#include <vmlinux.h>
#include <missing_definitions.h>
#include "runtime/constants.h"
#include "runtime/task_helpers.h"
#include "runtime/maps.h"
#include "bpf_core_read.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"

SEC("kprobe/do_init_module")
int BPF_KPROBE(kprobe_do_init_module)
{
    struct module *mod = (struct module *)PT_REGS_PARM1(ctx);
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task)
        return 0;

    buf_t *cache = get_percpu_buf(LOCAL_CACHE);
    if (!cache)
        return 0;
    if (mod)
        bpf_probe_read_str(&cache->buf[0], 64, &mod->name);

    struct path exe = BPF_CORE_READ(task, mm, exe_file, f_path);
    void *exe_path = get_path(__builtin_preserve_access_index(&exe));

    struct hds_context event_ctx = init_context(ctx, DO_INIT_MODULE);
    EVT_SUBMIT(&event_ctx,
        &event_ctx.data_type,
        &cache->buf[0],
        exe_path);
    return report_event(&event_ctx);
}

SEC("kprobe/security_kernel_read_file")
int BPF_KPROBE(kprobe_security_kernel_read_file)
{
    struct file *file = (struct file *)PT_REGS_PARM1(ctx);
    int type_id = (int)PT_REGS_PARM2(ctx);
    if (!file)
        return 0;

    struct path fpath = BPF_CORE_READ(file, f_path);
    void *path = get_path(__builtin_preserve_access_index(&fpath));

    struct hds_context event_ctx = init_context(ctx, SECURITY_KERNEL_READ_FILE);
    EVT_SUBMIT(&event_ctx,
        &event_ctx.data_type,
        &type_id,
        path);
    return report_event(&event_ctx);
}

SEC("kprobe/call_usermodehelper")
int BPF_KPROBE(kprobe_call_usermodehelper)
{
    const char *path = (const char *)PT_REGS_PARM1(ctx);
    const char *const *argv = (const char *const *)PT_REGS_PARM2(ctx);
    int wait = (int)PT_REGS_PARM4(ctx);

    const char *argv0 = NULL;
    if (argv)
        bpf_probe_read(&argv0, sizeof(argv0), argv);

    struct hds_context event_ctx = init_context(ctx, CALL_USERMODEHELPER);
    EVT_SUBMIT(&event_ctx,
        &event_ctx.data_type,
        path,
        argv0,
        &wait);
    return report_event(&event_ctx);
}

SEC("kprobe/security_file_permission")
int BPF_KPROBE(kprobe_security_file_permission)
{
    struct file *file = (struct file *)PT_REGS_PARM1(ctx);
    int mask = (int)PT_REGS_PARM2(ctx);
    if (!file)
        return 0;

    struct path fpath = BPF_CORE_READ(file, f_path);
    void *path = get_path(__builtin_preserve_access_index(&fpath));

    struct hds_context event_ctx = init_context(ctx, ANTI_RKT_FOPS);
    EVT_SUBMIT(&event_ctx,
        &event_ctx.data_type,
        &mask,
        path);
    return report_event(&event_ctx);
}

/*
 * Anti-rootkit uprobe hooks — triggered from Rust userspace scanner.
 *
 * Rust uses the standard System V AMD64 (C) ABI, so arguments land in the
 * normal parameter registers (rdi/rsi/rdx on x86-64, x0/x1/x2 on arm64),
 * which is exactly what PT_REGS_PARM1/2/3 abstract.  This is the opposite
 * of Go 1.17+ which puts arg1 in AX, arg2 in BX, arg3 in CX on x86-64.
 *
 * Rust trigger prototypes (in src/scanner.rs):
 *   extern "C" fn trigger_sct_scan(table: *const u64, index: u64)
 *   extern "C" fn trigger_module_scan(index: u64, name: *const c_char)
 */

/*
 * Syscall-table scan:  Rust passes (sys_call_table_kaddr, entry_index).
 * BPF reads table[index] and submits (index, addr) for userspace analysis.
 */
SEC("uprobe/trigger_sct_scan")
int trigger_sct_scan(struct pt_regs *ctx)
{
    unsigned long *address = (unsigned long *)PT_REGS_PARM1(ctx);
    __u64 index = (__u64)PT_REGS_PARM2(ctx);
    if (!address)
        return 0;

    __u64 addr = 0;
    bpf_probe_read(&addr, sizeof(addr), &address[index]);
    if (!addr)
        return 0;

    struct hds_context event_ctx = init_context(ctx, ANTI_RKT_SCT);
    EVT_SUBMIT(&event_ctx,
        &event_ctx.data_type,
        &index,
        &addr);
    return report_event(&event_ctx);
}

/*
 * Kernel-module scan:  Rust passes (module_index, module_name_cstr).
 * BPF records the name for comparison against /proc/modules from userspace.
 */
SEC("uprobe/trigger_module_scan")
int trigger_module_scan(struct pt_regs *ctx)
{
    __u64 index = (__u64)PT_REGS_PARM1(ctx);
    char *name = (char *)PT_REGS_PARM2(ctx);
    if (!name)
        return 0;

    struct hds_context event_ctx = init_context(ctx, ANTI_RKT_MODULE);
    EVT_SUBMIT(&event_ctx,
        &event_ctx.data_type,
        &index,
        name);
    return report_event(&event_ctx);
}

#endif