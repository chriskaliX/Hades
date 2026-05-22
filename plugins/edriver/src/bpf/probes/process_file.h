// SPDX-License-Identifier: GPL-2.0-or-later

#ifndef __PROBES_PROCESS_FILE_H__
#define __PROBES_PROCESS_FILE_H__

#include <vmlinux.h>
#include <missing_definitions.h>
#include "runtime/constants.h"
#include "runtime/task_helpers.h"
#include "runtime/maps.h"
#include "bpf_core_read.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"

static __always_inline void *file_dentry_name(struct dentry *dentry)
{
    buf_t *cache = get_percpu_buf(LOCAL_CACHE);
    if (!cache || !dentry)
        return NULL;
    struct qstr q = BPF_CORE_READ(dentry, d_name);
    if (!q.name)
        return NULL;
    if (bpf_probe_read_str(&cache->buf[0], MAX_STRING_SIZE, q.name) <= 0)
        return NULL;
    return &cache->buf[0];
}

static __always_inline int file_emit_common(void *ctx, __u32 dt, void *p0, void *p1, void *p2)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task)
        return 0;

    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)id;
    __u32 tgid = (__u32)(id >> 32);
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));

    struct path exe = BPF_CORE_READ(task, mm, exe_file, f_path);
    void *exe_path = get_path(__builtin_preserve_access_index(&exe));

    struct hds_context event_ctx = init_context(ctx, dt);
    EVT_SUBMIT(&event_ctx,
        &event_ctx.data_type,
        &pid,
        &tgid,
        &comm,
        exe_path,
        p0,
        p1,
        p2);
    return report_event(&event_ctx);
}

SEC("kprobe/security_inode_create")
int BPF_KPROBE(kprobe_security_inode_create)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task)
        return 0;

    __u16 family = 0;
    struct hds_socket_info sinfo = {};
    pid_t socket_pid = 0;
    struct sock *sk = proc_socket_info(task, &socket_pid);
    if (sk) {
        family = BPF_CORE_READ(sk, sk_family);
        if (family == AF_INET)
            get_sock_v4(sk, &sinfo);
    }

    struct dentry *dentry = (struct dentry *)PT_REGS_PARM2(ctx);
    void *name = file_dentry_name(dentry);
    return file_emit_common(ctx, SECURITY_INODE_CREATE, name, &family, &sinfo);
}

SEC("kprobe/security_sb_mount")
int BPF_KPROBE(kprobe_security_sb_mount)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task)
        return 0;

    const char *dev_name = (const char *)PT_REGS_PARM1(ctx);
    struct path *path = (struct path *)PT_REGS_PARM2(ctx);
    const char *type = (const char *)PT_REGS_PARM3(ctx);
    unsigned long flags = (unsigned long)PT_REGS_PARM4(ctx);

    void *path_str = get_path(path);
    struct path exe = BPF_CORE_READ(task, mm, exe_file, f_path);
    void *exe_path = get_path(__builtin_preserve_access_index(&exe));

    __u32 tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    struct proc_info *pinfo = NULL;
    bpf_map_update_elem(&proc_info_cache, &tgid, &_proc, BPF_ANY);
    pinfo = bpf_map_lookup_elem(&proc_info_cache, &tgid);
    if (pinfo)
        proc_pid_tree(pinfo, task);

    struct hds_context event_ctx = init_context(ctx, SECURITY_SB_MOUNT);
    EVT_SUBMIT(&event_ctx,
        &event_ctx.data_type,
        dev_name,
        path_str,
        type,
        &flags,
        exe_path,
        pinfo ? pinfo->pidtree : NULL);
    return report_event(&event_ctx);
}

SEC("kprobe/security_inode_rename")
int BPF_KPROBE(kprobe_security_inode_rename)
{
    struct dentry *from = (struct dentry *)PT_REGS_PARM2(ctx);
    struct dentry *to = (struct dentry *)PT_REGS_PARM4(ctx);
    void *from_name = file_dentry_name(from);
    void *to_name = file_dentry_name(to);
    return file_emit_common(ctx, SECURITY_INODE_RENAME, from_name, to_name, NULL);
}

SEC("kprobe/security_inode_link")
int BPF_KPROBE(kprobe_security_inode_link)
{
    struct dentry *from = (struct dentry *)PT_REGS_PARM1(ctx);
    struct dentry *to = (struct dentry *)PT_REGS_PARM3(ctx);
    void *from_name = file_dentry_name(from);
    void *to_name = file_dentry_name(to);
    return file_emit_common(ctx, SECURITY_INODE_LINK, from_name, to_name, NULL);
}

#endif