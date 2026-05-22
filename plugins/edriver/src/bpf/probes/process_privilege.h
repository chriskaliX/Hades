// SPDX-License-Identifier: GPL-2.0-or-later

#ifndef __PROBES_PROCESS_PRIVILEGE_H__
#define __PROBES_PROCESS_PRIVILEGE_H__

#include <vmlinux.h>
#include <missing_definitions.h>
#include "runtime/constants.h"
#include "runtime/task_helpers.h"
#include "runtime/maps.h"
#include "bpf_core_read.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"

SEC("kprobe/commit_creds")
int BPF_KPROBE(kprobe_commit_creds)
{
    struct cred *new = (struct cred *)PT_REGS_PARM1(ctx);
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task || !new)
        return 0;

    struct cred *old = (struct cred *)BPF_CORE_READ(task, real_cred);
    if (!old)
        return 0;

    __u32 old_uid = BPF_CORE_READ(old, uid.val);
    __u32 new_uid = BPF_CORE_READ(new, uid.val);
    if (!(new_uid == 0 && old_uid != 0))
        return 0;

    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)id;
    __u32 tgid = (__u32)(id >> 32);
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));

    struct path exe = BPF_CORE_READ(task, mm, exe_file, f_path);
    void *exe_path = get_path(__builtin_preserve_access_index(&exe));
    __u32 cache_key = tgid;
    struct proc_info *pinfo = NULL;
    bpf_map_update_elem(&proc_info_cache, &cache_key, &_proc, BPF_ANY);
    pinfo = bpf_map_lookup_elem(&proc_info_cache, &cache_key);
    if (pinfo)
        proc_pid_tree(pinfo, task);

    struct hds_context event_ctx = init_context(ctx, COMMIT_CREDS);
    EVT_SUBMIT(&event_ctx,
        &event_ctx.data_type,
        &pid,
        &tgid,
        &comm,
        &old_uid,
        &new_uid,
        exe_path,
        pinfo ? pinfo->pidtree : NULL);
    return report_event(&event_ctx);
}

#endif