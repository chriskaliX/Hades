// SPDX-License-Identifier: GPL-2.0-or-later

#ifndef __PROBES_PROCESS_UPROBE_H__
#define __PROBES_PROCESS_UPROBE_H__

#include <vmlinux.h>
#include <missing_definitions.h>
#include "runtime/constants.h"
#include "runtime/task_helpers.h"
#include "runtime/maps.h"
#include "bpf_core_read.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"

SEC("uretprobe/bash_readline")
int uretprobe_bash_readline(struct pt_regs *ctx)
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

    void *line = (void *)PT_REGS_RC(ctx);
    void *tty_path = get_task_tty(task);
    struct path pwd = BPF_CORE_READ(task, fs, pwd);
    void *pwd_path = get_path(__builtin_preserve_access_index(&pwd));
    /* skip stdin/stdout fd lookup (get_fd→get_path would create 3-deep call chain
     * triggering BPF verifier EAGAIN on 5.15 WSL2 kernel) */
    void *stdin_path = NULL;
    void *stdout_path = NULL;

    __u16 family = 0;
    struct hds_socket_info sinfo = {};
    pid_t socket_pid = 0;
    struct sock *sk = proc_socket_info(task, &socket_pid);
    if (sk) {
        family = BPF_CORE_READ(sk, sk_family);
        if (family == AF_INET)
            get_sock_v4(sk, &sinfo);
    }

    /* reuse pidtree already populated by process_exec — avoids expensive recomputation */
    __u32 cache_key = tgid;
    struct proc_info *pinfo = bpf_map_lookup_elem(&proc_info_cache, &cache_key);

    struct hds_context event_ctx = init_context(ctx, BASH_READLINE);
    EVT_SUBMIT(&event_ctx,
        &event_ctx.data_type,
        &pid,
        &tgid,
        &comm,
        exe_path,
        line,
        tty_path,
        stdin_path,
        stdout_path,
        &family,
        &sinfo,
        pinfo ? pinfo->pidtree : NULL,
        pwd_path);
    return report_event(&event_ctx);
}

#endif