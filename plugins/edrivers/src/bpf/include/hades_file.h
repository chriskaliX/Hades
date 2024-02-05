// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Authors: chriskalix@protonmail.com
 */
#include "define.h"
#include "utils.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"
#include "bpf_tracing.h"

SEC("kprobe/security_inode_create")
int BPF_KPROBE(kprobe_security_inode_create)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;
    if (context_filter(&data.context))
        return 0;
    data.context.dt = SECURITY_INODE_CREATE;
    void *exe = get_exe_from_task(data.task);
    save_str_to_buf(&data, exe, 0);
    struct dentry *dentry = (struct dentry *)PT_REGS_PARM2(ctx);
    void *dentry_path = get_dentry_path_str(dentry);
    save_str_to_buf(&data, dentry_path, 1);
    get_socket_info(&data, 2);
    return events_perf_submit(&data);
}

SEC("kprobe/security_sb_mount")
int BPF_KPROBE(kprobe_security_sb_mount)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;
    if (context_filter(&data.context))
        return 0;
    data.context.dt = SECURITY_SB_MOUNT;
    const char *dev_name = (const char *)PT_REGS_PARM1(ctx);
    struct path *path = (struct path *)PT_REGS_PARM2(ctx);
    const char *type = (const char *)PT_REGS_PARM3(ctx);
    unsigned long flags = (unsigned long)PT_REGS_PARM4(ctx);
    void *path_str = get_path_str_simple(path);
    save_str_to_buf(&data, (void *)dev_name, 0);
    save_str_to_buf(&data, path_str, 1);
    save_str_to_buf(&data, (void *)type, 2);
    save_to_submit_buf(&data, &flags, sizeof(unsigned long), 3);
    void *exe = get_exe_from_task(data.task);
    save_str_to_buf(&data, exe, 4);
    save_pid_tree_to_buf(&data, 8, 5);
    return events_perf_submit(&data);
}

SEC("kprobe/security_inode_rename")
int BPF_KPROBE(kprobe_security_inode_rename)
{
        event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;
    if (context_filter(&data.context))
        return 0;
    data.context.dt = SECURITY_INODE_RENAME;
    
    struct dentry *from = (struct dentry *) PT_REGS_PARM2(ctx);
    struct dentry *to = (struct dentry *) PT_REGS_PARM4(ctx);

    void *from_ptr = get_dentry_path_str(from);
    if (from_ptr == NULL)
        return 0;
    save_str_to_buf(&data, from_ptr, 0);
    void *to_ptr = get_dentry_path_str(to);
    if (to_ptr == NULL)
        return 0;
    save_str_to_buf(&data, to_ptr, 1);
    return events_perf_submit(&data);
}

SEC("kprobe/security_inode_link")
int BPF_KPROBE(kprobe_security_inode_link)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;
    if (context_filter(&data.context))
        return 0;
    data.context.dt = SECURITY_INODE_LINK;
    
    struct dentry *from = (struct dentry *) PT_REGS_PARM1(ctx);
    struct dentry *to = (struct dentry *) PT_REGS_PARM3(ctx);

    void *from_ptr = get_dentry_path_str(from);
    if (from_ptr == NULL)
        return 0;
    save_str_to_buf(&data, from_ptr, 0);
    void *to_ptr = get_dentry_path_str(to);
    if (to_ptr == NULL)
        return 0;
    save_str_to_buf(&data, to_ptr, 1);
    return events_perf_submit(&data);
}
