#include "utils.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"
#include "bpf_tracing.h"

// ltp tested
SEC("kprobe/security_inode_create")
int kprobe_security_inode_create(struct pt_regs *ctx)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;
    data.context.type = SECURITY_INODE_CREATE;
    void *exe = get_exe_from_task(data.task);
    save_str_to_buf(&data, exe, 0);
    struct dentry *dentry = (struct dentry *)PT_REGS_PARM2(ctx);
    void *dentry_path = get_dentry_path_str(dentry);
    save_str_to_buf(&data, dentry_path, 1);
    get_socket_info(&data, 2);
    return events_perf_submit(&data);
}

// ltp tested
SEC("kprobe/security_sb_mount")
int kprobe_security_sb_mount(struct pt_regs *ctx)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;
    data.context.type = SECURITY_SB_MOUNT;
    const char *dev_name = (const char *)PT_REGS_PARM1(ctx);
    struct path *path = (struct path *)PT_REGS_PARM2(ctx);
    const char *type = (const char *)PT_REGS_PARM3(ctx);
    unsigned long flags = (unsigned long)PT_REGS_PARM4(ctx);
    void *path_str = get_path_str(path);
    save_str_to_buf(&data, (void *)dev_name, 0);
    save_str_to_buf(&data, path_str, 1);
    save_str_to_buf(&data, (void *)type, 2);
    save_to_submit_buf(&data, &flags, sizeof(unsigned long), 3);
    void *exe = get_exe_from_task(data.task);
    save_str_to_buf(&data, exe, 4);
    save_pid_tree_to_buf(&data, 8, 5);
    return events_perf_submit(&data);
}
