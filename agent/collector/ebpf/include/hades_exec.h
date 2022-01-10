#include <linux/sched.h>

#include "common.h"
#include "utils.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"
#include "bpf_tracing.h"

struct _sys_enter_execve {
    __u64 unused;
    int syscall_nr;
    const char *filename;
    const char *const * argv;
    const char *const * envp;
};

struct _sys_enter_execveat {
    __u64 unused;
    int syscall_nr;
    const char *filename;
    const char *const * argv;
    const char *const * envp;
    int flags;
};

/* execve hooks */
// TODO: filter to pid, file_path in kernel
SEC("tracepoint/syscalls/sys_enter_execve")
int sys_enter_execve(struct _sys_enter_execve *ctx)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;
    data.context.type = 1;
    // filename
    save_str_to_buf(&data, (void *)ctx->filename, 0);
    // cwd
    struct fs_struct *file;
    bpf_probe_read(&file, sizeof(file), &data.task->fs);
    void *file_path = get_path_str(GET_FIELD_ADDR(file->pwd));
    save_str_to_buf(&data, file_path, 1);
    // 新增 pid_tree
    save_pid_tree_new_to_buf(&data, 8, 2);
    save_str_arr_to_buf(&data, (const char *const *)ctx->argv, 3);
    save_envp_to_buf(&data, (const char *const *)ctx->envp, 4);
    return events_perf_submit(&data);
}

SEC("tracepoint/syscalls/sys_enter_execveat")
int sys_enter_execveat(struct _sys_enter_execveat *ctx)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;
    data.context.type = 2;
    // filename
    save_str_to_buf(&data, (void *)ctx->filename, 0);
    // cwd
    struct fs_struct *file;
    bpf_probe_read(&file, sizeof(file), &data.task->fs);
    void *file_path = get_path_str(GET_FIELD_ADDR(file->pwd));
    save_str_to_buf(&data, file_path, 1);
    // 新增 pid_tree
    save_pid_tree_new_to_buf(&data, 8, 2);
    save_str_arr_to_buf(&data, (const char *const *)ctx->argv, 3);
    save_envp_to_buf(&data, (const char *const *)ctx->envp, 4);
    return events_perf_submit(&data);
}

/* exit hooks */
// reference of exit & exit_group: https://stackoverflow.com/questions/27154256/what-is-the-difference-between-exit-and-exit-group
SEC("kprobe/do_exit")
int kprobe_do_exit(struct pt_regs *ctx)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;
    data.context.type = 3;
    long code = PT_REGS_PARM1(ctx);
    data.context.retval = code;
    return events_perf_submit(&data);
}