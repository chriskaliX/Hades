#include <linux/sched.h>
#include <linux/binfmts.h>
#include <linux/kconfig.h>

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

struct _tracepoint_sched_process_fork
{
    __u64 unused;
    char parent_comm[16];
    pid_t parent_pid;
    char child_comm[16];
    pid_t child_pid;
};

/* execve hooks */
// TODO: filter to pid, file_path, swicher in kernel space!
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
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = pid_tgid >> 32;
    u32 pid = pid_tgid;
    //TODO: figure - 线程退出
    if (tgid != pid) {
        return 0;
    }

    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;
    data.context.type = 3;
    long code = PT_REGS_PARM1(ctx);
    data.context.retval = code;
    return events_perf_submit(&data);
}

SEC("kprobe/sys_exit_group")
int kprobe_sys_exit_group(struct pt_regs *ctx)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;
    data.context.type = 4;
    long code = PT_REGS_PARM2(ctx);
    data.context.retval = code;
    return events_perf_submit(&data);
}

/* fork : nothing but just record the command line */
SEC("tracepoint/sched/sched_process_fork")
int tracepoint_sched_process_fork(struct _tracepoint_sched_process_fork *ctx)
{
    u32 pid = 0;
    u32 ppid = 0;
    bpf_probe_read(&pid, sizeof(pid), &ctx->child_pid);
    bpf_probe_read(&ppid, sizeof(ppid), &ctx->parent_pid);
    struct pid_cache_t cache = {};
    cache.ppid = ppid;
    bpf_probe_read(&cache.pcomm, sizeof(cache.pcomm), &ctx->parent_comm);
    bpf_map_update_elem(&pid_cache_lru, &pid, &cache, BPF_ANY);
    return 0;
}


/* lsm bprm: unfinished - 看的tracee, 上次看了又忘记了... */
SEC("kprobe/security_bprm_check")
int kprobe_security_bprm_check(struct pt_regs *ctx)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;
    data.context.type = 5;
    struct linux_binprm *bprm = (struct linux_binprm *)PT_REGS_PARM1(ctx);
    struct file *file = READ_KERN(bprm->file);
    void *file_path = get_path_str(GET_FIELD_ADDR(file->f_path));
    // 这里 tracee 和 datadog 的做法不一样, datadog 的执行都会放到一个 LRU 里面, 做存储, 来做跨 programs 的传输
    // 但是 security_bprm_check 的 hook 原因是啥呢? 看着 tracee 下的应该是对内存执行的监控, 这种是跳过 execve 的, 所以从上下文的 LRU 里取不到就 return (datadog 做法), 可能是没有意义的
    // 当然衍生出另外一个问题, 这个 hook 会导致 execve 下的数量翻倍, 同一个链路下的, 考虑在内核态做过滤
    // TODO: 场景探究 & 内核过滤必要性
    save_str_to_buf(&data, file_path, 0);
    return events_perf_submit(&data);
}