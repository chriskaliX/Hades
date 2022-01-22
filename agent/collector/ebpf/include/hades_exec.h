#include <linux/sched.h>
#include <linux/binfmts.h>
#include <linux/kconfig.h>
#include <uapi/linux/ptrace.h>

#include "utils_buf.h"
#include "utils.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"
#include "bpf_tracing.h"

// TODO: Hook ID 的标准化, 看 format 里面
struct _sys_enter_execve
{
    __u64 unused;
    int syscall_nr;
    const char *filename;
    const char *const * argv;
    const char *const * envp;
};

struct _sys_enter_execveat
{
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

struct _sys_enter_kill
{
    __u64 unused;
    pid_t pid;
    int   sig;
};

struct _sys_exit_kill
{
    __u64 unused;
    long  ret;
};

struct _sys_enter_prctl
{
    __u64 unused;
    int option;
	unsigned long arg2;
	unsigned long arg3;
	unsigned long arg4;
	unsigned long arg5;
};

struct _sys_enter_ptrace
{
    long request;
	long pid;
	unsigned long addr;
	unsigned long data;
};

// TODO: raw_tracepoint
// 相比来说有一定的性能提升, 给出的 benchmark 里能看到有 5% 左右的性能提升(某个 hook)
// 但是对于性能来说, 还是尽可能的用 tracepoint, 看起来效率比 kprobe 更好
// @Reference: TRACEE - https://github.com/aquasecurity/tracee/pull/205
// @Reference: https://lwn.net/Articles/748352/
// @Prerequisties: kernel version > 4.17
// @Notes: 看起来对兼容性要做一定处理，在 tracee 中对于这些 hook 点的处理方式都是统一入口点，之后尾调具体处理函数

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
    // tty
    void *ttyname = get_task_tty_str(data.task);
    save_str_to_buf(&data, ttyname, 2);
    // stdin
    void *stdin = get_fraw_str(0);
    save_str_to_buf(&data, stdin, 3);
    // stdout
    void *stdout = get_fraw_str(1);
    save_str_to_buf(&data, stdout, 4);
    // socket
    get_socket_info(&data, 5);

    // 新增 pid_tree
    save_pid_tree_to_buf(&data, 8, 6);
    save_str_arr_to_buf(&data, (const char *const *)ctx->argv, 7);
    save_envp_to_buf(&data, (const char *const *)ctx->envp, 8);
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
    // tty
    void *ttyname = get_task_tty_str(data.task);
    save_str_to_buf(&data, ttyname, 2);
    // stdin
    void *stdin = get_fraw_str(0);
    save_str_to_buf(&data, stdin, 3);
    // stdout
    void *stdout = get_fraw_str(1);
    save_str_to_buf(&data, stdout, 4);
    // socket
    // TODO: Add socket to this
    get_socket_info(&data, 5);

    // 新增 pid_tree
    save_pid_tree_to_buf(&data, 8, 6);
    save_str_arr_to_buf(&data, (const char *const *)ctx->argv, 7);
    save_envp_to_buf(&data, (const char *const *)ctx->envp, 8);
    return events_perf_submit(&data);
}

/* exit hooks */
// 日志量很大...开启的必要性是...
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
    bpf_probe_read_str(&cache.pcomm, sizeof(cache.pcomm), &ctx->parent_comm);
    bpf_map_update_elem(&pid_cache_lru, &pid, &cache, BPF_ANY);
    return 0;
}
/* lsm bprm: unfinished - 看的tracee, 上次看了又忘记了... */
// https://blog.aquasec.com/ebpf-container-tracing-malware-detection
// 这个主要检测 dynamic code execution, 如果不捕获 payload, 是否能只做简单匹配
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
    buf_t *string_p = get_buf(STRING_BUF_IDX);
    if (string_p == NULL)
        return 0;
    // memfd 这个应该相当于 kprobe/memfd_create, 还有一个 shm_open https://x-c3ll.github.io/posts/fileless-memfd_create/ 可以绕过字节的 hook 吗? 字节的大佬说 execve 可以 hook
    // 对应的也就是 /dev/shm/ | /run/shm/
    // 这样 hook 考虑到性能问题, 需要看 datadog 下对这个的加速
    // TODO: optimize this function get_path_str
    if (has_prefix("memfd://", (char *)&string_p->buf[0], 9) || has_prefix("/dev/shm/", (char *)&string_p->buf[0], 10), has_prefix("/run/shm/", (char *)&string_p->buf[0], 10)) {
        save_str_to_buf(&data, file_path, 0);
        return events_perf_submit(&data);
    }
    return 0;
}

// @Kernel Source Code: CAP标志位 https://github.com/torvalds/linux/blob/7c636d4d20f8c5acfbfbc60f326fddb0e1cf5daa/include/uapi/linux/capability.h
// @Reference: https://blog.51cto.com/u_2559640/2365794
// @Notes: 可能有用的：CAP_SETGID/CAP_SETUID/CAP_SYS_MODULE/CAP_SYS_PTRACE/CAP_BPF
// Prctl(CAP)/Ptrace(SYS_ENTER) 操作/注入进程
SEC("tracepoint/syscalls/sys_enter_prctl")
int sys_enter_prctl(struct _sys_enter_prctl *ctx)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;
    data.context.type = 6;
    // 读 option, 类型?
    save_to_submit_buf(&data, &ctx->option, sizeof(int), 0);
    char *name = NULL;
    save_to_submit_buf(&data, &ctx->arg2, sizeof(unsigned long), 1);
    save_str_to_buf(&data, name, 1);
    events_perf_submit(&data);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_ptrace")
int sys_enter_ptrace(struct _sys_enter_ptrace *ctx)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;
    data.context.type = 7;
    long request;
    // 仅抓取两种 request 位
    bpf_probe_read(&request, sizeof(request), &ctx->request);
    if (request != PTRACE_POKETEXT && request != PTRACE_POKEDATA)
        return 0;
    save_to_submit_buf(&data, &ctx->request, sizeof(long), 0);
    save_to_submit_buf(&data, &ctx->pid, sizeof(long), 1);
    save_to_submit_buf(&data, &ctx->addr, sizeof(unsigned long), 2);
    save_to_submit_buf(&data, &ctx->data, sizeof(unsigned long), 3);
    events_perf_submit(&data);
    return 0;
}

// TODO: ptrace 的 hook, kprobe 直接挂载或者 CAP_CAPABLE, 明天开始 check 一下
/* kill/tkill/tgkill */
SEC("tracepoint/syscalls/sys_enter_kill")
int sys_enter_kill(struct _sys_enter_kill *ctx)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;
    data.context.type = 8;
    save_to_submit_buf(&data, &ctx->pid, sizeof(u32), 0);
    save_to_submit_buf(&data, &ctx->sig, sizeof(int), 1);
    return 0;
}