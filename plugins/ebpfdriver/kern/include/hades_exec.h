// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Authors: chriskalix@protonmail.com
 */
#ifndef CORE
#include <linux/binfmts.h>
#include <linux/kconfig.h>
#include <linux/prctl.h>
#include <linux/sched.h>
#include <uapi/linux/ptrace.h>
#else
#include <vmlinux.h>
#include <missing_definitions.h>
#endif

#include "bpf_core_read.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "define.h"
#include "utils.h"
#include "utils_buf.h"

/*
 * In tracee, they do not capture the args since the pointer...
 * Reference:
 * https://lists.iovisor.org/g/iovisor-dev/topic/how_to_get_function_param_in/76044869?p=
 * Also, for compatibility, the fexit/entry is not used since it's only
 * supported for kernel >= 5.5
 * The only option is to read and store the values in kprobe
 *
 * Internal functions for cache
 *
 * Note: syscall is non-reentrant during it's lifetime. The kernel thread is
 * not changed until the function return. So we save(cache) the argv and envp
 * from the entry and get it out from the exit, since the original pointer is
 * useless in exit.
 *
 * raw_tracepoint should be considered since it's perform better than
 * tracepoint and kprobe. References are here:
 * https://github.com/aquasecurity/tracee/pull/205
 * https://lwn.net/Articles/748352/
 *
 * Also, fields like stdin/stdout are not same as Elkeid. Need check
 * for this.
 *
 * issue #34: the filename from ctx is not the execute path we
 * expected. We need to get the right execute path from kretprobe or
 * sys_exit_execve in task_struct->mm
 *
 * Also, in tracee, they said that the argv/envp pointers are invalid
 * in both entry and exit, be careful if we change the hook to raw_
 * tracepoint.
 */

SEC("tracepoint/syscalls/sys_enter_execve")
int sys_enter_execve(struct syscall_enter_args *ctx)
{
    __u64 id = bpf_get_current_pid_tgid();
    struct syscall_buffer *buf = reset_syscall_buffer_cache(id);
    if (!buf)
        return 0;
    save_args_into_buffer(buf, (void *)ctx->args[1]);
    save_envp_into_buffer(buf, (void *)ctx->args[2]);
    return 1;
}

SEC("tracepoint/syscalls/sys_exit_execve")
int sys_exit_execve(void *ctx)
{
    // here, we remove to head, judge get buf is correct！
    __u64 id = bpf_get_current_pid_tgid();
    struct syscall_buffer *buf = get_syscall_buffer_cache(id);
    if (buf == NULL)
        return 0;

    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        goto delete;
    if (context_filter(&data.context))
        goto delete;
    data.context.type = SYS_ENTER_EXECVE;
    /* filename
   * The filename contains dot slash thing. It's not abs path,
   * but the args[0] of execve(at)
   * like Elkeid, we should get this in kretprobe/exit from
   * the get_exe_from_task function. (current->mm->exe_file->f_path)
   * and it's safe to access path in it's own context
   */
    void *exe = get_exe_from_task(data.task);
    save_str_to_buf(&data, exe, 0);
    // cwd
    struct fs_struct *file = get_task_fs(data.task);
    if (file == NULL)
        goto delete;
    void *file_path = get_path_str(GET_FIELD_ADDR(file->pwd));
    save_str_to_buf(&data, file_path, 1);
    void *ttyname = get_task_tty_str(data.task);
    save_str_to_buf(&data, ttyname, 2);
    void *stdin = get_fraw_str(0);
    save_str_to_buf(&data, stdin, 3);
    void *stdout = get_fraw_str(1);
    save_str_to_buf(&data, stdout, 4);
    __u32 socket_pid = get_socket_info(&data, 5);
    // save socket_pid
    // 0 means error, we'll handle that in user space
    save_to_submit_buf(&data, &socket_pid, sizeof(socket_pid), 6);
    // pid_tree
    save_pid_tree_to_buf(&data, 8, 7);
    // save argv
    int argv_ret = save_argv_to_buf(&data, buf, 8);
    if (argv_ret == 0)
        goto delete;
    // save envp
    int envp_ret = save_envp_to_buf(&data, buf, 9);
    if (envp_ret == 0) {
        goto delete;
    }

    delete_syscall_buffer_cache(id);
    return events_perf_submit(&data);
    delete : delete_syscall_buffer_cache(id);
    return 0;
}

/*
 * In execveat, an empty argv or envp is always possible
 */
SEC("tracepoint/syscalls/sys_enter_execveat")
int sys_enter_execveat(struct syscall_enter_args *ctx)
{
    __u64 id = bpf_get_current_pid_tgid();
    struct syscall_buffer *buf = reset_syscall_buffer_cache(id);
    if (!buf)
        return 0;
    save_args_into_buffer(buf, (void *)ctx->args[2]);
    save_envp_into_buffer(buf, (void *)ctx->args[3]);
    return 1;
}

SEC("tracepoint/syscalls/sys_exit_execveat")
int sys_exit_execveat(void *ctx)
{
    // here, we remove to head, judge get buf is correct！
    __u64 id = bpf_get_current_pid_tgid();
    struct syscall_buffer *buf = get_syscall_buffer_cache(id);
    if (buf == NULL)
        return 0;

    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        goto delete;
    if (context_filter(&data.context))
        goto delete;
    data.context.type = SYS_ENTER_EXECVEAT;
    /* filename
   * The filename contains dot slash thing. It's not abs path,
   * but the args[0] of execve(at)
   * like Elkeid, we should get this in kretprobe/exit from
   * the get_exe_from_task function. (current->mm->exe_file->f_path)
   * and it's safe to access path in it's own context
   */
    void *exe = get_exe_from_task(data.task);
    save_str_to_buf(&data, exe, 0);
    // cwd
    struct fs_struct *file = get_task_fs(data.task);
    if (file == NULL)
        goto delete;
    void *file_path = get_path_str(GET_FIELD_ADDR(file->pwd));
    save_str_to_buf(&data, file_path, 1);
    void *ttyname = get_task_tty_str(data.task);
    save_str_to_buf(&data, ttyname, 2);
    void *stdin = get_fraw_str(0);
    save_str_to_buf(&data, stdin, 3);
    void *stdout = get_fraw_str(1);
    save_str_to_buf(&data, stdout, 4);
    __u32 socket_pid = get_socket_info(&data, 5);
    // save socket_pid
    // 0 means error, we'll handle that in user space
    save_to_submit_buf(&data, &socket_pid, sizeof(socket_pid), 6);
    // pid_tree
    save_pid_tree_to_buf(&data, 8, 7);
    // save argv
    int argv_ret = save_argv_to_buf(&data, buf, 8);
    if (argv_ret == 0)
        goto delete;
    // save envp
    int envp_ret = save_envp_to_buf(&data, buf, 9);
    if (envp_ret == 0) {
        goto delete;
    }

    delete_syscall_buffer_cache(id);
    return events_perf_submit(&data);
    delete : delete_syscall_buffer_cache(id);
    return 0;
}

struct _sys_enter_prctl {
    unsigned long long unused;
    long syscall_nr;
    int option;
    unsigned long arg2;
    unsigned long arg3;
    unsigned long arg4;
    unsigned long arg5;
};
/*
 * Prctl(CAP)/Ptrace(SYS_ENTER) inject process
 * In Elkeid, only PR_SET_NAME is collected, in function "prctl_pre_handler".
 * using PR_SET_NAME to set name for a process or thread. prctl is the
 * function that we use for change(get) the attribute of threads. But there
 * are too many options for this function. Some references:
 *
 * http://www.leveryd.top/2021-12-26-%E5%A6%82%E4%BD%95%E4%BC%AA%E8%A3%85%E8%BF%9B%E7%A8%8B%E4%BF%A1%E6%81%AF/
 * https://stackoverflow.com/questions/57749629/manipulating-process-name-and-arguments-by-way-of-argv
 * https://www.blackhat.com/docs/us-16/materials/us-16-Leibowitz-Horse-Pill-A-New-Type-Of-Linux-Rootkit.pdf
 */
SEC("tracepoint/syscalls/sys_enter_prctl")
int sys_enter_prctl(struct syscall_enter_args *ctx)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;
    if (context_filter(&data.context))
        return 0;
    data.context.type = SYS_ENTER_PRCTL;

    int option;
    char *newname = NULL;
    unsigned long flag2;

    bpf_probe_read(&option, sizeof(option), &ctx->args[0]);
    if (option != PR_SET_NAME && option != PR_SET_MM)
        return 0;
    save_to_submit_buf(&data, &option, sizeof(int), 0);

    void *exe = get_exe_from_task(data.task);
    save_str_to_buf(&data, exe, 1);

    switch (option) {
    case PR_SET_NAME:
        bpf_probe_read_user_str(&newname, TASK_COMM_LEN, (char *)ctx->args[1]);
        save_str_to_buf(&data, &newname, 2);
        break;
    /*
     * Some reference:
     * https://man7.org/linux/man-pages/man2/prctl.2.html
     * https://cloud.tencent.com/developer/article/1040079
     */
    case PR_SET_MM:
        bpf_probe_read_user(&flag2, sizeof(flag2), &ctx->args[1]);
        save_to_submit_buf(&data, &flag2, sizeof(unsigned long), 2);
        break;
    default:
        break;
    }
    return events_perf_submit(&data);
}

// @Reference:
// https://www.giac.org/paper/gcih/467/tracing-ptrace-case-study-internal-root-compromise-incident-handling/105271
// @Reference:
// https://driverxdw.github.io/2020/07/06/Linux-ptrace-so%E5%BA%93%E6%B3%A8%E5%85%A5%E5%88%86%E6%9E%90/
SEC("tracepoint/syscalls/sys_enter_ptrace")
int sys_enter_ptrace(struct syscall_enter_args *ctx)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;
    if (context_filter(&data.context))
        return 0;
    data.context.type = SYS_ENTER_PTRACE;
    long request;
    bpf_probe_read(&request, sizeof(request), &ctx->args[0]);
    if (request != PTRACE_POKETEXT && request != PTRACE_POKEDATA)
        return 0;

    void *exe = get_exe_from_task(data.task);
    save_str_to_buf(&data, exe, 0);
    save_to_submit_buf(&data, &request, sizeof(long), 1);
    save_to_submit_buf(&data, &ctx->args[1], sizeof(long), 2);
    save_to_submit_buf(&data, &ctx->args[2], sizeof(unsigned long), 3);
    save_pid_tree_to_buf(&data, 12, 4);
    return events_perf_submit(&data);
}

struct _sys_enter_memfd_create {
    unsigned long long unused;
    long syscall_nr;
    const char *uname;
    unsigned int flags;
};

// https://xeldax.top/article/linux_no_file_elf_mem_execute
SEC("tracepoint/syscalls/sys_enter_memfd_create")
int sys_enter_memfd_create(struct syscall_enter_args *ctx)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;
    if (context_filter(&data.context))
        return 0;
    data.context.type = SYS_ENTER_MEMFD_CREATE;
    void *exe = get_exe_from_task(data.task);
    save_str_to_buf(&data, exe, 0);
    save_str_to_buf(&data, (char *)ctx->args[0], 1);
    save_to_submit_buf(&data, &ctx->args[1], sizeof(unsigned int), 2);
    return events_perf_submit(&data);
}
