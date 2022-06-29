// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Authors: chriskalix@protonmail.com
 */
#ifndef CORE
#include <linux/sched.h>
#include <linux/binfmts.h>
#include <linux/kconfig.h>
#include <linux/prctl.h>
#include <uapi/linux/ptrace.h>
#else
#include <vmlinux.h>
#include <missing_definitions.h>
#endif

#include "define.h"
#include "utils_buf.h"
#include "utils.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"
#include "bpf_tracing.h"

struct _sys_enter_execve
{
    unsigned long long unused;
    long syscall_nr;
    const char *filename;
    const char *const *argv;
    const char *const *envp;
};

struct _sys_enter_execveat
{
    unsigned long long unused;
    long syscall_nr;
    int fd;
    const char *filename;
    const char *const *argv;
    const char *const *envp;
    int flags;
};

/*
 * In tracee, they do not capture the args since the pointer...
 * Reference: https://lists.iovisor.org/g/iovisor-dev/topic/how_to_get_function_param_in/76044869?p=
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
 */
BPF_PERCPU_ARRAY(execve_argv_array, buf_t, 4);
BPF_PERCPU_ARRAY(execve_envp_array, buf_t, 4);
BPF_PERCPU_HASH(execve_argv_hash, 4);
BPF_PERCPU_HASH(execve_envp_hash, 4);

#define MAX_ARRAY_COUNT 8192
#define _TYPE_ARGV 0
#define _TYPE_ENVP 1
#define _EXECVE_INDEX 0
#define _EXECVEAT_INDEX 1

static __always_inline int store_execve_data(const char *const *argv_p, const char *const *envp_p, int index)
{
    // argv
    buf_t *argv = (buf_t *)bpf_map_lookup_elem(&execve_argv_array, &index);
    int argv_size = save_argv_to_buf_t(argv, argv_p);
    bpf_map_update_elem(&execve_argv_hash, &index, &argv_size, BPF_ANY);
    // envp
    buf_t *envp = (buf_t *)bpf_map_lookup_elem(&execve_envp_array, &index);
    int envp_size = save_envp_to_buf_t(envp, envp_p);
    bpf_map_update_elem(&execve_envp_hash, &index, &envp_size, BPF_ANY);
    return 1;
};

static __always_inline int save_array_to_buf(event_data_t *data, int buf_index, int type_index, int index)
{
    /* save argv */
    buf_t *buffer = NULL;
    int *size = NULL;
    if (buf_index == _TYPE_ARGV)
    {
        buffer = (buf_t *)bpf_map_lookup_elem(&execve_argv_array, &type_index);
        size = (int *)bpf_map_lookup_elem(&execve_argv_hash, &type_index);
    }
    else
    {
        buffer = (buf_t *)bpf_map_lookup_elem(&execve_envp_array, &type_index);
        size = (int *)bpf_map_lookup_elem(&execve_envp_hash, &type_index);
    }
    // pre vaildate
    if (buffer == NULL || size == NULL || size <= 0)
        return 0;
    // read and save the index, update the buf_off
    data->submit_p->buf[data->buf_off & (MAX_PERCPU_BUFSIZE - 1)] = index;
    data->buf_off += 1;
    // validate
    if (data->buf_off > (MAX_PERCPU_BUFSIZE - MAX_ARRAY_COUNT))
        return 0;
    int ret = bpf_probe_read(&(data->submit_p->buf[data->buf_off]), MAX_ARRAY_COUNT, (void *)&buffer->buf[0]);
    if (ret == 0)
        data->buf_off += *size;
    else
        return 0;
    data->context.argnum++;
    return 1;
}

/*
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
 * Also, in tracee, they said that the argv/envp pointers are invaild
 * in both entry and exit, be careful if we change the hook to raw_
 * tracepoint.
 */
SEC("tracepoint/syscalls/sys_enter_execve")
int sys_enter_execve(struct _sys_enter_execve *ctx)
{
    return store_execve_data((const char *const *)ctx->argv, (const char *const *)ctx->envp, _EXECVE_INDEX);
}

SEC("tracepoint/syscalls/sys_exit_execve")
int sys_exit_execve(void *ctx)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;
    if (context_filter(&data.context))
        return 0;
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
        return 0;
    void *file_path = get_path_str(GET_FIELD_ADDR(file->pwd));
    save_str_to_buf(&data, file_path, 1);
    void *ttyname = get_task_tty_str(data.task);
    save_str_to_buf(&data, ttyname, 2);
    void *stdin = get_fraw_str(0);
    save_str_to_buf(&data, stdin, 3);
    void *stdout = get_fraw_str(1);
    save_str_to_buf(&data, stdout, 4);
    get_socket_info(&data, 5);
    // pid_tree
    save_pid_tree_to_buf(&data, 8, 6);
    int ret = 0;
    ret = save_array_to_buf(&data, _TYPE_ARGV, _EXECVE_INDEX, 7);
    if (ret == 0)
        return 0;
    ret = save_array_to_buf(&data, _TYPE_ENVP, _EXECVE_INDEX, 8);
    if (ret == 0)
        return 0;
    return events_perf_submit(&data);
}

SEC("tracepoint/syscalls/sys_enter_execveat")
int sys_enter_execveat(struct _sys_enter_execveat *ctx)
{
    return store_execve_data((const char *const *)ctx->argv, (const char *const *)ctx->envp, _EXECVEAT_INDEX);
}

SEC("tracepoint/syscalls/sys_exit_execveat")
int sys_exit_execveat(void *ctx)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;
    if (context_filter(&data.context))
        return 0;
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
        return 0;
    void *file_path = get_path_str(GET_FIELD_ADDR(file->pwd));
    save_str_to_buf(&data, file_path, 1);
    void *ttyname = get_task_tty_str(data.task);
    save_str_to_buf(&data, ttyname, 2);
    void *stdin = get_fraw_str(0);
    save_str_to_buf(&data, stdin, 3);
    void *stdout = get_fraw_str(1);
    save_str_to_buf(&data, stdout, 4);
    get_socket_info(&data, 5);
    // pid_tree
    save_pid_tree_to_buf(&data, 8, 6);
    int ret = 0;
    ret = save_array_to_buf(&data, _TYPE_ARGV, _EXECVEAT_INDEX, 7);
    if (ret == 0)
        return 0;
    ret = save_array_to_buf(&data, _TYPE_ENVP, _EXECVEAT_INDEX, 8);
    if (ret == 0)
        return 0;
    return events_perf_submit(&data);
}

struct _sys_enter_prctl
{
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
int sys_enter_prctl(struct _sys_enter_prctl *ctx)
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

    bpf_probe_read(&option, sizeof(option), &ctx->option);
    if (option != PR_SET_NAME && option != PR_SET_MM)
        return 0;
    save_to_submit_buf(&data, &option, sizeof(int), 0);

    void *exe = get_exe_from_task(data.task);
    save_str_to_buf(&data, exe, 1);

    switch (option)
    {
    case PR_SET_NAME:
        bpf_probe_read_user_str(&newname, TASK_COMM_LEN, (char *)ctx->arg2);
        save_str_to_buf(&data, &newname, 2);
        break;
        /*
         * Some reference:
         * https://man7.org/linux/man-pages/man2/prctl.2.html
         * https://cloud.tencent.com/developer/article/1040079
         */
    case PR_SET_MM:
        bpf_probe_read_user(&flag2, sizeof(flag2), &ctx->arg2);
        save_to_submit_buf(&data, &flag2, sizeof(unsigned long), 2);
        break;
    default:
        break;
    }
    return events_perf_submit(&data);
}

struct _sys_enter_ptrace
{
    unsigned long long unused;
    long syscall_nr;
    long request;
    long pid;
    unsigned long addr;
    unsigned long data;
};
// @Reference: https://www.giac.org/paper/gcih/467/tracing-ptrace-case-study-internal-root-compromise-incident-handling/105271
// @Reference: https://driverxdw.github.io/2020/07/06/Linux-ptrace-so%E5%BA%93%E6%B3%A8%E5%85%A5%E5%88%86%E6%9E%90/
SEC("tracepoint/syscalls/sys_enter_ptrace")
int sys_enter_ptrace(struct _sys_enter_ptrace *ctx)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;
    if (context_filter(&data.context))
        return 0;
    data.context.type = SYS_ENTER_PTRACE;
    long request;
    bpf_probe_read(&request, sizeof(request), &ctx->request);
    if (request != PTRACE_POKETEXT && request != PTRACE_POKEDATA)
        return 0;

    void *exe = get_exe_from_task(data.task);
    save_str_to_buf(&data, exe, 0);
    save_to_submit_buf(&data, &request, sizeof(long), 1);
    save_to_submit_buf(&data, &ctx->pid, sizeof(long), 2);
    save_to_submit_buf(&data, &ctx->addr, sizeof(unsigned long), 3);
    save_pid_tree_to_buf(&data, 12, 4);
    return events_perf_submit(&data);
}

struct _sys_enter_memfd_create
{
    unsigned long long unused;
    long syscall_nr;
    const char *uname;
    unsigned int flags;
};

// https://xeldax.top/article/linux_no_file_elf_mem_execute
SEC("tracepoint/syscalls/sys_enter_memfd_create")
int sys_enter_memfd_create(struct _sys_enter_memfd_create *ctx)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;
    if (context_filter(&data.context))
        return 0;
    data.context.type = SYS_ENTER_MEMFD_CREATE;
    void *exe = get_exe_from_task(data.task);
    save_str_to_buf(&data, exe, 0);
    save_str_to_buf(&data, (char *)ctx->uname, 1);
    save_to_submit_buf(&data, &ctx->flags, sizeof(unsigned int), 2);
    return events_perf_submit(&data);
}
