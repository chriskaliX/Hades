#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h" // tracing, 来读取上下文

/*
    记录一些reference
    https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md
    https://github.com/andrewkroh/go-ebpf/blob/db8c37d734c59d955b679c721e12a342e3b5d93c/exec/bpf/exec.c
*/

/*
    issue 1: 碰到 LLVM 的问题
    https://github.com/cilium/ebpf/issues/43
    解决方法:
    llvm-strip ./kprobeexample_bpfeb.o --no-strip-all -R .BTF
    llvm-strip ./kprobeexample_bpfel.o --no-strip-all -R .BTF
*/

char __license[] SEC("license") = "Dual MIT/GPL";

// 截取长度最大值
#define TASK_COMM_LEN 16
#define ARGV_LEN 128
#define FILE_NAME_LEN 128
#define __user

// default 512
struct execve_t {
    u32 pid;
    u32 uid;
    u32 gid;
    u32 ppid;
    char file_name[FILE_NAME_LEN];
    char comm[TASK_COMM_LEN];
    char argv[ARGV_LEN];
};

struct bpf_map_def SEC("maps/execve_events") execve_events = {
        .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
        .key_size = sizeof(int),
        .value_size = sizeof(__u32),
        .max_entries = 1024,
};

// 参考 https://github.com/iovisor/bcc/blob/e83019bdf6c400b589e69c7d18092e38088f89a8/tools/execsnoop.py
SEC("kprobe/sys_execve")
int bpf_sys_execve(struct pt_regs *ctx)
{
    u32 cpu = bpf_get_smp_processor_id();
    // task_struct 是一个普遍的结构体, 详细定义看 vmlinux.h (从 common.h 替换了)
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    // execve_data
    struct execve_t execve_data;
    // https://github.com/iovisor/bcc/issues/2623
    __builtin_memset(&execve_data, 0, sizeof(execve_data));
    execve_data.pid = bpf_get_current_pid_tgid() >> 32;
    execve_data.uid = bpf_get_current_uid_gid() >> 32;
    execve_data.gid = bpf_get_current_uid_gid();
    // 获取 ppid 的在某些内核版本下会为 0, 需要 fallback
    execve_data.ppid = task->real_parent->tgid >> 32;    
    // 获取 comm
    bpf_get_current_comm(&execve_data.comm, sizeof(execve_data.comm));
    // 获取 filename
    struct pt_regs *ctx1 = (struct pt_regs *) PT_REGS_PARM1(ctx);
    char *filename;
    bpf_probe_read(&filename, sizeof(filename), &PT_REGS_PARM1(ctx1));
    bpf_probe_read(&execve_data.file_name, sizeof(execve_data.file_name), filename);

    const char __user *const __user *argv = (void *)PT_REGS_PARM2(ctx);
    // for (int i = 0;i < ARGV_LEN;i++) {
    //     char *argp = NULL;
    //     long res = bpf_probe_read(&argp, sizeof(&argp), (void *)argv);
    //     if (res == 0) {
    //         bpf_probe_read(execve_data.argv, sizeof(execve_data.argv), argp);
    //         bpf_perf_event_output(ctx, &execve_events, cpu, &execve_data, sizeof(execve_data));
    //         argv++;
    //     } else {
    //         break;
    //     }
    // }


    char *argp = NULL;
    bpf_probe_read_user(&argp, sizeof(argp), (void *)&argv[0]);
    bpf_probe_read(&execve_data.argv, sizeof(execve_data.argv), argp);

    // if (argv) {
    //     bpf_probe_read(&execve_data.argv, sizeof(execve_data.argv), argv);
    // } else {
    //     char nothing[] = "...";
    //     bpf_probe_read(&execve_data.argv, sizeof(execve_data.argv), (void *)nothing);
    // }

    bpf_perf_event_output(ctx, &execve_events, cpu, &execve_data, sizeof(execve_data));
    return 0;
}