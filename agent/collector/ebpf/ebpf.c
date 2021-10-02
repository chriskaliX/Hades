// #include "common.h"
#include "vmlinux.h"
#include "bpf_helpers.h"
/*
    记录一些reference
    https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md
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
#define TASK_COMM_LEN 256
#define ARGV_LEN 256

// execve struct
struct execve {
    u32 pid;
    u32 uid;
    u32 gid;
    u32 ppid;
    char comm[TASK_COMM_LEN];
    char argv[ARGV_LEN];
};

// 定义返回通信的 map array?
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
    // bpf 的默认结构体, 查看 bpf_helper_defs.h 前面申明的 struct, 获取当前 attach 信息
    // task_struct 是一个普遍的结构体, 详细定义看 vmlinux.h (从 common.h 替换了)
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    // execve_data
    // struct execve execve_data = {
    //     .pid = bpf_get_current_pid_tgid() >> 32,
    //     .uid = bpf_get_current_uid_gid() >> 32,
    //     .gid = bpf_get_current_uid_gid(),
    //     .ppid = task->real_parent->tgid, // 这个有bug, 在一些内核版本下会直接返回 0, 再搜一下
    // };
    struct execve execve_data;

    // https://github.com/iovisor/bcc/issues/2623
    __builtin_memset(&execve_data, 0, sizeof(execve_data));
    execve_data.pid = bpf_get_current_pid_tgid() >> 32;
    execve_data.uid = bpf_get_current_uid_gid() >> 32;
    execve_data.gid = bpf_get_current_uid_gid();
    execve_data.ppid = task->real_parent->tgid >> 32;

    bpf_get_current_comm(&execve_data.comm, sizeof(execve_data.comm));

    // const char *argp = NULL;
    // bpf_probe_read_user(&argp, sizeof(argp), ptr);

    // https://zhidao.baidu.com/question/684624210709860732.html
    // const char __user *const __user *__argv;
    // const char *argp = NULL;
    // bpf_probe_read_user(execve_data.argv, sizeof(&execve_data.argv), (void *)&__argv);

    bpf_perf_event_output(ctx, &execve_events, BPF_F_CURRENT_CPU, &execve_data, sizeof(execve_data));
    // handle truncated argument list
    // char ellipsis[] = "...";

    return 0;
}
