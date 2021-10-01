#include "common.h"
#include "bpf_helpers.h"
// #include "bpf_helper_defs.h"

// clang -(llvm)-> ebpf obj -(load)-> libbpf

/*
    记录一些reference
    https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md
*/

/* 
* 基本上很少看到 ebpf 如何写的
* 所以基本就靠直接啃, 不懂的就搜索
* C 的基础属于幼儿园水平, 但是没关系, 慢慢扣、多学习
*/

// 截取长度最大值
#define TASK_COMM_LEN 16

// execve struct
struct execve {
    u32 pid;
    u32 uid;
    u32 gid;
    u32 ppid;
    char comm[TASK_COMM_LEN];
};

// 定义返回通信的 map array?
struct bpf_map_def SEC("maps/execve_events") execve_events = {
        .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
        .key_size = sizeof(int),
        .value_size = sizeof(__u32),
        .max_entries = 1024,
};

SEC("kprobe/sys_execve")
int bpf_sys_execve(struct pt_regs *ctx)
{
    // bpf 的默认结构体, 查看 bpf_helper_defs.h 前面申明的 struct, 获取当前 attach 信息
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    // 创建 execve 结构体
    struct execve execve_data = {
        .pid = bpf_get_current_pid_tgid() >> 32,
        .uid = bpf_get_current_uid_gid() >> 32,
        .gid = bpf_get_current_uid_gid(),
        // .ppid = task->real_parent->tgid // 这个有bug, 在一些内核版本下
        .ppid = 0,
    };


    bpf_get_current_comm(&execve_data.comm, sizeof(execve_data.comm));
    bpf_perf_event_output(ctx, &execve_events, BPF_F_CURRENT_CPU, &execve_data, sizeof(execve_data));

    return 0;
}