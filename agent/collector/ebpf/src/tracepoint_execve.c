#include "vmlinux.h"
#include "bpf_helpers.h"

#define TASK_COMM_LEN 16
#define FNAME_LEN 32
#define ARGSIZE 128
#define DEFAULT_MAXARGS 20 // 有些启动参数,会十分的长

// enter_execve
struct enter_execve_t {
    u32 type;
	u32 pid;
    u32 tgid;
    u32 uid;
    u32 gid;
    u32 ppid;
	char filename[FNAME_LEN];
	char comm[TASK_COMM_LEN];
    char args[ARGSIZE];
    u32 argsize;
};

// 开始看 perf_events, 更正一下对 max_entries 的认识, 是存储用户态传输给内核的 fd, 而不是误认为的 array 队列长度之类
// 从内户态透传给用户态的, 是每个 cpu 一个 buffer, perf_events 可以是这些 ringbuf 的一个集合
struct bpf_map_def SEC("maps") perf_events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
};

/* /sys/kernel/debug/tracing/events/syscalls/sys_enter_execve/format */
struct execve_entry_args_t {
    __u64 unused;
	int syscall_nr;
	const char *filename;
    const char *const * argv;
    const char *const * envp;
};

SEC("tracepoint/syscalls/sys_enter_execve")
int enter_execve(struct execve_entry_args_t *ctx)
{
    // 定义返回数据
    struct enter_execve_t enter_execve_data = {};

    // 用来标识 sys_enter_execve, 供用户态区分
    enter_execve_data.type = 1;

    // 获取当前用户 id 和 gid
    u64 id = bpf_get_current_uid_gid();
    enter_execve_data.uid = id;
    enter_execve_data.gid = id >> 32;

    // 获取 pid & tgid
    id = bpf_get_current_pid_tgid();
    enter_execve_data.pid = id;
    enter_execve_data.tgid = id >> 32; // 线程 id
	
    // 通过 task_struct 获取父进程 id, 这个可能会有 bug 的, 比如 kernel 4.19(?) 的时候会是 0(TODO: check 这个问题!)
    // task_struct, 用于获取进程id, 线程id, 以及父进程id
    struct task_struct *task;
    struct task_struct* real_parent_task;
    task = (struct task_struct*)bpf_get_current_task();

    // 获取 cmdline
    bpf_get_current_comm(&enter_execve_data.comm, sizeof(enter_execve_data.comm));

    // TODO: BPF_CORE_READ 看后面 CO-RE 的时候, 直接获取。内核支持 BTF, kernel version 4.18
    bpf_probe_read(&real_parent_task, sizeof(real_parent_task), &task->real_parent );
	bpf_probe_read(&enter_execve_data.ppid, sizeof(enter_execve_data.ppid), &real_parent_task->pid );
    bpf_probe_read_str(enter_execve_data.filename, sizeof(enter_execve_data.filename), ctx->filename);
    
	const char* argp = NULL;

    for (__s32 i = 0; i < DEFAULT_MAXARGS; i++)
    {
		bpf_probe_read(&argp, sizeof(argp), &ctx->argv[i]);
		if (!argp) {
            return 0;
		}
        enter_execve_data.argsize = bpf_probe_read_str(enter_execve_data.args, ARGSIZE, argp);
        bpf_perf_event_output(ctx, &perf_events, BPF_F_CURRENT_CPU, &enter_execve_data, sizeof(enter_execve_data));
    }
	return 0;
}

char LICENSE[] SEC("license") = "GPL";