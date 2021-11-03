// #include "common.h"
#include "vmlinux.h"
#include "bpf_helpers.h"

#define TASK_COMM_LEN 16
#define FNAME_LEN 32
#define ARGSIZE 128
#define DEFAULT_MAXARGS 20


struct exec_data_t {
    u32 type;
	u32 pid;
    u32 tgid;
    u32 uid;
    u32 gid;
    u32 ppid;
	char fname[FNAME_LEN];
	char comm[TASK_COMM_LEN];
    char args[ARGSIZE];
    u32 arg_size;
};

struct bpf_map_def SEC("maps") perf_events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    // .max_entries = 128,
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
	struct exec_data_t exec_data = {};
	exec_data.pid = bpf_get_current_pid_tgid();
    exec_data.tgid = bpf_get_current_pid_tgid() >> 32;
    exec_data.uid = bpf_get_current_uid_gid();
    exec_data.gid = bpf_get_current_uid_gid() >> 32;
    bpf_get_current_comm(exec_data.comm, sizeof(exec_data.comm));

    // 获取 ppid, task_struct 的问题
    struct task_struct *task;
    task = (struct task_struct*)bpf_get_current_task();
	struct task_struct* real_parent_task;
	bpf_probe_read(&real_parent_task, sizeof(real_parent_task), &task->real_parent );
	bpf_probe_read(&exec_data.ppid, sizeof(exec_data.ppid), &real_parent_task->pid );
    
    // 参数地址
	const char* argp = NULL;
	// https://stackoverflow.com/questions/67188440/ebpf-cannot-read-argv-and-envp-from-tracepoint-sys-enter-execve
	#pragma unroll
    for (__s32 i = 0; i < DEFAULT_MAXARGS; i++)
    {
		bpf_probe_read(&argp, sizeof(argp), &ctx->argv[i]);
		if (!argp) {
			goto finish;
		}
        exec_data.arg_size = bpf_probe_read_str(exec_data.args, ARGSIZE, argp);
        bpf_perf_event_output(ctx, &perf_events, BPF_F_CURRENT_CPU, &exec_data, sizeof(exec_data));
    }
	finish:
    exec_data.type = 1;
	bpf_probe_read_str(exec_data.fname, sizeof(exec_data.fname), ctx->filename);
    bpf_perf_event_output(ctx, &perf_events, BPF_F_CURRENT_CPU, &exec_data, sizeof(exec_data));
	return 0;
}

char LICENSE[] SEC("license") = "GPL";