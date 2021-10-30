// #ifdef USE_VMLINUX
// #include "vmlinux.h"
// #else
#include "linux/sched.h"
// // #include <linux/ptrace.h>
// #endif

#include "common.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"

/*
    Besides, Kernel Version needs to be compared
    https://github.com/iovisor/bcc/issues/3232 --- CO-RE libbpf Ubuntu vmlinux.h
*/

char __license[] SEC("license") = "Dual MIT/GPL";

#define TASK_COMM_LEN 16
#define ARGV_LEN 128
#define FILE_NAME_LEN 128
#define MAXARG 20

struct data {
    u32 pid;
    u32 uid;
    u32 gid;
    u32 ppid;
    char filename[FILE_NAME_LEN];
    char comm[TASK_COMM_LEN];
    char argv[ARGV_LEN];
};

struct bpf_map_def SEC("maps") exe_events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(u32),
    .max_entries = 1024,
};

SEC("kprobe/sys_execve")
int bpf_sys_execve(struct pt_regs *ctx)
{
	struct data data = {
		.pid = 0,
	};
	void *pfilename = (void *)(ctx->rdi + offsetof(struct pt_regs, rdi));
	void *pargv = (void *)(ctx->rdi + offsetof(struct pt_regs, rsi));
	char *filename, **argv;
	int bail = 0;
	int i;

	// set_current_info(&data);

	if (bpf_probe_read(&filename, sizeof(filename), pfilename) ||
	    bpf_probe_read_str(data.argv, sizeof(data.argv), filename) < 0) {
		__builtin_strcpy(data.argv, "<filename FAILED>");
		bail = 1;
	}

	if (bpf_perf_event_output(ctx, &exe_events, BPF_F_CURRENT_CPU,
				  &data, sizeof(data)) < 0 || bail)
		goto out;

	if (bpf_probe_read((void *) &argv, sizeof(void *), pargv))
		goto out;

	/* skip first arg; submitted filename */
	#pragma unroll
	for (int i = 1; i <= MAXARG; i++) {
		void *ptr = NULL;

		if (bpf_probe_read(&ptr, sizeof(ptr), &argv[i]) || ptr == NULL)
			goto out;
		if (bpf_probe_read_str(data.argv, sizeof(data.argv), ptr) < 0)
			goto out;
		if (bpf_perf_event_output(ctx, &exe_events, BPF_F_CURRENT_CPU,
					  &data, sizeof(data)) < 0)
			goto out;
	}

	strcpy(data.argv, "...");
	bpf_perf_event_output(ctx, &exe_events, BPF_F_CURRENT_CPU,
			      &data, sizeof(data));
out:
	return 0;
}