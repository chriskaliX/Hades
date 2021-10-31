#include "vmlinux.h" /*在 vmlinux.h里只取了 pt_regs(或者ptrace.h) 和一些其他定义*/
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
int BPF_KPROBE(probe_sys_execve, const char *filename, 
    const char *const *argv, 
    const char *const *envp) {
		
	struct data data = {
		.pid = 0,
	};
	u32 cpu = bpf_get_smp_processor_id();
	bpf_get_current_comm(&data.comm, sizeof(data.comm));

	// void *fn;
	// fn = ___bpf_kprobe_args2(ctx);

	// bpf_probe_read_user_str(&data.filename, sizeof(data.filename), filename);
	// const char * filename_t = (const char *)PT_REGS_PARM1(ctx);
	// bpf_probe_read_user_str( &data.filename, sizeof( data.filename ), filename_t );

	// struct pt_regs *ctx1 = (struct pt_regs *)(PT_REGS_PARM1(ctx));
	// bpf_probe_read(&filename, sizeof(filename), &PT_REGS_PARM1(ctx1));
	// bpf_probe_read(&data.filename, sizeof(data.filename), fn);

	bpf_perf_event_output(ctx, &exe_events, cpu, &data, sizeof(data));
	return 0;
}

// SEC("kprobe/sys_execve")
// int bpf_sys_execve(struct pt_regs *ctx)
// {
// 	char *filename;
// 	struct data data = {
// 		.pid = 0,
// 	};
// 	u32 cpu = bpf_get_smp_processor_id();
// 	bpf_get_current_comm(&data.comm, sizeof(data.comm));

	
// 	struct pt_regs *ctx1 = (struct pt_regs *)(___bpf_kprobe_args1(ctx));

// 	bpf_probe_read(&filename, sizeof(filename), &PT_REGS_PARM1(ctx1));
// 	bpf_probe_read(&data.filename, sizeof(data.filename), filename);
// 	bpf_perf_event_output(ctx, &exe_events, cpu, &data, sizeof(data));
// 	return 0;
// 	if (bpf_probe_read(&filename, sizeof(filename), pfilename) ||
// 	    bpf_probe_read_str(data.argv, sizeof(data.argv), filename) < 0) {
// 		__builtin_strcpy(data.argv, "<filename FAILED>");
// 		bail = 1;
// 	}

// 	if (bpf_perf_event_output(ctx, &exe_events, BPF_F_CURRENT_CPU,
// 				  &data, sizeof(data)) < 0 || bail)
// 		goto out;

// 	if (bpf_probe_read((void *) &argv, sizeof(void *), pargv))
// 		goto out;

// 	/* skip first arg; submitted filename */
// 	#pragma unroll
// 	for (int i = 1; i <= MAXARG; i++) {
// 		void *ptr = NULL;
// 		if (bpf_probe_read(&ptr, sizeof(ptr), &argv[i]) || ptr == NULL)
// 			goto out;
// 		if (bpf_probe_read_str(data.argv, sizeof(data.argv), ptr) < 0)
// 			goto out;
// 		if (bpf_perf_event_output(ctx, &exe_events, BPF_F_CURRENT_CPU, &data, sizeof(data)) < 0)
// 			goto out;
// 	}

// 	strcpy(data.argv, "...");
// 	bpf_perf_event_output(ctx, &exe_events, BPF_F_CURRENT_CPU, &data, sizeof(data));
// out:
// 	return 0;
// }