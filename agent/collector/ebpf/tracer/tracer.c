#include <linux/kconfig.h>
#include <linux/sched.h>
#include <linux/nsproxy.h>
#include <linux/utsname.h>
#include <linux/types.h>
#include <linux/ns_common.h>
#include <linux/sched/signal.h>
#include <linux/tty.h>
#include <linux/fs_struct.h>
#include <linux/path.h>
#include <linux/dcache.h>

#include "common.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"

#include "definition.h"

struct bpf_map_def SEC("maps") perf_events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
};

// at 多了一个 flags
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
    event_data_t data = {};
    if (!init_event_data(&data))
        return 0;
    data.context.type = 1;
    // filename, 改为获取 filename
    save_str_to_buf(&data, (void *)ctx->filename, 0);
    save_str_arr_to_buf(&data, (const char *const *)ctx->argv, 1);
    // 环境变量, 获取如 LD_PRELOAD 等信息
    // 先不在内核态做 envp 的过滤, 全部传递至用户态来? env 数据太多了, 思考一下
    save_str_arr_to_buf(&data, (const char *const *)ctx->envp, 2);
    bpf_probe_read(&(data.submit_p->buf[0]), sizeof(context_t), &data.context);

    // satisfy validator by setting buffer bounds
    int size = data.buf_off & ((MAX_PERCPU_BUFSIZE)-1);
    void *output_data = data.submit_p->buf;
    return bpf_perf_event_output(ctx, &exec_events, BPF_F_CURRENT_CPU, output_data, size);
}

// SEC("tracepoint/syscalls/sys_enter_execveat")
// int enter_execveat(struct execve_entry_args_t *ctx)
// {
//     // 定义返回数据
//     context_t enter_execve_data = {};
//     enter_execve_data.type = 2;
//     execve_common(&enter_execve_data);
//     bpf_probe_read_str(enter_execve_data.exe, sizeof(enter_execve_data.exe), ctx->filename);
//     return 0;
// }

struct _tracepoint_sched_process_fork {
    __u64 unused;
    char parent_comm[16];
    pid_t parent_pid;
    char child_comm[16];
    pid_t child_pid;
};

// 为了缓解 ppid 的问题, 需要 hook 到 fork 上面, 在本地维护一个 map
SEC("tracepoint/sched/sched_process_fork")
int process_fork( struct _tracepoint_sched_process_fork *ctx ) {
    u32 pid = 0;
    u32 ppid = 0;
    bpf_probe_read(&pid, sizeof(pid), &ctx->child_pid);
    bpf_probe_read(&ppid, sizeof(ppid), &ctx->parent_pid);
    struct pid_cache_t cache = {};
    cache.ppid = ppid;
    bpf_probe_read(&cache.pcomm, sizeof(cache.pcomm), &ctx->parent_comm);
    bpf_map_update_elem(&pid_cache_lru, &pid, &cache, BPF_ANY);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";