#include <linux/sched.h>

#include "common.h"
#include "utils.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"

// All this is based on tracee
// TODO: 1. 网络、进程、文件等事件采集 2. CO-RE 3. 判断 kernel version, use ringbuf
char LICENSE[] SEC("license") = "GPL";

struct tp_execve_t {
    __u64 unused;
    int syscall_nr;
    const char *filename;
    const char *const * argv;
    const char *const * envp;
};

SEC("tracepoint/syscalls/sys_enter_execve")
int enter_execve(struct tp_execve_t *ctx)
{
    event_data_t data = {};
    if (!init_event_data(&data))
        return 0;
    data.context.type = 1;
    // filename
    save_str_to_buf(&data, (void *)ctx->filename, 0);
    // cwd
    struct fs_struct *file;
    bpf_probe_read(&file, sizeof(file), &data.task->fs);
    void *file_path = get_path_str(GET_FIELD_ADDR(file->pwd));
    save_str_to_buf(&data, file_path, 1);
    // 新增 pid_tree
    save_pid_tree_new_to_buf(&data, 8, 2);
    save_str_arr_to_buf(&data, (const char *const *)ctx->argv, 3);
    save_envp_to_buf(&data, (const char *const *)ctx->envp, 4);
    bpf_probe_read(&(data.submit_p->buf[0]), sizeof(context_t), &data.context);
    // satisfy validator by setting buffer bounds
    int size = data.buf_off & ((MAX_PERCPU_BUFSIZE)-1);
    void *output_data = data.submit_p->buf;
    return bpf_perf_event_output(ctx, &exec_events, BPF_F_CURRENT_CPU, output_data, size);
}

