#include <linux/sched.h>

#include "common.h"
#include "utils.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"

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
    // filename, 改为获取 filename
    save_str_to_buf(&data, (void *)ctx->filename, 0);
    // 新增 pid_tree
    save_pid_tree_new_to_buf(&data, 8, 1);
    save_str_arr_to_buf(&data, (const char *const *)ctx->argv, 2);
    save_envp_to_buf(&data, (const char *const *)ctx->envp, 3);
    bpf_probe_read(&(data.submit_p->buf[0]), sizeof(context_t), &data.context);

    // 对于 cwd 的获取实现, tracee 上有一个很好的 issue
    // https://github.com/aquasecurity/tracee/issues/852
    // 简单来说目前读取的时候没有办法对 dentry tree & mount point 添加锁, 所以会导致读取的时候可能会出现数据不准确的情况
    // 在目前的 Hades 中, 我们可以在 execve 中变相的从 envp 中读取(也是不可靠的, 但是能用...)。但是长期来看，应该还是要按照 tracee 的方法来满足其他 hook 点的需求
    // 另外也提到了 https://github.com/Gui774ume/fsprobe 中的读取方式
    // TODO: take a look

    // satisfy validator by setting buffer bounds
    int size = data.buf_off & ((MAX_PERCPU_BUFSIZE)-1);
    void *output_data = data.submit_p->buf;
    return bpf_perf_event_output(ctx, &exec_events, BPF_F_CURRENT_CPU, output_data, size);
}

