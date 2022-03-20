// For uprobe, here are things that I want!
// uprobe is really useful, we can use this in lower kernel version. Since
// re-location is not needed, CO-RE seems not that important...
#include "utils.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"
#include "bpf_tracing.h"

// in Cilium example, the size of the line is limited to 80, we enlarge this to 256
SEC("uretprobe/bash_readline")
int uretprobe_bash_readline(struct pt_regs *ctx)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;
    data.context.type = 2000;
    // exe
    void *exe = get_exe_from_task(data.task);
    int ret = save_str_to_buf(&data, exe, 0);
    if (ret == 0)
    {
        char nothing[] = "-1";
        save_str_to_buf(&data, nothing, 0);
    }
    // line
    void *line = (void *)PT_REGS_RC(ctx);
    save_str_to_buf(&data, line, 1);
    void *ttyname = get_task_tty_str(data.task);
    save_str_to_buf(&data, ttyname, 2);
    // stdin
    void *stdin = get_fraw_str(0);
    save_str_to_buf(&data, stdin, 3);
    // stdout
    void *stdout = get_fraw_str(1);
    save_str_to_buf(&data, stdout, 4);
    // socket
    get_socket_info(&data, 5);
    // 新增 pid_tree
    save_pid_tree_to_buf(&data, 8, 6);
    struct fs_struct *file;
    bpf_probe_read(&file, sizeof(file), &data.task->fs);
    void *file_path = get_path_str(GET_FIELD_ADDR(file->pwd));
    ret = save_str_to_buf(&data, file_path, 7);
    if (ret == 0)
    {
        char nothing[] = "-1";
        save_str_to_buf(&data, nothing, 7);
    }
    return events_perf_submit(&data);
}