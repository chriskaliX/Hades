#include "utils.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"
#include "bpf_tracing.h"

SEC("kprobe/security_inode_create")
int kprobe_security_inode_create(struct pt_regs *ctx)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;
    data.context.type = 1028;
    // exe
    void *exe = get_exe_from_task(data.task);
    int ret = save_str_to_buf(&data, exe, 0);
    if (ret == 0)
    {
        char nothing[] = "-1";
        save_str_to_buf(&data, nothing, 0);
    }
    struct dentry *dentry = (struct dentry *)PT_REGS_PARM2(ctx);
    void *dentry_path = get_dentry_path_str(dentry);
    save_str_to_buf(&data, dentry_path, 1);
    get_socket_info(&data, 2);
    return events_perf_submit(&data);
}