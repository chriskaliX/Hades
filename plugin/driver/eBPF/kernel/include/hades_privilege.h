// cred
#include <linux/cred.h>
#include <linux/user_namespace.h>
#include "utils_buf.h"
#include "utils.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"
#include "bpf_tracing.h"

// Detection of privilege escalation
// TODO: going to go through this. would this been too much for this?
SEC("kprobe/commit_creds")
int kprobe_commit_creds(struct pt_regs *ctx)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;
    data.context.type = 1011;

    struct cred *new = (struct cred *)PT_REGS_PARM1(ctx);
    struct cred *old = (struct cred *)READ_KERN(data.task->real_cred);

    unsigned int new_uid;
    unsigned int old_uid;

    bpf_probe_read(&new_uid, sizeof(new_uid), &new->uid.val);
    bpf_probe_read(&old_uid, sizeof(old_uid), &old->uid.val);
    // in Elkeid: privilege escalation only detect uid none zero to zero
    // But in tracee, any uid changes will lead to detection of this
    if (new_uid == 0 && old_uid != 0)
    {
        save_to_submit_buf(&data, &new_uid, sizeof(unsigned int), 0);
        save_to_submit_buf(&data, &old_uid, sizeof(unsigned int), 1);
        void *exe = get_exe_from_task(data.task);
        int ret = save_str_to_buf(&data, exe, 2);
        if (ret == 0)
        {
            char nothing[] = "-1";
            save_str_to_buf(&data, nothing, 2);
        }
        save_pid_tree_to_buf(&data, 12, 3);
        events_perf_submit(&data);
        return 1;
    }

    return 0;
}