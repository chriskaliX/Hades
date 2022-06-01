#ifndef CORE
#include <linux/cred.h>
#include <linux/user_namespace.h>
#else
#include <vmlinux.h>
#include <missing_definitions.h>
#endif

#include "define.h"
#include "utils_buf.h"
#include "utils.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"
#include "bpf_tracing.h"

// Detection of privilege escalation
SEC("kprobe/commit_creds")
int BPF_KPROBE(kprobe_commit_creds)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;
    if (context_filter(&data.context))
        return 0;
    data.context.type = COMMIT_CREDS;

    struct cred *new = (struct cred *)PT_REGS_PARM1(ctx);
    struct cred *old = (struct cred *)get_task_real_cred(data.task);

    unsigned int new_uid = READ_KERN(new->uid.val);
    unsigned int old_uid = READ_KERN(old->uid.val);

    // in Elkeid: privilege escalation only detect uid none zero to zero
    // But in tracee, any uid changes will lead to detection of this
    if (new_uid == 0 && old_uid != 0)
    {
        save_to_submit_buf(&data, &new_uid, sizeof(unsigned int), 0);
        save_to_submit_buf(&data, &old_uid, sizeof(unsigned int), 1);
        void *exe = get_exe_from_task(data.task);
        save_str_to_buf(&data, exe, 2);
        save_pid_tree_to_buf(&data, 12, 3);
        events_perf_submit(&data);
        return 1;
    }
    return 0;
}