// cred
#include <linux/cred.h>
#include <linux/user_namespace.h>
#include "utils_buf.h"
#include "utils.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"
#include "bpf_tracing.h"

typedef struct slim_cred
{
    uid_t uid;           // real UID of the task
    gid_t gid;           // real GID of the task
    uid_t suid;          // saved UID of the task
    gid_t sgid;          // saved GID of the task
    uid_t euid;          // effective UID of the task
    gid_t egid;          // effective GID of the task
    uid_t fsuid;         // UID for VFS ops
    gid_t fsgid;         // GID for VFS ops
    u32 user_ns;         // User Namespace of the event
    u32 securebits;      // SUID-less security management
    u64 cap_inheritable; // caps our children can inherit
    u64 cap_permitted;   // caps we're permitted
    u64 cap_effective;   // caps we can actually use
    u64 cap_bset;        // capability bounding set
    u64 cap_ambient;     // Ambient capability set
} slim_cred_t;

// Detection of privilege escalation
SEC("kprobe/commit_creds")
int kprobe_commit_creds(struct pt_regs *ctx)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;
    data.context.type = 11;

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
        slim_cred_t old_slim = {0};
        slim_cred_t new_slim = {0};

        struct user_namespace *userns_old = READ_KERN(old->user_ns);
        struct user_namespace *userns_new = READ_KERN(new->user_ns);

        old_slim.uid = READ_KERN(old->uid.val);
        old_slim.gid = READ_KERN(old->gid.val);
        old_slim.suid = READ_KERN(old->suid.val);
        old_slim.sgid = READ_KERN(old->sgid.val);
        old_slim.euid = READ_KERN(old->euid.val);
        old_slim.egid = READ_KERN(old->egid.val);
        old_slim.fsuid = READ_KERN(old->fsuid.val);
        old_slim.fsgid = READ_KERN(old->fsgid.val);
        old_slim.user_ns = READ_KERN(userns_old->ns.inum);
        old_slim.securebits = READ_KERN(old->securebits);

        new_slim.uid = READ_KERN(new->uid.val);
        new_slim.gid = READ_KERN(new->gid.val);
        new_slim.suid = READ_KERN(new->suid.val);
        new_slim.sgid = READ_KERN(new->sgid.val);
        new_slim.euid = READ_KERN(new->euid.val);
        new_slim.egid = READ_KERN(new->egid.val);
        new_slim.fsuid = READ_KERN(new->fsuid.val);
        new_slim.fsgid = READ_KERN(new->fsgid.val);
        new_slim.user_ns = READ_KERN(userns_new->ns.inum);
        new_slim.securebits = READ_KERN(new->securebits);

        save_to_submit_buf(&data, (void *)&old_slim, sizeof(slim_cred_t), 0);
        save_to_submit_buf(&data, (void *)&new_slim, sizeof(slim_cred_t), 1);
        save_pid_tree_to_buf(&data, 12, 2);

        events_perf_submit(&data);
        return 1;
    }

    return 0;
}