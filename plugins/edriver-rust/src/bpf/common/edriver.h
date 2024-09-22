// SPDX-License-Identifier: GPL-2.0-or-later

#ifndef __EDRIVER_H__
#define __EDRIVER_H__
#include <vmlinux.h>
#include <missing_definitions.h>
#include "consts.h"
#include "common.h"
#include "maps.h"
#include "bpf_core_read.h"
#include "bpf_helpers.h"

static struct proc_info *proc_info_init(struct task_struct *);
static unsigned int proc_info_args(struct proc_info *, struct task_struct *);
static unsigned int proc_info_envs(struct proc_info *, struct task_struct *);
static __noinline struct sock *proc_socket_info(struct task_struct *, pid_t *);
static __always_inline int proc_pid_tree(struct proc_info *, struct task_struct *);
static __always_inline int proc_info_creds(struct proc_info *, struct task_struct *);
static __noinline int prepend_pid_tree(struct proc_info *, struct task_struct *);
static __noinline int match_key(char *, int, uint64_t, int);

// trace/events/sched.h: TP_PROTO(struct task_struct *p, pid_t old_pid, struct linux_binprm *bprm)
SEC("raw_tracepoint/sched_process_exec")
int rtp__process_exec(struct bpf_raw_tracepoint_args *ctx)
{
    struct task_struct *task = (struct task_struct *) bpf_get_current_task();
    if (task == NULL)
        return 0;

    /* ingore kernel threads 
     * https://elixir.bootlin.com/linux/v6.10/source/include/linux/sched.h#L1644
     */
    u32 flags = BPF_CORE_READ(task, flags);
	if (flags & PF_KTHREAD)
		return 0;

    /* fulfill proc information */
    struct proc_info *proc_i = proc_info_init(task);
    if (proc_i == NULL)
        return 0;
    proc_info_args(proc_i, task);
    proc_info_envs(proc_i, task);
    proc_pid_tree(proc_i, task);

    struct hds_context c = init_context(ctx, SYS_ENTER_EXECVE);
    SBT((&c), &c.data_type, S_U32);
    SBT((&c), &proc_i->pid, S_U32);
    SBT((&c), &proc_i->tgid, S_U32);
    SBT((&c), &proc_i->pgid, S_U32);
    SBT((&c), &proc_i->ppid, S_U32);
    SBT((&c), &proc_i->sid, S_U32);
    SBT((&c), &proc_i->pns, S_U32);
    SBT((&c), &proc_i->cred.uid, S_U32);
    SBT((&c), &proc_i->cred.gid, S_U32);
    SBT((&c), &proc_i->socket_pid, S_U32);
    SBT_CHAR((&c), &proc_i->comm);
    SBT_CHAR((&c), &proc_i->node);
    SBT_CHAR((&c), &proc_i->args);
    SBT_CHAR((&c), &proc_i->ssh_conn);
    SBT_CHAR((&c), &proc_i->ld_pre);
    SBT_CHAR((&c), &proc_i->ld_lib);
    SBT_CHAR((&c), get_task_tty(task));
    /* pwd */
    struct path pwd = BPF_CORE_READ(task, fs, pwd);
    void *pwd_ptr = get_path(__builtin_preserve_access_index(&pwd));
    SBT_CHAR((&c), pwd_ptr);
    /* stdin & stdout */
    SBT_CHAR((&c), get_fd(task, 0));
    SBT_CHAR((&c), get_fd(task, 1));
    /* exe */
    struct path exe = BPF_CORE_READ(task, mm, exe_file, f_path);
    void *exe_ptr = get_path(__builtin_preserve_access_index(&exe));
    SBT_CHAR((&c), exe_ptr);
    /* socket info */
    SBT((&c), &proc_i->family, S_U16);
    if (proc_i->family == AF_INET6)
        SBT((&c), &proc_i->sinfo_v6, sizeof(struct hds_socket_info_v6));
    else if (proc_i->family == AF_INET)
        SBT((&c), &proc_i->sinfo, sizeof(struct hds_socket_info));
    /* process tree */
    SBT_CHAR((&c), &proc_i->pidtree);
    return report_event(&c);
}

/* proc_info init */
static struct proc_info *proc_info_init(struct task_struct *task)
{
    struct proc_info *proc_i;
    u32 tgid, pid;
    long ret = 0;

    pid = BPF_CORE_READ(task, pid);
    tgid = BPF_CORE_READ(task, tgid);

    /* get proper process info */
    if (bpf_map_update_elem(&proc_info_cache, &tgid, &_proc, BPF_NOEXIST))
        return NULL;
    proc_i = bpf_map_lookup_elem(&proc_info_cache, &tgid);
    if (!proc_i)
        return NULL;

    /* process info fullfill */
    proc_i->pid = pid;
    proc_i->socket_pid = pid;
    proc_i->tgid = tgid;
    proc_i->ppid = BPF_CORE_READ(task, real_parent, tgid);
    proc_i->pgid = get_task_pgid(task);
    proc_i->pns = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns.inum);
    char *uts_name = BPF_CORE_READ(task, nsproxy, uts_ns, name.nodename);
    if (uts_name)
        bpf_probe_read_str(proc_i->node, MAX_NODENAME, uts_name);
    ret = bpf_get_current_comm(&proc_i->comm, TASK_COMM_LEN);
    if (ret < 0)
        return NULL;
    /* socket */
    struct sock *sk = proc_socket_info(task, (pid_t *)&proc_i->socket_pid);
    if (!sk) {
        proc_i->socket_pid = 0;
    } else {        
        proc_i->family = BPF_CORE_READ(sk, sk_family);
        if (proc_i->family == AF_INET) {
            struct hds_socket_info sinfo = {};
            get_sock_v4(sk, &sinfo);
            proc_i->sinfo = sinfo;
        } else if (proc_i->family == AF_INET6) {
            struct hds_socket_info_v6 sinfo_v6 = {};
            get_sock_v6(sk, &sinfo_v6);
            proc_i->sinfo_v6 = sinfo_v6;
        }
    }
    /* user */
    proc_info_creds(proc_i, task);
    return proc_i;
}

/* fill up args for proc_info */
static unsigned int proc_info_args(struct proc_info *info, struct task_struct *task)
{
    unsigned long arg_start, arg_end;
    unsigned int arg_len, sl, len = 0;

    /* args information */
    arg_start = BPF_CORE_READ(task, mm, arg_start);
    arg_end = BPF_CORE_READ(task, mm, arg_end);
    arg_len = (unsigned int)(arg_end - arg_start);
    if (arg_len == 0)
        return 0;
    if (arg_len >= MAX_STR)
        arg_len = MAX_STR_MASK;
    
    buf_t *cache = get_percpu_buf(LOCAL_CACHE);
    if (cache == NULL)
        return 0;
    
    /* args mapping */
#pragma unroll
    for (int i = 0; i < ARR_ARGS_LEN; i++)
    {
        if (len >= arg_len)
            goto out;
        sl = bpf_probe_read_str(&cache->buf[len & MAX_STR_MASK], MAX_STR, (void *)(arg_start + len));
        if (sl <= 0)
            goto out; /* notice: break do not work on unroll */
        len = len + sl;
        cache->buf[(len - 1) & MAX_STR_MASK] = 0x20;
    }
out:
    cache->buf[(len - 1) & MAX_STR_MASK] = '\0';
    return bpf_probe_read_str(info->args, len & MAX_STR_MASK, cache->buf);
}

/* fill up envs for proc_info */
static unsigned int proc_info_envs(struct proc_info *info, struct task_struct *task)
{
    unsigned long env_start, env_end;
    unsigned int env_len, sl, len = 0;
    unsigned int offset = 0;

    /* args information */
    env_start = BPF_CORE_READ(task, mm, env_start);
    env_end = BPF_CORE_READ(task, mm, env_end);
    env_len = (unsigned int)(env_end - env_start);
    if (env_len == 0)
        return 0;
    
    buf_t *cache = get_percpu_buf(LOCAL_CACHE);
    if (cache == NULL)
        return 0;
    
    /* args mapping */
#pragma unroll
    for (int i = 0; i < ARR_ENVS_LEN; i++)
    {
        sl = bpf_probe_read_str(&cache->buf[0], MAX_STR_MASK, (void *)(env_start + len));
        if (sl <= 0)
            goto out; /* notice: break do not work on unroll */
        len = len + sl;
        if (match_key((char *)&cache->buf[0], sl, 0x4e4e4f435f485353UL, 14)) {
            /* SSH_CONN */
            bpf_probe_read_str(info->ssh_conn, MAX_STR_ENV, &cache->buf[15]);
        } else if (match_key((char *)&cache->buf[0], sl, 0x4f4c4552505f444cUL, 10)) {
            /* LD_PRELO */
            bpf_probe_read_str(info->ld_pre, MAX_STR_ENV, &cache->buf[11]);
        } else if (match_key((char *)&cache->buf[0], sl, 0x415242494c5f444cUL, 15)) {
            /* LD_LIBRA */
            bpf_probe_read_str(info->ld_lib, MAX_STR_ENV, &cache->buf[16]);
        } else {
            continue;
        }
    }
out:
    return 0;
}

static __noinline struct sock *proc_socket_info(struct task_struct *task, pid_t *pid)
{
    struct task_struct *parent;
    struct sock *sk;

    /* try find sockfd for current (given) task */
    sk = find_sockfd(task);
    if (sk) {
        *pid = BPF_CORE_READ(task, tgid);
        goto out;
    }
    /* process for parent process of current */
    parent = (struct task_struct *)BPF_CORE_READ(task, real_parent);
    if (!parent || parent == task)
        goto out;
    sk = find_sockfd(parent);
    if (sk) {
        *pid = BPF_CORE_READ(parent, tgid);
        goto out;
    }
    /* process grandfather process */
    task = parent;
    parent = (struct task_struct *)BPF_CORE_READ(task, real_parent);
    if (!parent || parent == task)
        goto out;
    sk = find_sockfd(parent);
    if (sk) {
        *pid = BPF_CORE_READ(parent, tgid);
        goto out;
    }
out:
    return sk;
}

/* Elkeid v1.8-rc */
static __always_inline int proc_pid_tree(struct proc_info *info, struct task_struct *task)
{
    struct task_struct *parent;
    int i;

    info->pidtree_len = 0;

#pragma unroll
    for (i = 0; i < 12; i++) {
        if (!prepend_pid_tree(info, task))
            break;
        parent = BPF_CORE_READ(task, real_parent);
        if (!parent || parent == task)
            break;
        task = parent;
    }

    /* trailing \0 added */
    if (info->pidtree_len)
        info->pidtree_len++;
    return (int)info->pidtree_len;
}

static __noinline int prepend_pid_tree(struct proc_info *info, struct task_struct *task)
{
    char *comm;
    pid_t pid;
    int rc = 0, len, last;

    pid = BPF_CORE_READ(task, tgid);
    if (!pid)
        return 0;

    len = last = info->pidtree_len;
    if (len) {
        info->pidtree[len & PIDTREE_MASK] = '<';
        len = len + 1;
    }
    rc = do_u32toa(pid, &info->pidtree[len & PIDTREE_MASK], PIDTREE_LEN - len);
    if (!rc)
        goto out;
    len += rc;
    info->pidtree[len & PIDTREE_MASK] = '.';
    len = len + 1;
    comm = BPF_CORE_READ(task, comm);
    if (!comm)
        goto out;
    if (len >= PIDTREE_LEN - TASK_COMM_LEN)
        goto out;
    rc = bpf_probe_read_str(&info->pidtree[len & PIDTREE_MASK], TASK_COMM_LEN, comm);
    if (rc <= 1)
        goto out;
    if (rc > TASK_COMM_LEN)
        rc = TASK_COMM_LEN;
    len += rc - 1;

    info->pidtree[len & PIDTREE_MASK] = 0;
    info->pidtree_len = len;
    return len;

out:
    info->pidtree[last & PIDTREE_MASK] = 0;
    return 0;
}

static __always_inline int proc_info_creds(struct proc_info *info, struct task_struct *task)
{
    info->cred.uid = BPF_CORE_READ(task, real_cred, uid.val);
    info->cred.gid = BPF_CORE_READ(task, real_cred, gid.val);
    info->cred.suid = BPF_CORE_READ(task, real_cred, suid.val);
    info->cred.sgid = BPF_CORE_READ(task, real_cred, sgid.val);
    info->cred.euid = BPF_CORE_READ(task, real_cred, euid.val);
    info->cred.egid = BPF_CORE_READ(task, real_cred, egid.val);
    info->cred.fsuid = BPF_CORE_READ(task, real_cred, fsuid.val);
    info->cred.fsgid = BPF_CORE_READ(task, real_cred, fsgid.val);
    return 0;
}


#endif

/* from Elkeid 1.8-rc, easier way to match */
static __noinline int match_key(char *envs, int lenv, uint64_t key, int es)
{
    uint64_t *d = (void *)envs;
    return (lenv > es && *d == key && envs[es & MAX_STR_MASK] == '=');
}