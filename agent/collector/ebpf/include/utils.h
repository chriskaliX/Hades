#include "common.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"
#include "define.h"
#include <linux/sched.h>

/* save envp to buf (with specific fields) */
static __always_inline int save_envp_to_buf(event_data_t *data, const char __user *const __user *ptr, u8 index)
{
    // Data saved to submit buf: [index][string count][str1 size][str1][str2 size][str2]...
    /* if we want to limited size of buf_t to 1 << 13, we have to do a precheck before every save_(*)_to_buf function */
    /* init the elem num */
    u8 elem_num = 0;
    data->submit_p->buf[(data->buf_off) & ((MAX_PERCPU_BUFSIZE)-1)] = index;
    /* flags for envs */
    int ssh_connection_flag, ld_preload_flag, ld_library_path_flag, tmp_flag;
    // Save space for number of elements (1 byte): [string count]
    u32 orig_off = data->buf_off+1;
    // update the buf_off
    data->buf_off += 2;
    /* Bounded loops are available starting with Linux 5.3, so we had to unroll the for loop at compile time */
    #pragma unroll
    for (int i = 0; i < MAX_STR_ARR_ELEM; i++) {
        const char *argp = NULL;
        /* read to argp and check */
        bpf_probe_read(&argp, sizeof(argp), &ptr[i]);
        if (!argp)
            goto out;
        /* check the available size */
        if (data->buf_off > (MAX_PERCPU_BUFSIZE) - (MAX_STRING_SIZE) - sizeof(int))
            goto out;
        /* out if all envs are collected */
        if (ld_library_path_flag && ld_preload_flag && ssh_connection_flag) {
            goto out;
        }
        /* TODO: implements the strtok to make this configurable */
        if (!ssh_connection_flag) {
            if has_prefix(argp, "SSH_CONNECTION=", 15) {
                ssh_connection_flag = 1;
                tmp_flag = 1;
            }
        }
        if (!ld_preload_flag) {
            if has_prefix(argp, "LD_PRELOAD=", 11) {
                ld_preload_flag = 1;
                tmp_flag = 1;
            }
        }
        if (!ld_library_path_flag) {
            if has_prefix(argp, "LD_LIBRARY_PATH=", 16) {
                ld_library_path_flag = 1;
                tmp_flag = 1;
            }
        }
        if (!tmp_flag) {
            continue;
        } else {
            tmp_flag = 0;
        }
        /* read into buf & update the elem_num */
        int sz = bpf_probe_read_str(&(data->submit_p->buf[data->buf_off + sizeof(int)]), MAX_STRING_SIZE, argp);
        if (sz > 0) {
            if (data->buf_off > (MAX_PERCPU_BUFSIZE) - sizeof(int))
                goto out;
            bpf_probe_read(&(data->submit_p->buf[data->buf_off]), sizeof(int), &sz);
            data->buf_off += sz + sizeof(int);
            elem_num++;
            continue;
        } else {
            goto out;
        }
    }
    char ellipsis[] = "...";
    if (data->buf_off > (MAX_PERCPU_BUFSIZE) - (MAX_STRING_SIZE) - sizeof(int))
        goto out;

    // Read into buffer
    int sz = bpf_probe_read_str(&(data->submit_p->buf[data->buf_off + sizeof(int)]), MAX_STRING_SIZE, ellipsis);
    if (sz > 0) {
        if (data->buf_off > (MAX_PERCPU_BUFSIZE) - sizeof(int))
            goto out;
        bpf_probe_read(&(data->submit_p->buf[data->buf_off]), sizeof(int), &sz);
        data->buf_off += sz + sizeof(int);
        elem_num++;
    }
out:
    // save number of elements in the array
    data->submit_p->buf[orig_off & ((MAX_PERCPU_BUFSIZE)-1)] = elem_num;
    data->context.argnum++;
    return 1;
}
/* save str array to buf (like args) */
static __always_inline int save_str_arr_to_buf(event_data_t *data, const char __user *const __user *ptr, u8 index)
{
    u8 elem_num = 0;
    data->submit_p->buf[(data->buf_off) & ((MAX_PERCPU_BUFSIZE)-1)] = index;
    u32 orig_off = data->buf_off+1;
    data->buf_off += 2;
    #pragma unroll
    for (int i = 0; i < MAX_STR_ARR_ELEM; i++) {
        const char *argp = NULL;
        bpf_probe_read(&argp, sizeof(argp), &ptr[i]);
        if (!argp)
            goto out;
        if (data->buf_off > (MAX_PERCPU_BUFSIZE) - (MAX_STRING_SIZE) - sizeof(int))
            goto out;
        int sz = bpf_probe_read_str(&(data->submit_p->buf[data->buf_off + sizeof(int)]), MAX_STRING_SIZE, argp);
        if (sz > 0) {
            if (data->buf_off > (MAX_PERCPU_BUFSIZE) - sizeof(int))
                goto out;
            bpf_probe_read(&(data->submit_p->buf[data->buf_off]), sizeof(int), &sz);
            data->buf_off += sz + sizeof(int);
            elem_num++;
            continue;
        } else {
            goto out;
        }
    }
    char ellipsis[] = "...";
    if (data->buf_off > (MAX_PERCPU_BUFSIZE) - (MAX_STRING_SIZE) - sizeof(int))
        goto out;
    int sz = bpf_probe_read_str(&(data->submit_p->buf[data->buf_off + sizeof(int)]), MAX_STRING_SIZE, ellipsis);
    if (sz > 0) {
        if (data->buf_off > (MAX_PERCPU_BUFSIZE) - sizeof(int))
            goto out;
        bpf_probe_read(&(data->submit_p->buf[data->buf_off]), sizeof(int), &sz);
        data->buf_off += sz + sizeof(int);
        elem_num++;
    }
out:
    data->submit_p->buf[orig_off & ((MAX_PERCPU_BUFSIZE)-1)] = elem_num;
    data->context.argnum++;
    return 1;
}

static __always_inline int get_pid_tree(struct task_struct *task, int limit) {
    /* Data structure: [count][str1 len][str1][str2 len][str2]... */
    struct task_struct *task;
    struct task_struct *old_task;
    char * pid_tree;

    #pragma unroll
    for ( int i = 0; i < limit; i++ ) {
        
    }
}

/* init_context */
static __always_inline int init_context(context_t *context, struct task_struct *task) {
    // 获取 timestamp
    struct task_struct * realparent;
    bpf_probe_read(&realparent, sizeof(realparent), &task->real_parent);
    bpf_probe_read(&context->ppid, sizeof(context->ppid), &realparent->pid);
    context->ts = bpf_ktime_get_ns();
    // 填充 id 相关信息
    u64 id = bpf_get_current_uid_gid();
    context->uid = id;
    context->gid = id >> 32;
    id = bpf_get_current_pid_tgid();
    context->pid = id;
    context->tid = id >> 32;
    context->cgroup_id = bpf_get_current_cgroup_id();
    // 读取 cred 下, 填充 id
    struct cred *cred;
    // 有三个 ptracer_cred, real_cred, cred, 看kernel代码即可
    bpf_probe_read(&cred, sizeof(cred), &task->real_cred);
    bpf_probe_read(&context->euid, sizeof(context->euid), &cred->euid);

    // 容器相关信息
    struct nsproxy *nsp;
    struct uts_namespace *uts_ns;
    bpf_probe_read(&nsp, sizeof(nsp), &task->nsproxy);
    bpf_probe_read(&uts_ns, sizeof(uts_ns), &nsp->uts_ns);
    bpf_probe_read_str(&context->nodename, sizeof(context->nodename), &uts_ns->name.nodename);
    bpf_probe_read(&context->uts_inum, sizeof(context->uts_inum), &uts_ns->ns.inum);
    bpf_probe_read(&nsp, sizeof(nsp), &realparent->nsproxy);
    bpf_probe_read(&uts_ns, sizeof(uts_ns), &nsp->uts_ns);
    bpf_probe_read(&context->parent_uts_inum, sizeof(context->parent_uts_inum), &uts_ns->ns.inum);

    // ssh 相关信息, tty
    // 参考 https://github.com/Gui774ume/ssh-probe/blob/26b6f0b38bf7707a5f7f21444917ed2760766353/ebpf/utils/process.h
    // ttyname
    struct signal_struct *signal;
    bpf_probe_read(&signal, sizeof(signal), &task->signal);
    struct tty_struct *tty;
    bpf_probe_read(&tty, sizeof(tty), &signal->tty);
    bpf_probe_read_str(&context->ttyname, sizeof(context->ttyname), &tty->name);
    
    // sessionid
    bpf_probe_read(&context->sessionid, sizeof(context->sessionid), &task->sessionid);

    struct pid_cache_t * parent = bpf_map_lookup_elem(&pid_cache_lru, &context->pid);
    if( parent ) {
        // 防止未知的 fallback 情况, 参考 issue 提问
        if (context->ppid == 0) {
            bpf_probe_read(&context->ppid, sizeof(context->ppid), &parent->ppid);
        }
        bpf_probe_read(&context->pcomm, sizeof(context->pcomm), &parent->pcomm);
    }
    bpf_get_current_comm(&context->comm, sizeof(context->comm));
    context->argnum = 0;
    return 0;
}
