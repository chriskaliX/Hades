#include "common.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"
#include "define.h"
#include "helpers.h"
#include <linux/sched.h>

/* save envp to buf (with specific fields) */
// TODO: 后期改成动态的
/* R3 max value is outside of the array range */
// 这个地方非常非常的坑，都因为 bpf_verifier 机制, 之前 buf_off > MAX_PERCPU_BUFSIZE - sizeof(int) 本身都是成立的
// 前面明明有一个更为严格的 data->buf_off > (MAX_PERCPU_BUFSIZE) - (MAX_STRING_SIZE) - sizeof(int)，但是不行
// 在每次调 index 之前都需要 check 一下，所以看源码的时候很多地方会写：To satisfied the verifier...
// TODO: 写一个文章记录一下这个...

// TODO: 判断 kernel version, 使用 ringbuf, 传输优化

static __always_inline int save_envp_to_buf(event_data_t *data, const char __user *const __user *ptr, u8 index)
{
    // Data saved to submit buf: [index][string count][str1 size][str1][str2 size][str2]...
    u8 elem_num = 0;
    data->submit_p->buf[(data->buf_off) & ((MAX_PERCPU_BUFSIZE)-1)] = index;
    // Save space for number of elements (1 byte): [string count]
    u32 orig_off = data->buf_off+1;
    // update the buf_off
    data->buf_off += 2;
    // flags for collection
    int ssh_connection_flag = 0, ld_preload_flag = 0, ld_library_path_flag = 0, tmp_flag = 0;
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
        /* read into buf & update the elem_num */
        int sz = bpf_probe_read_str(&(data->submit_p->buf[data->buf_off + sizeof(int)]), MAX_STRING_SIZE, argp);
        if (sz > 0) {
            if (data->buf_off > (MAX_PERCPU_BUFSIZE) - sizeof(int) - (MAX_STRING_SIZE))
                goto out;
            // Add & ((MAX_PERCPU_BUFSIZE)-1)] for verifier if the index is not checked
            if (ld_preload_flag == 0 && sz > 11 && prefix("LD_PRELOAD=",(char*)&data->submit_p->buf[data->buf_off + sizeof(int)], 11)) {
                ld_preload_flag = 1;
                tmp_flag = 1;
            }

            if (ssh_connection_flag == 0 && sz > 15 && prefix("SSH_CONNECTION=",(char*)&data->submit_p->buf[data->buf_off + sizeof(int)], 15)) {
                ssh_connection_flag = 1;
                tmp_flag = 1;
            }

            if (ld_library_path_flag == 0 && sz > 16 && prefix("LD_LIBRARY_PATH=",(char*)&data->submit_p->buf[data->buf_off + sizeof(int)], 16)) {
                ld_library_path_flag = 1;
                tmp_flag = 1;
            }

            if (tmp_flag == 0) {
                continue;
            } else {
                tmp_flag = 0;
            }

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

static __always_inline int save_str_to_buf(event_data_t *data, void *ptr, u8 index)
{
    // Data saved to submit buf: [index][size][ ... string ... ]
    // If we don't have enough space - return
    if (data->buf_off > (MAX_PERCPU_BUFSIZE) - (MAX_STRING_SIZE) - sizeof(int))
        return 0;
    // Save argument index
    data->submit_p->buf[(data->buf_off) & ((MAX_PERCPU_BUFSIZE)-1)] = index;
    // Satisfy validator for probe read
    if ((data->buf_off+1) <= (MAX_PERCPU_BUFSIZE) - (MAX_STRING_SIZE) - sizeof(int)) {
        // Read into buffer
        int sz = bpf_probe_read_str(&(data->submit_p->buf[data->buf_off+1+sizeof(int)]), MAX_STRING_SIZE, ptr);
        if (sz > 0) {
            // Satisfy validator for probe read
            if ((data->buf_off+1) > (MAX_PERCPU_BUFSIZE) - sizeof(int)) {
                return 0;
            }
            __builtin_memcpy(&(data->submit_p->buf[data->buf_off+1]), &sz, sizeof(int));
            data->buf_off += sz + sizeof(int) + 1;
            data->context.argnum++;
            return 1;
        }
    }
    return 0;
}

static __always_inline int save_pid_tree_to_buf(event_data_t *data, int limit, u8 index) {
    // Data saved to submit buf: [index][size][ ... string ... ]
    // 2022-01-09: change to array -> [index][string count][pid1][str1 size][str1][pid2][str2 size][str2]
    // char sparate = '<';
    const char connector = '.';
    // save 1 length for \0
    struct task_struct *task = data->task;
    int length = TASK_COMM_LEN + sizeof(char) + sizeof(u32);
    // we read pid+connector+pid_comm firstly
    if (data->buf_off > (MAX_PERCPU_BUFSIZE) - (length) - sizeof(int))
        return 0;
    // Save argument index
    data->submit_p->buf[(data->buf_off) & ((MAX_PERCPU_BUFSIZE)-1)] = index;
    if ((data->buf_off+1) <= (MAX_PERCPU_BUFSIZE) - (length) - sizeof(int)){
        // according to bcc's markdown, the mininum kernel version for bpf_snprintf is 5.13...not a good choice I think
        int flag = bpf_probe_read(&(data->submit_p->buf[data->buf_off+1+sizeof(int)]), sizeof(u32), &task->tgid);
        if (flag != 0) 
            return 0;
        if (data->buf_off > (MAX_PERCPU_BUFSIZE) - (length) - sizeof(int))
            return 0;
        flag = bpf_probe_read(&(data->submit_p->buf[data->buf_off+1+sizeof(int)+sizeof(u32)]), sizeof(char), &connector);
        if (flag != 0)
            return 0;
        if (data->buf_off > (MAX_PERCPU_BUFSIZE) - (length) - sizeof(int) - 1)
            return 0;
        int sz = bpf_probe_read_str(&(data->submit_p->buf[data->buf_off+1+sizeof(int)+sizeof(u32)+sizeof(char)]), TASK_COMM_LEN, &task->comm);
        if (sz > 0) {
            if ((data->buf_off+1) > (MAX_PERCPU_BUFSIZE) - sizeof(int))
                return 0;
            sz = sz + sizeof(u32) + sizeof(char);
            __builtin_memcpy(&(data->submit_p->buf[data->buf_off+1]), &sz, sizeof(int));
            data->buf_off += sz + sizeof(int) + 1;
            data->context.argnum++;
            return 1;
        }
    }
    return 0;
}

static __always_inline int save_pid_tree_new_to_buf(event_data_t *data, int limit, u8 index)
{
    // data: [index][string count][pid1][str1 size][str1][pid2][str2 size][str2]
    u8 elem_num = 0;
    data->submit_p->buf[(data->buf_off) & ((MAX_PERCPU_BUFSIZE)-1)] = index;
    u32 orig_off = data->buf_off+1;
    data->buf_off += 2;
    if (limit < 1 || limit >= 32) {
        return 0;
    }

    struct task_struct *task = data->task;
    u32 pid;

    #pragma unroll
    for (int i = 0; i < limit; i++) {
        // check pid
        int flag = bpf_probe_read(&pid, sizeof(pid), &task->tgid);
        if (flag != 0)
            goto out;
        if (pid == 0)
            goto out;
        if (data->buf_off > (MAX_PERCPU_BUFSIZE) - sizeof(int)) {
            goto out;
        }
        // read pid firstly
        flag = bpf_probe_read(&(data->submit_p->buf[data->buf_off]), sizeof(int), &pid);
        if (flag != 0)
            goto out;
        // read comm
        if (data->buf_off >= (MAX_PERCPU_BUFSIZE) - (TASK_COMM_LEN) - sizeof(int) - sizeof(int))
            goto out;
        int sz = bpf_probe_read_str(&(data->submit_p->buf[data->buf_off + sizeof(int) + sizeof(int)]), TASK_COMM_LEN, &task->comm);
        if (sz > 0) {
            if (data->buf_off > (MAX_PERCPU_BUFSIZE) - sizeof(int) - sizeof(int))
                goto out;
            bpf_probe_read(&(data->submit_p->buf[data->buf_off + sizeof(int)]), sizeof(int), &sz);
            data->buf_off += sz + sizeof(int) + sizeof(int);
            elem_num++;
            // task = task->real_parent;
            flag = bpf_probe_read(&task, sizeof(task), &task->real_parent);
            if (flag != 0)
                goto out;
            continue;
        } else {
            goto out;
        }
    }
out:
    data->submit_p->buf[orig_off & ((MAX_PERCPU_BUFSIZE)-1)] = elem_num;
    data->context.argnum++;
    return 1;
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

static __always_inline int init_event_data(event_data_t *data)
{
    data->task = (struct task_struct *)bpf_get_current_task();
    init_context(&data->context, data->task);
    data->buf_off = sizeof(context_t);
    int buf_idx = SUBMIT_BUF_IDX;
    data->submit_p = bpf_map_lookup_elem(&bufs, &buf_idx);
    if (data->submit_p == NULL)
        return 0;
    return 1;
}

static __always_inline void* get_path_str(struct path *path)
{
    struct path f_path;
    bpf_probe_read(&f_path, sizeof(struct path), path);
    char slash = '/';
    int zero = 0;
    struct dentry *dentry = f_path.dentry;
    struct vfsmount *vfsmnt = f_path.mnt;
    struct mount *mnt_parent_p;

    struct mount *mnt_p = real_mount(vfsmnt);
    bpf_probe_read(&mnt_parent_p, sizeof(struct mount*), &mnt_p->mnt_parent);

    u32 buf_off = (MAX_PERCPU_BUFSIZE >> 1);
    struct dentry *mnt_root;
    struct dentry *d_parent;
    struct qstr d_name;
    unsigned int len;
    unsigned int off;
    int sz;

    // Get per-cpu string buffer
    buf_t *string_p = get_buf(STRING_BUF_IDX);
    if (string_p == NULL)
        return NULL;

    #pragma unroll
    for (int i = 0; i < MAX_PATH_COMPONENTS; i++) {
        mnt_root = READ_KERN(vfsmnt->mnt_root);
        d_parent = READ_KERN(dentry->d_parent);
        if (dentry == mnt_root || dentry == d_parent) {
            if (dentry != mnt_root) {
                // We reached root, but not mount root - escaped?
                break;
            }
            if (mnt_p != mnt_parent_p) {
                // We reached root, but not global root - continue with mount point path
                bpf_probe_read(&dentry, sizeof(struct dentry*), &mnt_p->mnt_mountpoint);
                bpf_probe_read(&mnt_p, sizeof(struct mount*), &mnt_p->mnt_parent);
                bpf_probe_read(&mnt_parent_p, sizeof(struct mount*), &mnt_p->mnt_parent);
                vfsmnt = &mnt_p->mnt;
                continue;
            }
            // Global root - path fully parsed
            break;
        }
        // Add this dentry name to path
        d_name = READ_KERN(dentry->d_name);
        len = (d_name.len+1) & (MAX_STRING_SIZE-1);
        off = buf_off - len;

        // Is string buffer big enough for dentry name?
        sz = 0;
        if (off <= buf_off) { // verify no wrap occurred
            len = len & (((MAX_PERCPU_BUFSIZE) >> 1)-1);
            sz = bpf_probe_read_str(&(string_p->buf[off & (((MAX_PERCPU_BUFSIZE) >> 1)-1)]), len, (void *)d_name.name);
        }
        else
            break;
        if (sz > 1) {
            buf_off -= 1; // remove null byte termination with slash sign
            bpf_probe_read(&(string_p->buf[buf_off & ((MAX_PERCPU_BUFSIZE)-1)]), 1, &slash);
            buf_off -= sz - 1;
        } else {
            // If sz is 0 or 1 we have an error (path can't be null nor an empty string)
            break;
        }
        dentry = d_parent;
    }

    if (buf_off == (MAX_PERCPU_BUFSIZE >> 1)) {
        // memfd files have no path in the filesystem -> extract their name
        buf_off = 0;
        d_name = READ_KERN(dentry->d_name);
        bpf_probe_read_str(&(string_p->buf[0]), MAX_STRING_SIZE, (void *)d_name.name);
    } else {
        // Add leading slash
        buf_off -= 1;
        bpf_probe_read(&(string_p->buf[buf_off & ((MAX_PERCPU_BUFSIZE)-1)]), 1, &slash);
        // Null terminate the path string
        bpf_probe_read(&(string_p->buf[((MAX_PERCPU_BUFSIZE) >> 1)-1]), 1, &zero);
    }

    set_buf_off(STRING_BUF_IDX, buf_off);
    return &string_p->buf[buf_off];
}