#ifndef __UTILS_BUF_H
#define __UTILS_BUF_H
/* buf related function */
#include "bpf_helpers.h"
#include "bpf_core_read.h"
#include "define.h"
#include "helpers.h"

#ifndef CORE
#include <linux/sched.h>
#else
#include <vmlinux.h>
#include <missing_definitions.h>
#endif

/*
 * @function: save str array to buffer
 * @structure: [index][string count][str1 size][str1][str2 siza][str2]...
 */
static __always_inline int save_str_arr_to_buf(event_data_t *data, const char __user *const __user *ptr, u8 index)
{
    u8 elem_num = 0;
    data->submit_p->buf[(data->buf_off) & (MAX_PERCPU_BUFSIZE - 1)] = index;
    u32 orig_off = data->buf_off + 1;
    data->buf_off += 2;
#pragma unroll
    for (int i = 0; i < MAX_STR_ARR_ELEM; i++)
    {
        const char *argp = NULL;
        bpf_probe_read(&argp, sizeof(argp), &ptr[i]);
        if (!argp)
            goto out;
        if (data->buf_off > (MAX_PERCPU_BUFSIZE) - (MAX_STRING_SIZE) - sizeof(int))
            goto out;
        int sz = bpf_probe_read_str(&(data->submit_p->buf[data->buf_off + sizeof(int)]), MAX_STRING_SIZE, argp);
        if (sz > 0)
        {
            if (data->buf_off > (MAX_PERCPU_BUFSIZE) - sizeof(int))
                goto out;
            bpf_probe_read(&(data->submit_p->buf[data->buf_off]), sizeof(int), &sz);
            data->buf_off += sz + sizeof(int);
            elem_num++;
            continue;
        }
        else
        {
            goto out;
        }
    }
    /* truncate rather than read ... */
out:
    data->submit_p->buf[orig_off & ((MAX_PERCPU_BUFSIZE)-1)] = elem_num;
    data->context.argnum++;
    return 1;
}
/*
 * @function: save str envp array to buffer
 * @structure: [index][string count][str1 size][str1][str2 siza][str2]...
 */
static __always_inline int save_envp_to_buf(event_data_t *data, const char __user *const __user *ptr, u8 index)
{
    // Data saved to submit buf: [index][string count][str1 size][str1][str2 size][str2]...
    u8 elem_num = 0;
    data->submit_p->buf[(data->buf_off) & ((MAX_PERCPU_BUFSIZE)-1)] = index;
    // Save space for number of elements (1 byte): [string count]
    u32 orig_off = data->buf_off + 1;
    // update the buf_off
    data->buf_off += 2;
    // flags for collection
    int ssh_connection_flag = 0, ld_preload_flag = 0, ld_library_path_flag = 0, tmp_flag = 0;
/* Bounded loops are available starting with Linux 5.3, so we had to unroll the for loop at compile time */
#pragma unroll
    for (int i = 0; i < MAX_STR_ARR_ELEM; i++)
    {
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
        if (sz > 0)
        {
            if (data->buf_off > (MAX_PERCPU_BUFSIZE) - sizeof(int) - (MAX_STRING_SIZE))
                goto out;
            // Add & ((MAX_PERCPU_BUFSIZE)-1)] for verifier if the index is not checked
            if (ld_preload_flag == 0 && sz > 11 && prefix("LD_PRELOAD=", (char *)&data->submit_p->buf[data->buf_off + sizeof(int)], 11))
            {
                ld_preload_flag = 1;
                tmp_flag = 1;
            }

            if (ssh_connection_flag == 0 && sz > 15 && prefix("SSH_CONNECTION=", (char *)&data->submit_p->buf[data->buf_off + sizeof(int)], 15))
            {
                ssh_connection_flag = 1;
                tmp_flag = 1;
            }

            if (ld_library_path_flag == 0 && sz > 16 && prefix("LD_LIBRARY_PATH=", (char *)&data->submit_p->buf[data->buf_off + sizeof(int)], 16))
            {
                ld_library_path_flag = 1;
                tmp_flag = 1;
            }

            if (tmp_flag == 0)
            {
                continue;
            }
            else
            {
                tmp_flag = 0;
            }

            bpf_probe_read(&(data->submit_p->buf[data->buf_off]), sizeof(int), &sz);
            data->buf_off += sz + sizeof(int);
            elem_num++;
            continue;
        }
        else
        {
            goto out;
        }
    }
out:
    data->submit_p->buf[orig_off & ((MAX_PERCPU_BUFSIZE)-1)] = elem_num;
    data->context.argnum++;
    return 1;
}

static __always_inline int save_u64_arr_to_buf(event_data_t *data, const u64 __user *ptr,int len , u8 index){
    // Data saved to submit buf: [index][u64 count][u64 1][u64 2][u64 3]...
    u8 elem_num = 0;
    // Save argument index
    data->submit_p->buf[(data->buf_off) & (MAX_PERCPU_BUFSIZE-1)] = index;
    // Save space for number of elements (1 byte)
    u32 orig_off = data->buf_off+1;
    data->buf_off += 2;

    #pragma unroll
    for (int i = 0; i < len; i++) {
        u64 element = 0;
        int err = bpf_probe_read(&element, sizeof(u64), &ptr[i]);
        if (err !=0)
            goto out;
        if (data->buf_off > MAX_PERCPU_BUFSIZE - sizeof(u64) )
                // not enough space - return
                goto out;

        void *addr = &(data->submit_p->buf[data->buf_off ]);
        int sz = bpf_probe_read(addr, sizeof(u64), (void *)&element);
        if (sz == 0) {
            elem_num++;
            if (data->buf_off > MAX_PERCPU_BUFSIZE )
                // Satisfy validator
                goto out;

            data->buf_off += sizeof(u64);
            continue;
        } else {
            goto out;
        }
    }
    goto out;
out:
    // save number of elements in the array
    data->submit_p->buf[orig_off & (MAX_PERCPU_BUFSIZE-1)] = elem_num;
    data->context.argnum++;
    return 1;

/*
 * @function: save str to buffer
 * @structure: [index][size][ ... string ... ]
 */
static __always_inline int save_str_to_buf(event_data_t *data, void *ptr, u8 index)
{
    // check the buf_off, to satisfy bpf verifier. And save index
    if (data->buf_off > (MAX_PERCPU_BUFSIZE) - (MAX_STRING_SIZE) - sizeof(int))
        return 0;
    data->submit_p->buf[(data->buf_off) & (MAX_PERCPU_BUFSIZE - 1)] = index;
    // Satisfy validator for probe read
    if ((data->buf_off + 1) <= (MAX_PERCPU_BUFSIZE) - (MAX_STRING_SIZE) - sizeof(int))
    {
        int sz = 0;
        // Read into buffer
        // (MAX_PERCPU_BUFSIZE - MAX_STRING_SIZE) just to make BPF verifier happy
        // added for nothing, assume that this would never failed.
        sz = bpf_probe_read_str(&(data->submit_p->buf[data->buf_off + 1 + sizeof(int)]), MAX_STRING_SIZE, ptr);
        if (sz < 0)
        {
            char nothing[] = "-1";
            // why check it again? nothing
            // just to make verifier happy, this will not happen
            if ((data->buf_off + 1) <= (MAX_PERCPU_BUFSIZE) - (MAX_STRING_SIZE) - sizeof(int)) {
                sz = bpf_probe_read_str(&(data->submit_p->buf[data->buf_off + 1 + sizeof(int)]), MAX_STRING_SIZE, nothing);
            }
        }
        if (sz > 0)
        {
            // just to make verifier happy, this will not happen
            if ((data->buf_off + 1) > (MAX_PERCPU_BUFSIZE) - sizeof(int))
                return 0;
            __builtin_memcpy(&(data->submit_p->buf[data->buf_off + 1]), &sz, sizeof(int));
            data->buf_off += sz + sizeof(int) + 1;
            data->context.argnum++;
            return 1;
        }
    }
    return 0;
}

/*
 * @function: save ptr(struct) to buffer
 * @structure: [index][buffer]
 */
static __always_inline int save_to_submit_buf(event_data_t *data, void *ptr, u32 size, u8 index)
{
// The biggest element that can be saved with this function should be defined here
#define MAX_ELEMENT_SIZE sizeof(struct sockaddr_un)
    // Data saved to submit buf: [index][ ... buffer[size] ... ]
    if (size == 0)
        return 0;

    // If we don't have enough space - return
    if (data->buf_off > MAX_PERCPU_BUFSIZE - (size + 1))
        return 0;

    // Save argument index
    volatile int buf_off = data->buf_off;
    data->submit_p->buf[buf_off & (MAX_PERCPU_BUFSIZE - 1)] = index;

    // Satisfy validator for probe read
    if ((data->buf_off + 1) <= MAX_PERCPU_BUFSIZE - MAX_ELEMENT_SIZE)
    {
        // Read into buffer
        if (bpf_probe_read(&(data->submit_p->buf[data->buf_off + 1]), size, ptr) == 0)
        {
            // We update buf_off only if all writes were successful
            data->buf_off += size + 1;
            data->context.argnum++;
            return 1;
        }
    }
    return 0;
}

// thiner than tracee. It's all we need now
typedef struct slim_cred {
    uid_t  uid;                    // real UID of the task
    gid_t  gid;                    // real GID of the task
    uid_t  suid;                   // saved UID of the task
    gid_t  sgid;                   // saved GID of the task
    uid_t  euid;                   // effective UID of the task
    gid_t  egid;                   // effective GID of the task
    uid_t  fsuid;                  // UID for VFS ops
    gid_t  fsgid;                  // GID for VFS ops
} slim_cred_t;

/*
 * @function: save pid_tree to buffer
 * @structure: [index][string count][pid1][str1 size][str1][pid2][str2 size][str2]
 */
// In Elkeid, a privilege escalation detection is added by checking the creds
// in here. And also, pid of socket is added in here.
// Working on creds check
static __always_inline int save_pid_tree_to_buf(event_data_t *data, int limit, u8 index)
{
    u8 elem_num = 0;
    u8 privilege_flag = 0;
    u32 pid;
    int flag;

    struct task_struct *task = data->task;
    // add creds check here
    // pay attention that here are three cred in task_struct
    struct cred *current_cred = (struct cred *)READ_KERN(task->real_cred);
    struct cred *parent_cred = NULL;

    data->submit_p->buf[(data->buf_off) & (MAX_PERCPU_BUFSIZE - 1)] = index;
    u32 orig_off = data->buf_off + 1;
    data->buf_off += 2;
    // hard code the limit
    if (limit >= 12)
        limit = 12;
#pragma unroll
    for (int i = 0; i < limit; i++)
    {
        pid = READ_KERN(task->tgid);
        // trace until pid = 1
        if (pid == 0)
            goto out;
        // 2022-03-28TODO: add cred check here:
        // skip 0, only 1 & 2 are readed.
        if (((i == 1) || (i == 2)) && (privilege_flag == 0))
        {
            parent_cred = (struct cred *)READ_KERN(task->real_cred);
            // check here
            privilege_flag = check_cred(current_cred, parent_cred);
            // does verifier supports this? In Elkeid
            current_cred = parent_cred;
        }

        if (data->buf_off > (MAX_PERCPU_BUFSIZE) - sizeof(int))
            goto out;
        // read pid to buffer firstly
        flag = bpf_probe_read(&(data->submit_p->buf[data->buf_off]), sizeof(int), &pid);
        if (flag != 0)
            goto out;
        // read comm
        if (data->buf_off >= (MAX_PERCPU_BUFSIZE) - (TASK_COMM_LEN) - sizeof(int) - sizeof(int))
            goto out;
        int sz = bpf_probe_read_str(&(data->submit_p->buf[data->buf_off + sizeof(int) + sizeof(int)]), TASK_COMM_LEN, &task->comm);
        if (sz > 0)
        {
            if (data->buf_off > (MAX_PERCPU_BUFSIZE) - sizeof(int) - sizeof(int))
                goto out;
            bpf_probe_read(&(data->submit_p->buf[data->buf_off + sizeof(int)]), sizeof(int), &sz);
            data->buf_off += sz + sizeof(int) + sizeof(int);
            elem_num++;
            flag = bpf_probe_read(&task, sizeof(task), &task->real_parent);
            if (flag != 0)
                goto out;
            continue;
        }
        else
        {
            goto out;
        }
    }
out:
    data->submit_p->buf[orig_off & ((MAX_PERCPU_BUFSIZE)-1)] = elem_num;
    data->context.argnum++;
    // add the logic of privilege escalation
    data->submit_p->buf[(data->buf_off) & (MAX_PERCPU_BUFSIZE - 1)] = privilege_flag;
    data->buf_off += 1;
    if(privilege_flag)
    {
        slim_cred_t slim = {0};
        slim.uid = READ_KERN(current_cred->uid.val);
        slim.gid = READ_KERN(current_cred->gid.val);
        slim.suid = READ_KERN(current_cred->suid.val);
        slim.sgid = READ_KERN(current_cred->sgid.val);
        slim.euid = READ_KERN(current_cred->euid.val);
        slim.egid = READ_KERN(current_cred->egid.val);
        slim.fsuid = READ_KERN(current_cred->fsuid.val);
        slim.fsgid = READ_KERN(current_cred->fsgid.val);
        // this index maybe misleading...but anyway
        save_to_submit_buf(data, (void*)&slim, sizeof(slim_cred_t), index);
        slim.uid = READ_KERN(parent_cred->uid.val);
        slim.gid = READ_KERN(parent_cred->gid.val);
        slim.suid = READ_KERN(parent_cred->suid.val);
        slim.sgid = READ_KERN(parent_cred->sgid.val);
        slim.euid = READ_KERN(parent_cred->euid.val);
        slim.egid = READ_KERN(parent_cred->egid.val);
        slim.fsuid = READ_KERN(parent_cred->fsuid.val);
        slim.fsgid = READ_KERN(parent_cred->fsgid.val);
        save_to_submit_buf(data, (void*)&slim, sizeof(slim_cred_t), index);
    }
    return 1;
}


#endif //__UTILS_BUF_H