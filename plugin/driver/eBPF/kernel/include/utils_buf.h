#ifndef __UTILS_BUF_H
#define __UTILS_BUF_H
/* buf related function */
#include "bpf_helpers.h"
#include "bpf_core_read.h"
#include "define.h"
#include "helpers.h"
#include <linux/sched.h>

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
        // Read into buffer
        int sz = bpf_probe_read_str(&(data->submit_p->buf[data->buf_off + 1 + sizeof(int)]), MAX_STRING_SIZE, ptr);
        if (sz > 0)
        {
            // Satisfy validator for probe read
            if ((data->buf_off + 1) > (MAX_PERCPU_BUFSIZE) - sizeof(int))
            {
                return 0;
            }
            __builtin_memcpy(&(data->submit_p->buf[data->buf_off + 1]), &sz, sizeof(int));
            data->buf_off += sz + sizeof(int) + 1;
            data->context.argnum++;
            return 1;
            // added for nothing, assume that this would never failed.
        }
    }
    return 0;
}

/*
 * @function: save pid_tree to buffer
 * @structure: [index][string count][pid1][str1 size][str1][pid2][str2 size][str2]
 * TODO: cache to speed up
 */
static __always_inline int save_pid_tree_to_buf(event_data_t *data, int limit, u8 index)
{
    u8 elem_num = 0;
    u32 pid;
    struct task_struct *task = data->task;

    data->submit_p->buf[(data->buf_off) & (MAX_PERCPU_BUFSIZE - 1)] = index;
    u32 orig_off = data->buf_off + 1;
    data->buf_off += 2;

    if (limit >= 12)
    {
        limit = 12;
    }

#pragma unroll
    for (int i = 0; i < limit; i++)
    {
        // check pid
        int flag = bpf_probe_read(&pid, sizeof(pid), &task->tgid);
        if (flag != 0)
            goto out;
        // trace until pid = 1
        if (pid == 0)
            goto out;
        if (data->buf_off > (MAX_PERCPU_BUFSIZE) - sizeof(int))
        {
            goto out;
        }
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
    return 1;
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

#endif //__UTILS_BUF_H