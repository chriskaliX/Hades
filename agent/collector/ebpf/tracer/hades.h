#include <linux/sched.h>

#include "common.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"

#define MAX_STR_SIZE 128
#define MAX_PERCPU_BUFSIZE 1 << 14
#define MAX_STRING_SIZE 512

typedef struct string_ {
    char str[MAX_STR_SIZE];
} string_t;

#define BPF_MAP(_name, _type, _key_type, _value_type, _max_entries)     \
    struct bpf_map_def SEC("maps") _name = {                            \
        .type = _type,                                                  \
        .key_size = sizeof(_key_type),                                  \
        .value_size = sizeof(_value_type),                              \
        .max_entries = _max_entries,                                    \
    };

/* BPF MAP DEFINATION MICROS, MODIFIED WITH MAX_ENTRIES */
#define BPF_HASH(_name, _key_type, _value_type, _max_entries) \
    BPF_MAP(_name, BPF_MAP_TYPE_HASH, _key_type, _value_type, _max_entries)
#define BPF_LRU_HASH(_name, _key_type, _value_type) \
    BPF_MAP(_name, BPF_MAP_TYPE_LRU_HASH, _key_type, _value_type, _max_entries)


/* filters */
// filter for argv with contains
BPF_HASH(argv_filter, string_t, u32, 32);
// filter for path
BPF_HASH(path_filter, string_t, u32, 32);
// sha256 filter?

/* allow */
// allow filter for envp
BPF_HASH(envp_allow, string_t, u32, 16);

/* storage */
BPF_LRU_HASH(process_tree_map, u32, string_t, 2048);

/* SAVE ENVP */
static __always_inline int save_str_envp_to_buf(event_data_t *data, const char __user *const __user *ptr, u8 index)
{
    // Data saved to submit buf: [index][string count][str1 size][str1][str2 size][str2]...
    u8 elem_num = 0;
    // Save argument index
    data->submit_p->buf[(data->buf_off) & ((MAX_PERCPU_BUFSIZE)-1)] = index;

    // Save space for number of elements (1 byte)
    u32 orig_off = data->buf_off+1;
    data->buf_off += 2;

    #pragma unroll
    for (int i = 0; i < MAX_STR_ARR_ELEM; i++) {
        const char *argp = NULL;
        bpf_probe_read(&argp, sizeof(argp), &ptr[i]);
        if (!argp)
            goto out;

        if (data->buf_off > (MAX_PERCPU_BUFSIZE) - (MAX_STRING_SIZE) - sizeof(int))
            // not enough space - return
            goto out;

        /*  */

        // Read into buffer
        int sz = bpf_probe_read_str(&(data->submit_p->buf[data->buf_off + sizeof(int)]), MAX_STRING_SIZE, argp);
        if (sz > 0) {
            if (data->buf_off > (MAX_PERCPU_BUFSIZE) - sizeof(int))
                // Satisfy validator
                goto out;
            bpf_probe_read(&(data->submit_p->buf[data->buf_off]), sizeof(int), &sz);
            data->buf_off += sz + sizeof(int);
            elem_num++;
            continue;
        } else {
            goto out;
        }
    }
    // handle truncated argument list
    char ellipsis[] = "...";
    if (data->buf_off > (MAX_PERCPU_BUFSIZE) - (MAX_STRING_SIZE) - sizeof(int))
        // not enough space - return
        goto out;

    // Read into buffer
    int sz = bpf_probe_read_str(&(data->submit_p->buf[data->buf_off + sizeof(int)]), MAX_STRING_SIZE, ellipsis);
    if (sz > 0) {
        if (data->buf_off > (MAX_PERCPU_BUFSIZE) - sizeof(int))
            // Satisfy validator
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