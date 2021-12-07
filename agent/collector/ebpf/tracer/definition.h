// #include "common.h"
// #include "bpf_helpers.h"
// #include "bpf_core_read.h"

// #define TASK_COMM_LEN 16
// #define FILENAME_LEN 32
// #define ARGV_LEN 128
// #define DEFAULT_MAXARGS 32
// #define BUFSIZE 4096
// #define MAX_STRING_SIZE 1 << 12
// #define MAX_PERCPU_BUFSIZE 1 << 12
// #define MAX_BUFFERS 3

// // context
// typedef struct event_context {
//     u64 ts;     // timestamp
//     u64 pns;    // 
//     u64 parent_pns; // 
//     u64 cid;    // cgroup_id
//     u32 type;   // type of struct
//     u32 pid;    // processid
//     u32 tid;    // thread id
//     u32 uid;    // user id
//     u32 gid;    // group id
//     u32 ppid;   // parent pid
//     u32 argsize;// arg size
//     char filename[FILENAME_LEN];   // file name
//     char comm[TASK_COMM_LEN];   // command
//     char pcomm[TASK_COMM_LEN];  // parent command
//     char args[MAX_STRING_SIZE]; // args
//     char nodename[65];          // uts_name
//     char ttyname[64];           // char name[64];
//     char cwd[40];               // TODO: 合适的 length
//     // stdin
//     // stout
// } context_t;

// typedef struct simple_buf {
//     u8 buf[MAX_PERCPU_BUFSIZE];
// } buf_t;

// typedef struct event_data {
//     struct task_struct *task;
//     context_t context;
//     void *ctx;
//     buf_t *submit_p;
//     u32 buf_off;
// } event_data_t;

// // for breaking the limitation of 512 stack while using perf_event_output
// struct bpf_map_def SEC("maps") bufs = {
//     .type = BPF_MAP_TYPE_PERCPU_ARRAY,
//     .key_size = sizeof(u32),
//     .value_size = sizeof(struct buf_t),
//     .max_entries = MAX_BUFFERS,
// };

// struct bpf_map_def SEC("maps") exec_events = {
//     .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
//     .key_size = sizeof(int),
//     .value_size = sizeof(u32),
// };

// struct bpf_map_def SEC("maps") file_events = {
//     .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
//     .key_size = sizeof(int),
//     .value_size = sizeof(u32),
// };

// struct bpf_map_def SEC("maps") net_events = {
//     .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
//     .key_size = sizeof(int),
//     .value_size = sizeof(u32),
// };

// // function definition start
// // reading str arr to buffer
// static __always_inline int save_str_arr_to_buf(event_data_t *data, const char __user *const __user *ptr, u8 index)
// {
//     // Data saved to submit buf: [index][string count][str1 size][str1][str2 size][str2]...

//     u8 elem_num = 0;

//     // Save argument index
//     data->submit_p->buf[(data->buf_off) & (MAX_PERCPU_BUFSIZE-1)] = index;

//     // Save space for number of elements (1 byte)
//     u32 orig_off = data->buf_off+1;
//     data->buf_off += 2;

//     #pragma unroll
//     for (int i = 0; i < MAX_STR_ARR_ELEM; i++) {
//         const char *argp = NULL;
//         bpf_probe_read(&argp, sizeof(argp), &ptr[i]);
//         if (!argp)
//             goto out;

//         if (data->buf_off > MAX_PERCPU_BUFSIZE - MAX_STRING_SIZE - sizeof(int))
//             // not enough space - return
//             goto out;

//         // Read into buffer
//         int sz = bpf_probe_read_str(&(data->submit_p->buf[data->buf_off + sizeof(int)]), MAX_STRING_SIZE, argp);
//         if (sz > 0) {
//             if (data->buf_off > MAX_PERCPU_BUFSIZE - sizeof(int))
//                 // Satisfy validator
//                 goto out;
//             bpf_probe_read(&(data->submit_p->buf[data->buf_off]), sizeof(int), &sz);
//             data->buf_off += sz + sizeof(int);
//             elem_num++;
//             continue;
//         } else {
//             goto out;
//         }
//     }
//     // handle truncated argument list
//     char ellipsis[] = "...";
//     if (data->buf_off > MAX_PERCPU_BUFSIZE - MAX_STRING_SIZE - sizeof(int))
//         // not enough space - return
//         goto out;

//     // Read into buffer
//     int sz = bpf_probe_read_str(&(data->submit_p->buf[data->buf_off + sizeof(int)]), MAX_STRING_SIZE, ellipsis);
//     if (sz > 0) {
//         if (data->buf_off > MAX_PERCPU_BUFSIZE - sizeof(int))
//             // Satisfy validator
//             goto out;
//         bpf_probe_read(&(data->submit_p->buf[data->buf_off]), sizeof(int), &sz);
//         data->buf_off += sz + sizeof(int);
//         elem_num++;
//     }
// out:
//     // save number of elements in the array
//     data->submit_p->buf[orig_off & (MAX_PERCPU_BUFSIZE-1)] = elem_num;
//     data->context.argnum++;
//     return 1;
// }