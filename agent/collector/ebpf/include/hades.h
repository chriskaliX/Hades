#include <linux/sched.h>

#include "common.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"

#define TASK_COMM_LEN 16
#define MAX_STR_FILTER_SIZE 128
#define MAX_PERCPU_BUFSIZE 1 << 14
#define MAX_STRING_SIZE 512
#define MAX_STR_ARR_ELEM 32

/* ========== struct definition ========== */
// general string field
typedef struct string_ {
    char str[MAX_STR_FILTER_SIZE];
} string_t;

// it's general field for all context, which we can get from task_struct, unrelated with hook point
typedef struct data_context {
    u64 ts;                     // timestamp
    u64 uts_inum;               // 
    u64 parent_uts_inum;        // 
    u64 cgroup_id;              // cgroup_id
    u32 type;                   // type of struct
    u32 pid;                    // processid
    u32 tid;                    // thread id
    u32 uid;                    // user id
    u32 gid;                    // group id
    u32 ppid;                   // parent pid => which is tpid...
    u32 sessionid;
    char comm[TASK_COMM_LEN];   // command
    char pcomm[TASK_COMM_LEN];  // parent command
    char nodename[64];          // uts_name => 64
    char ttyname[64];           // char name[64];
    u8  argnum;                 // argnum
} context_t;

/* ========== map micro definition ========== */
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
#define BPF_LRU_HASH(_name, _key_type, _value_type, _max_entries) \
    BPF_MAP(_name, BPF_MAP_TYPE_LRU_HASH, _key_type, _value_type, _max_entries)
#define BPF_ARRAY(_name, _value_type, _max_entries) \
    BPF_MAP(_name, BPF_MAP_TYPE_ARRAY, u32, _value_type, _max_entries)
#define BPF_PERCPU_ARRAY(_name, _value_type, _max_entries) \
    BPF_MAP(_name, BPF_MAP_TYPE_PERCPU_ARRAY, u32, _value_type, _max_entries)
#define BPF_PROG_ARRAY(_name, _max_entries) \
    BPF_MAP(_name, BPF_MAP_TYPE_PROG_ARRAY, u32, u32, _max_entries)
#define BPF_PERF_OUTPUT(_name, _max_entries) \
    BPF_MAP(_name, BPF_MAP_TYPE_PERF_EVENT_ARRAY, int, __u32, _max_entries)

/* ========== filters ========== */
// filter for argv with contains
BPF_HASH(argv_filter, string_t, u32, 32);
// filter for path
BPF_HASH(path_filter, string_t, u32, 32);

/* storage */
BPF_LRU_HASH(process_tree_map, u32, string_t, 2048);

