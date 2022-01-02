#include "common.h"

#define TASK_COMM_LEN 16
#define MAX_STR_FILTER_SIZE 128
#define MAX_PERCPU_BUFSIZE 1 << 14
#define MAX_STRING_SIZE 256
#define MAX_STR_ARR_ELEM 32

/* ========== MAP MICRO DEFINATION ========== */
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
/* ========== STRUCT FIELD DEFINITION ==========*/
/* buf_t that we used in event_data_t */
typedef struct simple_buf {
    u8 buf[MAX_PERCPU_BUFSIZE];
} buf_t;

/* general context for all hook point */
typedef struct data_context {
    u64 ts;                     // timestamp
    u64 uts_inum;               // 
    u64 parent_uts_inum;        // 
    u64 cgroup_id;              // cgroup_id
    u32 type;                   // type of struct
    u32 pid;                    // processid
    u32 tid;                    // thread id
    u32 uid;                    // user id
    u32 euid;                   // effective user id
    u32 gid;                    // group id
    u32 ppid;                   // parent pid => which is tpid, pid is for the kernel space. In user space, it's tgid actually
    u32 sessionid;
    char comm[TASK_COMM_LEN];   // command
    char pcomm[TASK_COMM_LEN];  // parent command
    char nodename[64];          // uts_name => 64
    char ttyname[64];           // char name[64];
    u8  argnum;                 // argnum
} context_t;

/* general field for event */
typedef struct event_data {
    struct task_struct *task;   // current task_struct
    context_t context;          // context: general fields for all hooks
    buf_t *submit_p;
    u32 buf_off;                // offset of the buf_t
} event_data_t;

/* general field for filter string */
typedef struct string {
    char str[MAX_STR_FILTER_SIZE];
} string_t;

struct mnt_namespace {
    atomic_t        count;
    struct ns_common    ns;
    // ...
};

struct mount {
    struct hlist_node mnt_hash;
    struct mount *mnt_parent;
    struct dentry *mnt_mountpoint;
    struct vfsmount mnt;
    // ...
};

struct pid_cache_t {
    u32 ppid;
    char pcomm[MAX_STRING_SIZE];
};

/* filters that communicate with user_space prog */
BPF_ARRAY(path_filter, string_t, u32, 32);
BPF_HASH(pid_filter, u32, u32, 32);
BPF_HASH(cgroup_id_filter, u64, u32, 32);
/* for pid tree */
BPF_LRU_HASH(pid_cache_lru, u32, pid_cache_t, 1024);
/* BPF_PERF_OUTPUT */
BPF_PERF_OUTPUT(exec_events, int, u32, 1024);
BPF_PERF_OUTPUT(file_events, int, u32, 1024);
BPF_PERF_OUTPUT(net_events, int, u32, 1024);