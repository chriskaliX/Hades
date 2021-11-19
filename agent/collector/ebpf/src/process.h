#include "vmlinux.h"
#include "bpf_helpers.h"

#define TASK_COMM_LEN 16

struct process_cache_t {
    u64 cid;
    u32 pid;
    u32 ppid;
    u32 tid;
    char comm[TASK_COMM_LEN];
};

// build pidtree with BPF LRU, include docker
struct bpf_map_def SEC("maps/pid_cache") pid_cache = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(struct process_cache_t),
    .max_entries = 4096,
};