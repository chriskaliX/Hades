#include <linux/sched.h>

#include "common.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"

#define MAX_STR_SIZE 128

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