#include "common.h"
#include "headers/bpf_helpers.h"

// helper functions
// maps
// clang -(llvm)-> ebpf obj -(load)-> libbpf

// 定义map
struct bpf_map_def SEC("maps") kprobe_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u64),
    .max_entries = 1,
};

// section
SEC("kprobe/sys_execve")
int hello(void *ctx) 
{
    bpf_printk("Hello");
    return 0;
}