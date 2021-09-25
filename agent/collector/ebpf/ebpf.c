#include <linux/bpf.h>
#include "bpf_helpers.h"

// helper functions
// maps
// clang -(llvm)-> ebpf obj -(load)-> libbpf

// section
SEC("kprobe/sys_execve")
int hello(void *ctx) 
{
    bpf_printk("Hello");
    return 0;
}