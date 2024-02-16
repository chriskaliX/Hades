#ifndef __MAPS_H__
#define __MAPS_H__

#include <vmlinux.h>
#include <missing_definitions.h>

#include "types.h"
#include "consts.h"
#include "bpf_core_read.h"
#include "bpf_helpers.h"

/* map macro defination */
#define BPF_MAP(_name, _type, _key_type, _value_type, _max_entries)            \
    struct {                                                                   \
        __uint(type, _type);                                                   \
        __uint(max_entries, _max_entries);                                     \
        __type(key, _key_type);                                                \
        __type(value, _value_type);                                            \
    } _name SEC(".maps");

#define BPF_MAP_NO_KEY(_name, _type, _value_type, _max_entries)                \
    struct {                                                                   \
        __uint(type, _type);                                                   \
        __uint(max_entries, _max_entries);                                     \
        __type(value, _value_type);                                            \
    } _name SEC(".maps");

#define BPF_HASH(_name, _key_type, _value_type, _max_entries)                  \
    BPF_MAP(_name, BPF_MAP_TYPE_HASH, _key_type, _value_type, _max_entries)
#define BPF_LRU_HASH(_name, _key_type, _value_type, _max_entries)              \
    BPF_MAP(_name, BPF_MAP_TYPE_LRU_HASH, _key_type, _value_type, _max_entries)
#define BPF_LPM_TRIE(_name, _key_type, _value_type, _max_entries)              \
    BPF_MAP(_name, BPF_MAP_TYPE_LPM_TRIE, _key_type, _value_type, _max_entries)
#define BPF_ARRAY(_name, _value_type, _max_entries)                            \
    BPF_MAP(_name, BPF_MAP_TYPE_ARRAY, __u32, _value_type, _max_entries)
#define BPF_PERCPU_ARRAY(_name, _value_type, _max_entries)                     \
    BPF_MAP(_name, BPF_MAP_TYPE_PERCPU_ARRAY, __u32, _value_type, _max_entries)
#define BPF_PROG_ARRAY(_name, _max_entries)                                    \
    BPF_MAP(_name, BPF_MAP_TYPE_PROG_ARRAY, __u32, __u32, _max_entries)
#define BPF_PERF_OUTPUT(_name, _max_entries)                                   \
    BPF_MAP(_name, BPF_MAP_TYPE_PERF_EVENT_ARRAY, int, __u32, _max_entries)
#define BPF_PERCPU_HASH(_name, _max_entries)                                   \
    BPF_MAP(_name, BPF_MAP_TYPE_PERCPU_HASH, int, int, _max_entries)
#define BPF_SOCKHASH(_name, _key_type, _value_type, _max_entries)              \
    BPF_MAP(_name, BPF_MAP_TYPE_SOCKHASH, _key_type, _value_type, _max_entries)
#define BPF_RINGBUF_OUTPUT(_name, _key_type, _value_type, _max_entries)        \
    BPF_MAP(_name, BPF_MAP_TYPE_RINGBUF, _key_type, _value_type, _max_entries)

/* maps defination */
BPF_PERF_OUTPUT(events, 1024);
BPF_PERCPU_ARRAY(bufs, buf_t, MAX_BUFFERS);
BPF_LRU_HASH(proc_info_cache, pid_t, struct proc_info, 10240);
BPF_HASH(pid_filter, u32, u32, 512);

#endif