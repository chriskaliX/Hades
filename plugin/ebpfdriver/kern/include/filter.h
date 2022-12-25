// filter.h contains kernel space filter with dynamic count
#ifndef __FILTER_H
#define __FILTER_H

#include "define.h"
#include <utils_buf.h>
#include "bpf_helpers.h"
#include "bpf_core_read.h"
#include "bpf_endian.h"

#define SECOND 1000000000
#define POLICY_PASS      0
#define POLICY_PERMANENT 1

typedef struct filter_data {
    u64 ts;
    u64 count;
} filter_data_t;

BPF_LRU_HASH(inner_filter, u64, filter_data_t, 20);
BPF_LRU_HASH(deny_filter, u64, int, 20);

// false - filtered
// true - pass
static __always_inline int hades_filter(u64 event_id, u64 limit, int policy)
{
    int *deny = bpf_map_lookup_elem(&deny_filter, &event_id);
    if (deny != NULL)
        return 0;
    filter_data_t *data = bpf_map_lookup_elem(&inner_filter, &event_id);
    // VERY FIRST TIME, new the map
    if (data == NULL){
        filter_data_t filter_data = {};
        filter_data.ts = bpf_ktime_get_ns();
        filter_data.count = 1;
        bpf_map_update_elem(&inner_filter, &event_id, &filter_data, BPF_ANY);
        return 1;
    }
    // check count and time
    u64 now = bpf_ktime_get_ns();
    // if over time, reset all
    if (now - data->ts > SECOND) {
        data->ts = now;
        data->count = 1;
        return 1;
    }
    // within time, check count
    if (data->count > limit) {
        if (policy == POLICY_PASS) {
            return 0;
        }
        int flag = 1;
        bpf_map_update_elem(&deny, &event_id, &flag, BPF_ANY);
        return 0;
    }
    data->count += 1;
    return 1;
}

#endif