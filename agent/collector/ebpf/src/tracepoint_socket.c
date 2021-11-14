#include "vmlinux.h"
#include "bpf_helpers.h"

#define TASK_COMM_LEN 16

struct bpf_map_def SEC("maps") perf_events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
};

struct netevent_t {
    u32 pid;
    u32 uid;
    u32 address;
    u32 addrlen;
    u16 family;
    u16 port;
    char comm[TASK_COMM_LEN];
};

// /sys/kernel/debug/tracing/events/syscalls/sys_enter_connect/format
/*
    前面一直都照抄写成int...导致debug了很久
    参考一下 linux 项目里带的 example
    https://github.com/torvalds/linux/tree/418baf2c28f3473039f2f7377760bd8f6897ae18/samples/bpf
*/
struct enter_connect_t {
    unsigned long long unused;
    long syscall_nr;
    long fd;
    // struct sockaddr* uservaddr;
    long uservaddr;
    long addrlen;
};

SEC("tracepoint/syscalls/sys_enter_connect")
int enter_connect(struct enter_connect_t *ctx) {
    // 定义返回数据
    struct netevent_t netevent = {};

    bpf_get_current_comm(&netevent.comm, sizeof(netevent.comm));
    // bpf_probe_read(&netevent.addrlen, sizeof(netevent.addrlen), &ctx->addrlen);

    struct sockaddr* address;
    address = (struct sockaddr *) ctx->uservaddr;
    bpf_probe_read_user(&netevent.family, sizeof(netevent.family), &address->sa_family);

    struct sockaddr_in *addr = (struct sockaddr_in *) address;
    bpf_probe_read_user(&netevent.address, sizeof(netevent.address), &addr->sin_addr.s_addr);
    bpf_probe_read_user(&netevent.port, sizeof(netevent.port), &addr->sin_port);
    bpf_perf_event_output(ctx, &perf_events, BPF_F_CURRENT_CPU, &netevent, sizeof(netevent));
    return 0;
}

char LICENSE[] SEC("license") = "GPL";