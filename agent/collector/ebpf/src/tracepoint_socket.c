#include "vmlinux.h"
#include "bpf_helpers.h"

#define TASK_COMM_LEN 16

struct bpf_map_def SEC("maps") perf_events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
};

struct netevent_t {
    uint64_t pid;
    uint64_t ts;
    char comm[TASK_COMM_LEN];
    uint64_t fd;
    uint64_t uid;
    uint16_t port;
    uint32_t address;
    uint32_t family;
};

// /sys/kernel/debug/tracing/events/syscalls/sys_enter_connect/format
struct enter_connect_t {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    int __syscall_nr;
    int fd;
    struct sockaddr * uservaddr;
    int addrlen;
};


SEC("tracepoint/syscalls/sys_enter_connect")
int enter_connect(struct enter_connect_t *ctx) {
    // 定义返回数据
    struct netevent_t netevent = {};
    bpf_get_current_comm(&netevent.comm, sizeof(netevent.comm));

    struct sockaddr address;
    bpf_probe_read(&address, sizeof(address), &ctx->uservaddr);
    bpf_probe_read_user(&netevent.family, sizeof(netevent.family), &address.sa_family);

    struct sockaddr_in *addr = (struct sockaddr_in *) &address;
    bpf_probe_read_user(&netevent.address, sizeof(netevent.address), &addr->sin_addr.s_addr);
    bpf_probe_read_user(&netevent.port, sizeof(netevent.port), &addr->sin_port);
    bpf_perf_event_output(ctx, &perf_events, BPF_F_CURRENT_CPU, &netevent, sizeof(netevent));
    return 0;
}

char LICENSE[] SEC("license") = "GPL";