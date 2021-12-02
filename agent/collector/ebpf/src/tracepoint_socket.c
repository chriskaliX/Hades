#include "vmlinux.h"
#include "bpf_helpers.h"

#define TASK_COMM_LEN 16
#define PATH_LEN 32

struct bpf_map_def SEC("maps") perf_events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
};

// 借鉴 osquery 的表把数据补全
struct netevent_t {
    u64 ts;
    u64 cid;
    u32 type;
    u32 tid;
    u32 pid;
    u32 ppid;
    u32 uid;
    u32 gid;
    u32 local_address;
    u32 remote_address;
    u16 local_port;
    u16 remote_port;
    u16 family;
    char comm[TASK_COMM_LEN];
};

void netevent_common(struct netevent_t* netevent) {
    netevent->ts = bpf_ktime_get_ns();
    // 填充 id 相关字段, 这里后面抽象一下防止重复
    u64 id = bpf_get_current_uid_gid();
    netevent->uid = id;
    netevent->gid = id >> 32;
    id = bpf_get_current_pid_tgid();
    netevent->pid = id;
    netevent->tid = id >> 32;
    netevent->cid = bpf_get_current_cgroup_id();
    // kernel version 4.18, 需要加一个判断, 加强代码健壮性
    // https://android.googlesource.com/platform/external/bcc/+/HEAD/tools/execsnoop.py
    // ppid 需要在用户层有一个 fallback, 从status里面取
    struct task_struct * task;
    struct task_struct * real_parent_task;
    task = (struct task_struct*)bpf_get_current_task();
    bpf_probe_read(&real_parent_task, sizeof(real_parent_task), &task->real_parent );
    bpf_probe_read(&netevent->ppid, sizeof(netevent->ppid), &real_parent_task->pid );
    bpf_get_current_comm(&netevent->comm, sizeof(netevent->comm));
}

// /sys/kernel/debug/tracing/events/syscalls/sys_enter_connect/format
struct enter_connect_t {
    unsigned long long unused;
    long syscall_nr;
    long fd;
    long uservaddr;
    long addrlen;
};

// osquery 的项目里, hook socket 相关的是
// connect, bind, accept, accept4
// 数据格式按照 https://osquery.io/schema/5.0.1/#bpf_socket_events 补全
// 代码参考仓库 https://github.com/trailofbits/ebpfpub/blob/abfe933dca88ffcdf1b0d6503f45476c86d11f1b/examples/socketevents/src/main.cpp
SEC("tracepoint/syscalls/sys_enter_connect")
int enter_connect(struct enter_connect_t *ctx) {
    struct netevent_t netevent = {};
    netevent.type = 8;
    netevent_common(&netevent);
    struct sockaddr* address;
    address = (struct sockaddr *) ctx->uservaddr;
    bpf_probe_read_user(&netevent.family, sizeof(netevent.family), &address->sa_family);

    struct sockaddr_in *addr = (struct sockaddr_in *) address;
    bpf_probe_read_user(&netevent.remote_address, sizeof(netevent.remote_address), &addr->sin_addr.s_addr);
    bpf_probe_read_user(&netevent.remote_port, sizeof(netevent.remote_port), &addr->sin_port);
    bpf_perf_event_output(ctx, &perf_events, BPF_F_CURRENT_CPU, &netevent, sizeof(netevent));
    return 0;
}

// TODO:bind 接口缺少过滤
SEC("tracepoint/syscalls/sys_enter_bind")
int enter_bind(struct enter_connect_t *ctx) {
    struct netevent_t netevent = {};
    netevent.type = 9;
    netevent_common(&netevent);
    struct sockaddr* address;
    address = (struct sockaddr *) ctx->uservaddr;
    bpf_probe_read_user(&netevent.family, sizeof(netevent.family), &address->sa_family);
    struct sockaddr_in *addr = (struct sockaddr_in *) address;
    bpf_probe_read_user(&netevent.local_address, sizeof(netevent.local_address), &addr->sin_addr.s_addr);
    bpf_probe_read_user(&netevent.local_port, sizeof(netevent.local_port), &addr->sin_port);
    bpf_perf_event_output(ctx, &perf_events, BPF_F_CURRENT_CPU, &netevent, sizeof(netevent));
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_accept")
int enter_accept(struct enter_connect_t *ctx) {
    struct netevent_t netevent = {};
    netevent.type = 10;
    netevent_common(&netevent);
    struct sockaddr* address;
    address = (struct sockaddr *) ctx->uservaddr;
    bpf_probe_read_user(&netevent.family, sizeof(netevent.family), &address->sa_family);
    struct sockaddr_in *addr = (struct sockaddr_in *) address;
    bpf_probe_read_user(&netevent.local_address, sizeof(netevent.local_address), &addr->sin_addr.s_addr);
    bpf_probe_read_user(&netevent.local_port, sizeof(netevent.local_port), &addr->sin_port);
    bpf_perf_event_output(ctx, &perf_events, BPF_F_CURRENT_CPU, &netevent, sizeof(netevent));
    return 0;
}

// accept4 下多了一个 flag, 直接 drop 掉吧
SEC("tracepoint/syscalls/sys_enter_accept4")
int enter_accept4(struct enter_connect_t *ctx) {
    struct netevent_t netevent = {};
    netevent.type = 11;
    netevent_common(&netevent);
    struct sockaddr* address;
    address = (struct sockaddr *) ctx->uservaddr;
    bpf_probe_read_user(&netevent.family, sizeof(netevent.family), &address->sa_family);
    struct sockaddr_in *addr = (struct sockaddr_in *) address;
    bpf_probe_read_user(&netevent.local_address, sizeof(netevent.local_address), &addr->sin_addr.s_addr);
    bpf_probe_read_user(&netevent.local_port, sizeof(netevent.local_port), &addr->sin_port);
    bpf_perf_event_output(ctx, &perf_events, BPF_F_CURRENT_CPU, &netevent, sizeof(netevent));
    return 0;
}

char LICENSE[] SEC("license") = "GPL";