#include "vmlinux.h"
#include "bpf_helpers.h"
#include "process.h"

#define FNAME_LEN 32
#define ARGSIZE 128
#define DEFAULT_MAXARGS 16 // 有些启动参数,会十分的长
#define BUFSIZE 4096

// 2021-11-27
// filter 部分可能无法直接引入, 因为 perf_event 发送的时候是分段发送的
// TODO: trace_event_raw_sys_enter

// enter_execve
struct enter_execve_t {
    u64 ts;
    u64 pns;
    u64 cid;
    u32 type;
    u32 pid;
    u32 tid;
    u32 uid;
    u32 gid;
    u32 ppid;
    u32 argsize;
    char filename[FNAME_LEN];
    char comm[TASK_COMM_LEN];
    char pcomm[TASK_COMM_LEN];
    char args[ARGSIZE];
    char nodename[65];
};

struct pid_cache_t {
    u32 ppid;
    char pcomm[16];
};

struct bpf_map_def SEC("maps") pid_cache_lru = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(struct pid_cache_t),
    .max_entries = 1024,
};

void execve_common(struct enter_execve_t* execve_event) {
    execve_event->ts = bpf_ktime_get_ns();
    // 填充 id 相关字段, 这里后面抽象一下防止重复
    u64 id = bpf_get_current_uid_gid();
    execve_event->uid = id;
    execve_event->gid = id >> 32;
    id = bpf_get_current_pid_tgid();
    execve_event->pid = id;
    execve_event->tid = id >> 32;
    execve_event->cid = bpf_get_current_cgroup_id(); // kernel version 4.18, 需要加一个判断, 加强代码健壮性
    // https://android.googlesource.com/platform/external/bcc/+/HEAD/tools/execsnoop.py
    // ppid 需要在用户层有一个 fallback, 从status里面取
    struct task_struct * task = (struct task_struct *)bpf_get_current_task();
    struct task_struct * real_parent_task;

    // bpf_probe_read(&execve_event->nodename, sizeof(execve_event->nodename),&task->nsproxy->uts_ns->name.nodename);
    /* 
        @note: namespace
        在 task_struct->nsproxy 下有很多 namespace
        uts(unix time sharing) namespace isolates the hostname & the NIS domain name; 

        TODO: 
        nodename, pns 目前为空的问题, 怀疑是 task_struct vminux relocation?
        所以 ppid 可能也是同一个问题
    */
    struct nsproxy *nsp;
    struct uts_namespace *uts_ns;
    bpf_probe_read(&nsp, sizeof(nsp), &task->nsproxy);
    bpf_probe_read(&uts_ns, sizeof(uts_ns), &nsp->uts_ns);
    bpf_probe_read_str(&execve_event->nodename, sizeof(execve_event->nodename), &uts_ns->name.nodename);

    struct pid_namespace *pns;
    bpf_probe_read(&pns, sizeof(pns), &nsp->pid_ns_for_children);
    bpf_probe_read(&execve_event->pns, sizeof(execve_event->pns), &pns->ns.inum);

    bpf_probe_read(&real_parent_task, sizeof(real_parent_task), &task->real_parent );
    bpf_probe_read(&execve_event->ppid, sizeof(execve_event->ppid), &real_parent_task->tgid );
    if (execve_event->ppid == 0) {
        struct pid_cache_t * parent = bpf_map_lookup_elem(&pid_cache_lru, &execve_event->pid);
        if( parent ) {
            bpf_probe_read(&execve_event->ppid, sizeof(execve_event->ppid), &parent->ppid );
            bpf_probe_read(&execve_event->pcomm, sizeof(execve_event->pcomm), &parent->pcomm );
        }
    }
    bpf_get_current_comm(&execve_event->comm, sizeof(execve_event->comm));
}

// 开始看 perf_events, 更正一下对 max_entries 的认识, 是存储用户态传输给内核的 fd, 而不是误认为的 array 队列长度之类
// 从内户态透传给用户态的, 是每个 cpu 一个 buffer, perf_events 可以是这些 ringbuf 的一个集合
struct bpf_map_def SEC("maps") perf_events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
};

// at 多了一个 flags
/* /sys/kernel/debug/tracing/events/syscalls/sys_enter_execve/format */
struct execve_entry_args_t {
    __u64 unused;
    int syscall_nr;
    const char *filename;
    const char *const * argv;
    const char *const * envp;
};

/*
    @reference: https://stackoverflow.com/questions/67553794/what-is-variable-attribute-sec-means

    @note: This is for declaring the structure of the object (in this case, the keys for the map) for BTF.
        SEC() is the same as __attribute__((section("name"), used)) so what it does is putting the defined object into the given ELF section.
*/
SEC("tracepoint/syscalls/sys_enter_execve")
int enter_execve(struct execve_entry_args_t *ctx)
{
    // 定义返回数据
    struct enter_execve_t enter_execve_data = {};
    // 用来标识 sys_enter_execve, 供用户态区分
    enter_execve_data.type = 1;
    execve_common(&enter_execve_data);
    bpf_probe_read_str(enter_execve_data.filename, sizeof(enter_execve_data.filename), ctx->filename);

    const char* argp = NULL;
    #pragma unroll
    for (int i = 0; i < DEFAULT_MAXARGS; i++)
    {
        bpf_probe_read(&argp, sizeof(argp), &ctx->argv[i]);
        if (!argp) {
            return 0;
        }
        enter_execve_data.argsize = bpf_probe_read_str(enter_execve_data.args, ARGSIZE, argp);
        // TODO: 有时候会出现读错误的情况, 后续 follow, 在用户态可以移除掉校验
        if (enter_execve_data.argsize <= ARGSIZE) {
            bpf_perf_event_output(ctx, &perf_events, BPF_F_CURRENT_CPU, &enter_execve_data, sizeof(enter_execve_data));
        };
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execveat")
int enter_execveat(struct execve_entry_args_t *ctx)
{
    // 定义返回数据
    struct enter_execve_t enter_execve_data = {};
    enter_execve_data.type = 2;
    execve_common(&enter_execve_data);
    bpf_probe_read_str(enter_execve_data.filename, sizeof(enter_execve_data.filename), ctx->filename);
    const char* argp = NULL;
    #pragma unroll
    for (int i = 0; i < DEFAULT_MAXARGS; i++)
    {
        bpf_probe_read(&argp, sizeof(argp), &ctx->argv[i]);
        if (!argp) {
            return 0;
        }
        enter_execve_data.argsize = bpf_probe_read_str(enter_execve_data.args, ARGSIZE, argp);
        if (enter_execve_data.argsize <= ARGSIZE) {
            bpf_perf_event_output(ctx, &perf_events, BPF_F_CURRENT_CPU, &enter_execve_data, sizeof(enter_execve_data));
        };
    }
    return 0;
}

struct _tracepoint_sched_process_fork {
    __u64 unused;
    char parent_comm[16];
    pid_t parent_pid;
    char child_comm[16];
    pid_t child_pid;
};

// 为了缓解 ppid 的问题, 需要 hook 到 fork 上面, 在本地维护一个 map
SEC("tracepoint/sched/sched_process_fork")
int process_fork( struct _tracepoint_sched_process_fork *ctx ) {
    u32 pid = 0;
    u32 ppid = 0;
    bpf_probe_read(&pid, sizeof(pid), &ctx->child_pid);
    bpf_probe_read(&ppid, sizeof(ppid), &ctx->parent_pid);
    struct pid_cache_t cache = {};
    cache.ppid = ppid;
    bpf_probe_read(&cache.pcomm, sizeof(cache.pcomm), &ctx->parent_comm);
    bpf_map_update_elem(&pid_cache_lru, &pid, &cache, BPF_ANY);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";