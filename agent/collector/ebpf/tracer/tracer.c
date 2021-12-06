#include <linux/kconfig.h>
#include <linux/sched.h>
#include <linux/nsproxy.h>
#include <linux/utsname.h>
#include <linux/types.h>
#include <linux/ns_common.h>
#include <linux/sched/signal.h>
#include <linux/tty.h>
#include <linux/fs_struct.h>
#include <linux/path.h>
#include <linux/dcache.h>

#include "common.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"

#define TASK_COMM_LEN 16
#define FNAME_LEN 32
#define ARGSIZE 128
#define DEFAULT_MAXARGS 16
#define BUFSIZE 4096

// tracepoint execve/execveat struct
struct tc_execve_t {
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
    char ttyname[64]; // char name[64];
    char cwd[40]; // TODO: 合适的 length
};


struct pid_cache_t {
    u32 ppid;
    char pcomm[16];
};

// process cache for real_parent->pid fallback
struct bpf_map_def SEC("maps") pid_cache_lru = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(struct pid_cache_t),
    .max_entries = 1024,
};

// 所有信息全部在内核态补齐! 减少用户态 read IO
void execve_common(struct tc_execve_t* execve_event) {
    execve_event->ts = bpf_ktime_get_ns();
    // 填充 id 相关字段, 这里后面抽象一下防止重复
    u64 id = bpf_get_current_uid_gid();
    execve_event->uid = id;
    execve_event->gid = id >> 32;
    id = bpf_get_current_pid_tgid();
    execve_event->pid = id;
    execve_event->tid = id >> 32;
    execve_event->cid = bpf_get_current_cgroup_id();

    // kernel version 4.18, 需要加一个判断, 加强代码健壮性
    // https://android.googlesource.com/platform/external/bcc/+/HEAD/tools/execsnoop.py
    struct task_struct * task = (struct task_struct *)bpf_get_current_task();
    struct task_struct * realparent;
    bpf_core_read(&realparent, sizeof(realparent), &task->real_parent);
    bpf_core_read(&execve_event->ppid, sizeof(execve_event->ppid), &realparent->pid);

    // 容器相关信息
    // 父节点的 nsproxy, 检测容器逃逸? TODO: 看一下
    struct nsproxy *nsp;
    struct uts_namespace *uts_ns;
    bpf_core_read(&nsp, sizeof(nsp), &task->nsproxy);
    bpf_core_read(&uts_ns, sizeof(uts_ns), &nsp->uts_ns);
    bpf_core_read_str(&execve_event->nodename, sizeof(execve_event->nodename), &uts_ns->name.nodename);
    bpf_core_read(&execve_event->pns, sizeof(execve_event->pns), &uts_ns->ns.inum);

    // ssh 相关信息, tty
    // 参考 https://github.com/Gui774ume/ssh-probe/blob/26b6f0b38bf7707a5f7f21444917ed2760766353/ebpf/utils/process.h
    // ttyname
    struct signal_struct *signal;
    bpf_probe_read(&signal, sizeof(signal), &task->signal);
    struct tty_struct *tty;
    bpf_probe_read(&tty, sizeof(tty), &signal->tty);
    bpf_probe_read_str(&execve_event->ttyname, sizeof(execve_event->ttyname), &tty->name);
    // TODO: session

    // 参考:https://pretagteam.com/question/current-directory-of-a-process-in-linuxkernel
    // TODO: cwd 获取有问题
    // 这里要看一下几个, 第一个 path -> root/path, 第二 hash 和 name, length
    // 这个实现方式是错误的, 我们在 bcc 的 issue 里也能找到类似的问题, 貌似还没有解决
    // https://github.com/iovisor/bpftrace/issues/29
    struct fs_struct *fs;
    struct path *path;
    struct dentry *dentry;
    // 这里获取 cwd 在内核看到的函数为 dentry_path_raw, 但是似乎不好实现
    // 也没有 fd -> path 的
    bpf_probe_read(&fs, sizeof(fs), &task->fs);
    bpf_probe_read(&path, sizeof(path), &fs->pwd);
    bpf_probe_read(&dentry, sizeof(dentry), &path->dentry);
    bpf_probe_read_str(&execve_event->cwd, sizeof(execve_event->cwd), &dentry->d_iname);

    // 防止未知的 fallback 情况, 参考 issue 提问
    // TODO: pcomm 外置
    if (execve_event->ppid == 0) {
        struct pid_cache_t * parent = bpf_map_lookup_elem(&pid_cache_lru, &execve_event->pid);
        if( parent ) {
            bpf_core_read(&execve_event->ppid, sizeof(execve_event->ppid), &parent->ppid );
            bpf_core_read(&execve_event->pcomm, sizeof(execve_event->pcomm), &parent->pcomm );
        }
    }
    bpf_get_current_comm(&execve_event->comm, sizeof(execve_event->comm));
}

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

SEC("tracepoint/syscalls/sys_enter_execve")
int enter_execve(struct execve_entry_args_t *ctx)
{
    // 定义返回数据
    struct tc_execve_t enter_execve_data = {};
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
    struct tc_execve_t enter_execve_data = {};
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