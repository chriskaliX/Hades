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

// ==== 定义常量 ====
#define TASK_COMM_LEN 16
#define FILENAME_LEN 32
#define ARGV_LEN 128
#define BUFSIZE 4096
#define MAX_STRING_SIZE 1 << 12
#define MAX_PERCPU_BUFSIZE 1 << 14
#define MAX_BUFFERS 3
#define MAX_STR_ARR_ELEM 32
#define STRING_BUF_IDX 0
#define SUBMIT_BUF_IDX 0
#define NODENAME_SIZE 65
#define TTY_SIZE 64

// ==== 内核版本 ====
// #if LINUX_VERSION_CODE < KERNEL_VERSION(4, 18, 0)
// #error Minimal required kernel version is 4.18
// #endif

// ==== 结构体定义 ====
// context
typedef struct event_context {
    u64 ts;     // timestamp
    u64 uts_inum;       // 
    u64 parent_uts_inum;// 
    u64 cgroup_id;      // cgroup_id
    u32 type;   // type of struct
    u32 pid;    // processid
    u32 tid;    // thread id
    u32 uid;    // user id
    u32 gid;    // group id
    u32 ppid;   // parent pid
    u32 sessionid;
    char exe[FILENAME_LEN];   // file name
    char comm[TASK_COMM_LEN];   // command
    char pcomm[TASK_COMM_LEN];  // parent command
    char nodename[65];          // uts_name
    char ttyname[64];           // char name[64];
    char cwd[40];               // TODO: 合适的 length
    // stdin
    // stout
    u8  argnum; // argnum
} context_t;

typedef struct simple_buf {
    u8 buf[MAX_PERCPU_BUFSIZE];
} buf_t;

// 事件定义
typedef struct event_data {
    struct task_struct *task;
    context_t context;
    buf_t *submit_p;
    u32 buf_off;
} event_data_t;

struct pid_cache_t {
    u32 ppid;
    char pcomm[16];
};

// ==== MAPS 定义 ====
// for breaking the limitation of 512 stack while using perf_event_output
struct bpf_map_def SEC("maps") bufs = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(struct simple_buf),
    .max_entries = MAX_BUFFERS,
};

// process cache for real_parent->pid fallback
struct bpf_map_def SEC("maps") pid_cache_lru = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(struct pid_cache_t),
    .max_entries = 1024,
};

// ==== 事件输出 perfs ====
struct bpf_map_def SEC("maps") exec_events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(u32),
};

struct bpf_map_def SEC("maps") file_events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(u32),
};

struct bpf_map_def SEC("maps") net_events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(u32),
};

static __always_inline int init_context(context_t *context, struct task_struct *task) {
    // 获取 timestamp
    struct task_struct * realparent;
    bpf_probe_read(&realparent, sizeof(realparent), &task->real_parent);
    bpf_probe_read(&context->ppid, sizeof(context->ppid), &realparent->pid);
    context->ts = bpf_ktime_get_ns();
    // 填充 id 相关信息
    u64 id = bpf_get_current_uid_gid();
    context->uid = id;
    context->gid = id >> 32;
    id = bpf_get_current_pid_tgid();
    context->pid = id;
    context->tid = id >> 32;
    context->cgroup_id = bpf_get_current_cgroup_id();

    // 容器相关信息
    struct nsproxy *nsp;
    struct uts_namespace *uts_ns;
    bpf_probe_read(&nsp, sizeof(nsp), &task->nsproxy);
    bpf_probe_read(&uts_ns, sizeof(uts_ns), &nsp->uts_ns);
    bpf_probe_read_str(&context->nodename, sizeof(context->nodename), &uts_ns->name.nodename);
    bpf_probe_read(&context->uts_inum, sizeof(context->uts_inum), &uts_ns->ns.inum);
    bpf_probe_read(&nsp, sizeof(nsp), &realparent->nsproxy);
    bpf_probe_read(&uts_ns, sizeof(uts_ns), &nsp->uts_ns);
    bpf_probe_read(&context->parent_uts_inum, sizeof(context->parent_uts_inum), &uts_ns->ns.inum);

    // ssh 相关信息, tty
    // 参考 https://github.com/Gui774ume/ssh-probe/blob/26b6f0b38bf7707a5f7f21444917ed2760766353/ebpf/utils/process.h
    // ttyname
    struct signal_struct *signal;
    bpf_probe_read(&signal, sizeof(signal), &task->signal);
    struct tty_struct *tty;
    bpf_probe_read(&tty, sizeof(tty), &signal->tty);
    bpf_probe_read_str(&context->ttyname, sizeof(context->ttyname), &tty->name);
    
    // sessionid
    bpf_probe_read(&context->sessionid, sizeof(context->sessionid), &task->sessionid);
    // 参考:https://pretagteam.com/question/current-directory-of-a-process-in-linuxkernel
    // TODO: cwd 获取有问题
    // 这里要看一下几个, 第一个 path -> root/path, 第二 hash 和 name, length
    // 这个实现方式是错误的, 我们在 bcc 的 issue 里也能找到类似的问题, 貌似还没有解决
    // https://github.com/iovisor/bpftrace/issues/29
    // struct fs_struct *fs;
    // struct path *path;
    // struct dentry *dentry;
    // struct qstr d_name;
    // // 这里获取 cwd 在内核看到的函数为 dentry_path_raw, 但是似乎不好实现
    // // 也没有 fd -> path 的
    // bpf_core_read(&fs, sizeof(fs), &task->fs);
    // bpf_core_read(&path, sizeof(path), &fs->pwd);
    // bpf_core_read(&dentry, sizeof(dentry), &path->dentry);
    // check_max_stack_depth
    // 要追溯到最上层的 dentry
    // #pragma unroll
    // for (int i=0; i < 30; i++) {
    //     struct dentry *d_parent;
    //     bpf_core_read(&d_parent,sizeof(d_parent), &dentry->d_parent);
    //     if (dentry == d_parent) {
    //         break;
    //     }
    //     // bpf_core_read(&dentry, sizeof(dentry), &d_parent);
    //     dentry = d_parent;
    // }
    // bpf_core_read(name, sizeof(name), dentry->d_name);
    // bpf_core_read_str(&execve_event->cwd, len, (void *)d_name.name);

    struct pid_cache_t * parent = bpf_map_lookup_elem(&pid_cache_lru, &context->pid);
    if( parent ) {
        // 防止未知的 fallback 情况, 参考 issue 提问
        if (context->ppid == 0) {
            bpf_core_read(&context->ppid, sizeof(context->ppid), &parent->ppid );
        }
        bpf_core_read(&context->pcomm, sizeof(context->pcomm), &parent->pcomm );
    }
    bpf_get_current_comm(&context->comm, sizeof(context->comm));
    context->argnum = 0;
    return 0;
}

static __always_inline int init_event_data(event_data_t *data)
{
    data->task = (struct task_struct *)bpf_get_current_task();
    init_context(&data->context, data->task);
    data->buf_off = sizeof(context_t);
    int buf_idx = SUBMIT_BUF_IDX;
    data->submit_p = bpf_map_lookup_elem(&bufs, &buf_idx);
    if (data->submit_p == NULL)
        return 0;
    return 1;
}

static __always_inline int save_str_to_buf(event_data_t *data, void *ptr, u8 index)
{
    // Data saved to submit buf: [index][size][ ... string ... ]

    // If we don't have enough space - return
    if (data->buf_off > (MAX_PERCPU_BUFSIZE) - (MAX_STRING_SIZE) - sizeof(int))
        return 0;

    // Save argument index
    data->submit_p->buf[(data->buf_off) & ((MAX_PERCPU_BUFSIZE)-1)] = index;

    // Satisfy validator for probe read
    if ((data->buf_off+1) <= (MAX_PERCPU_BUFSIZE) - (MAX_STRING_SIZE) - sizeof(int)) {
        // Read into buffer
        int sz = bpf_probe_read_str(&(data->submit_p->buf[data->buf_off+1+sizeof(int)]), MAX_STRING_SIZE, ptr);
        if (sz > 0) {
            // Satisfy validator for probe read
            if ((data->buf_off+1) > (MAX_PERCPU_BUFSIZE) - sizeof(int)) {
                return 0;
            }
            __builtin_memcpy(&(data->submit_p->buf[data->buf_off+1]), &sz, sizeof(int));
            data->buf_off += sz + sizeof(int) + 1;
            data->context.argnum++;
            return 1;
        }
    }

    return 0;
}

// 把 string array 复制到 buffuer 里面, 使用场景为: 在读取 args 的时候
static __always_inline int save_str_arr_to_buf(event_data_t *data, const char __user *const __user *ptr, u8 index)
{
    // Data saved to submit buf: [index][string count][str1 size][str1][str2 size][str2]...

    u8 elem_num = 0;

    // Save argument index
    data->submit_p->buf[(data->buf_off) & ((MAX_PERCPU_BUFSIZE)-1)] = index;

    // Save space for number of elements (1 byte)
    u32 orig_off = data->buf_off+1;
    data->buf_off += 2;

    #pragma unroll
    for (int i = 0; i < MAX_STR_ARR_ELEM; i++) {
        const char *argp = NULL;
        bpf_probe_read(&argp, sizeof(argp), &ptr[i]);
        if (!argp)
            goto out;

        if (data->buf_off > (MAX_PERCPU_BUFSIZE) - (MAX_STRING_SIZE) - sizeof(int))
            // not enough space - return
            goto out;

        // Read into buffer
        int sz = bpf_probe_read_str(&(data->submit_p->buf[data->buf_off + sizeof(int)]), MAX_STRING_SIZE, argp);
        if (sz > 0) {
            if (data->buf_off > (MAX_PERCPU_BUFSIZE) - sizeof(int))
                // Satisfy validator
                goto out;
            bpf_probe_read(&(data->submit_p->buf[data->buf_off]), sizeof(int), &sz);
            data->buf_off += sz + sizeof(int);
            elem_num++;
            continue;
        } else {
            goto out;
        }
    }
    // handle truncated argument list
    char ellipsis[] = "...";
    if (data->buf_off > (MAX_PERCPU_BUFSIZE) - (MAX_STRING_SIZE) - sizeof(int))
        // not enough space - return
        goto out;

    // Read into buffer
    int sz = bpf_probe_read_str(&(data->submit_p->buf[data->buf_off + sizeof(int)]), MAX_STRING_SIZE, ellipsis);
    if (sz > 0) {
        if (data->buf_off > (MAX_PERCPU_BUFSIZE) - sizeof(int))
            // Satisfy validator
            goto out;
        bpf_probe_read(&(data->submit_p->buf[data->buf_off]), sizeof(int), &sz);
        data->buf_off += sz + sizeof(int);
        elem_num++;
    }
out:
    // save number of elements in the array
    data->submit_p->buf[orig_off & ((MAX_PERCPU_BUFSIZE)-1)] = elem_num;
    data->context.argnum++;
    return 1;
}