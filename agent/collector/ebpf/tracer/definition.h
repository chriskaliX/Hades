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
#include <linux/cred.h>
#include <linux/mount.h>

// #include "string_utils.h"
#include "common.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"
// ==== 定义常量 ====
#define TASK_COMM_LEN 16
#define FILENAME_LEN 32
#define ARGV_LEN 128
#define MAX_STRING_SIZE 512
#define MAX_PERCPU_BUFSIZE 1 << 14
#define MAX_BUFFERS 3
#define MAX_STR_ARR_ELEM 32
#define STRING_BUF_IDX 0
#define SUBMIT_BUF_IDX 0
#define NODENAME_SIZE 65
#define TTY_SIZE 64
#define MAX_PATH_COMPONENTS 20

// ==== 内核版本 ====
// #if LINUX_VERSION_CODE < KERNEL_VERSION(4, 18, 0)
// #error Minimal required kernel version is 4.18
// #endif

#define READ_KERN(ptr)                                                  \
    ({                                                                  \
        typeof(ptr) _val;                                               \
        __builtin_memset((void *)&_val, 0, sizeof(_val));               \
        bpf_probe_read((void *)&_val, sizeof(_val), &ptr);              \
        _val;                                                           \
    })

// TODO: CORE判断, vmlinux
struct mnt_namespace {
    atomic_t        count;
    struct ns_common    ns;
    // ...
};

struct mount {
    struct hlist_node mnt_hash;
    struct mount *mnt_parent;
    struct dentry *mnt_mountpoint;
    struct vfsmount mnt;
    // ...
};

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
    u32 euid;   // effective user id
    u32 gid;    // group id
    u32 ppid;   // parent pid
    u32 sessionid;
    char comm[TASK_COMM_LEN];   // command
    char pcomm[TASK_COMM_LEN];  // parent command
    char nodename[65];          // uts_name => 64
    char ttyname[64];           // char name[64];
    // stdin
    // stout
    // TODO: ld_preload from envp
    u8  argnum; // argnum
} context_t;

typedef struct simple_buf {
    u8 buf[MAX_PERCPU_BUFSIZE];
} buf_t;

// 事件定义
typedef struct event_data {
    struct task_struct *task;
    context_t context;
    buf_t *submit_p; // pid_tree, from kernel
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
// ==== 过滤 filters ====
// this is for test
struct bpf_map_def SEC("maps") envp_allows = {
    .key_size = sizeof(struct simple_buf),
    .value_size = sizeof(u32),
    .max_entries = MAX_BUFFERS,
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
    // 读取 cred 下, 填充 id
    struct cred *cred;
    // 有三个 ptracer_cred, real_cred, cred, 看kernel代码即可
    bpf_probe_read(&cred, sizeof(cred), &task->real_cred);
    bpf_probe_read(&context->euid, sizeof(context->euid), &cred->euid);

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

    struct pid_cache_t * parent = bpf_map_lookup_elem(&pid_cache_lru, &context->pid);
    if( parent ) {
        // 防止未知的 fallback 情况, 参考 issue 提问
        if (context->ppid == 0) {
            bpf_probe_read(&context->ppid, sizeof(context->ppid), &parent->ppid);
        }
        bpf_probe_read(&context->pcomm, sizeof(context->pcomm), &parent->pcomm);
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
// 目前测试这个有问题? 读取 pwd 失败, 周末过一遍
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

static inline struct mount *real_mount(struct vfsmount *mnt)
{
    return container_of(mnt, struct mount, mnt);
}

static __always_inline buf_t* get_buf(int idx)
{
    return bpf_map_lookup_elem(&bufs, &idx);
}

// 获取 path
static __always_inline void* get_path_str(struct path *path)
{
    struct path f_path;
    bpf_probe_read(&f_path, sizeof(struct path), path);
    char slash = '/';
    int zero = 0;
    struct dentry *dentry = f_path.dentry;
    struct vfsmount *vfsmnt = f_path.mnt;
    struct mount *mnt_parent_p;

    struct mount *mnt_p = real_mount(vfsmnt);
    bpf_probe_read(&mnt_parent_p, sizeof(struct mount*), &mnt_p->mnt_parent);

    u32 buf_off = (MAX_PERCPU_BUFSIZE >> 1);
    struct dentry *mnt_root;
    struct dentry *d_parent;
    struct qstr d_name;
    unsigned int len;
    unsigned int off;
    int sz;

    // Get per-cpu string buffer
    buf_t *string_p = get_buf(STRING_BUF_IDX);
    if (string_p == NULL)
        return NULL;

    #pragma unroll
    for (int i = 0; i < MAX_PATH_COMPONENTS; i++) {
        bpf_probe_read(&mnt_root, sizeof(mnt_root), &vfsmnt->mnt_root);
        bpf_probe_read(&d_parent, sizeof(d_parent), &dentry->d_parent);
        if (dentry == mnt_root || dentry == d_parent) {
            if (dentry != mnt_root) {
                // We reached root, but not mount root - escaped?
                break;
            }
            if (mnt_p != mnt_parent_p) {
                // We reached root, but not global root - continue with mount point path
                bpf_probe_read(&dentry, sizeof(struct dentry*), &mnt_p->mnt_mountpoint);
                bpf_probe_read(&mnt_p, sizeof(struct mount*), &mnt_p->mnt_parent);
                bpf_probe_read(&mnt_parent_p, sizeof(struct mount*), &mnt_p->mnt_parent);
                vfsmnt = &mnt_p->mnt;
                continue;
            }
            // Global root - path fully parsed
            break;
        }
        // Add this dentry name to path
        bpf_probe_read(&d_name, sizeof(d_name), &dentry->d_name);
        len = (d_name.len+1) & (MAX_STRING_SIZE-1);
        off = buf_off - len;

        // Is string buffer big enough for dentry name?
        sz = 0;
        if (off <= buf_off) { // verify no wrap occurred
            len = len & ((MAX_PERCPU_BUFSIZE >> 1)-1);
            sz = bpf_probe_read_str(&(string_p->buf[off & ((MAX_PERCPU_BUFSIZE >> 1)-1)]), len, (void *)d_name.name);
        }
        else
            break;
        if (sz > 1) {
            buf_off -= 1; // remove null byte termination with slash sign
            bpf_probe_read(&(string_p->buf[buf_off & ((MAX_PERCPU_BUFSIZE)-1)]), 1, &slash);
            buf_off -= sz - 1;
        } else {
            // If sz is 0 or 1 we have an error (path can't be null nor an empty string)
            break;
        }
        dentry = d_parent;
    }

    if (buf_off == (MAX_PERCPU_BUFSIZE >> 1)) {
        // memfd files have no path in the filesystem -> extract their name
        buf_off = 0;
        bpf_probe_read(&d_name, sizeof(d_name), &dentry->d_name);
        bpf_probe_read_str(&(string_p->buf[0]), MAX_STRING_SIZE, (void *)d_name.name);
    } else {
        // Add leading slash
        buf_off -= 1;
        bpf_probe_read(&(string_p->buf[buf_off & ((MAX_PERCPU_BUFSIZE)-1)]), 1, &slash);
        // Null terminate the path string
        bpf_probe_read(&(string_p->buf[(MAX_PERCPU_BUFSIZE >> 1)-1]), 1, &zero);
    }

    // set_buf_off(STRING_BUF_IDX, buf_off);
    return &string_p->buf[buf_off];
}

// 参考字节 get_process_socket, 向上溯源
// extern 函数无法调用

// this is for test 
static __always_inline int save_str_arr_to_buf_with_allows(event_data_t *data, const char __user *const __user *ptr,u8 index)
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
        char *argp = NULL;
        bpf_probe_read(&argp, sizeof(argp), &ptr[i]);
        if (!argp)
            goto out;

        if (data->buf_off > (MAX_PERCPU_BUFSIZE) - (MAX_STRING_SIZE) - sizeof(int))
            // not enough space - return
            goto out;

        // before read into the buffers, test for the allowers
        // but in the bpf prog, we can not use libc function, strsep is not the right option
        // and I start to understand why the filters are implied in a simple way
        // I want to achieve this in a gentle way, so some time would be cost...

        // char *sbegin = argp;
	    // char *end;
        // if (sbegin == NULL)
        //     continue;
        // end = __builtin_strpbrk(sbegin, "=");
        // if (end)
        //     *end++ = '\0';
        // argp = end;
        // if (sbegin) {
        // }
        // char *argp_copy = NULL;
        // bpf_probe_read(&argp, sizeof(argp), argp);
        // __builtin_strpbrk()

        // if (temp) {
        //     u32 * value = bpf_map_lookup_elem(&envp_allows, &temp);
        //     if (!value) {
        //         continue;
        //     }
        // }

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