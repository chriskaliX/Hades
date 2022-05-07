#ifndef __DEFINE_H
#define __DEFINE_H
#ifndef CORE
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
#include <linux/string.h>
#include <linux/fs.h>
#include <net/inet_sock.h>
#include <uapi/linux/un.h>
#include <uapi/linux/bpf.h>
#include <linux/bpf.h>
#else
#include <vmlinux.h>
#include <missing_definitions.h>
#endif

#include "bpf_helpers.h"
#include "bpf_core_read.h"

#define TASK_COMM_LEN       16
#define MAX_STR_FILTER_SIZE 128
#define MAX_PERCPU_BUFSIZE  (1 << 14)
#define MAX_STRING_SIZE     256 // Same with Elkeid, but it's larger in tracee or other project
#define MAX_STR_ARR_ELEM    32
#define MAX_PATH_COMPONENTS 16
#define MAX_NODENAME        64

#define MAX_BUFFERS 3
#define TMP_BUF_IDX 1
#define SUBMIT_BUF_IDX 0
#define STRING_BUF_IDX 1

#define EXECVE_GET_SOCK_FD_LIMIT 8
#define EXECVE_GET_SOCK_PID_LIMIT 4

// from tracee, but why 18 and 14?
#define NUMBER_OF_SYSCALLS_TO_CHECK_X86 18
#define NUMBER_OF_SYSCALLS_TO_CHECK_ARM 14

/* ========== MAP MICRO DEFINATION ========== */
// update since bpf_map_def is marked as deprecated
#define BPF_MAP(_name, _type, _key_type, _value_type, _max_entries)     \
    struct {                                                            \
        __uint(type, _type);                                            \
        __uint(max_entries, _max_entries);                              \
        __type(key, _key_type);                                         \
        __type(value, _value_type);                                     \
    } _name SEC(".maps");
/* BPF MAP DEFINATION MICROS, MODIFIED WITH MAX_ENTRIES */
#define BPF_HASH(_name, _key_type, _value_type, _max_entries) \
    BPF_MAP(_name, BPF_MAP_TYPE_HASH, _key_type, _value_type, _max_entries)
#define BPF_LRU_HASH(_name, _key_type, _value_type, _max_entries) \
    BPF_MAP(_name, BPF_MAP_TYPE_LRU_HASH, _key_type, _value_type, _max_entries)
#define BPF_ARRAY(_name, _value_type, _max_entries) \
    BPF_MAP(_name, BPF_MAP_TYPE_ARRAY, u32, _value_type, _max_entries)
#define BPF_PERCPU_ARRAY(_name, _value_type, _max_entries) \
    BPF_MAP(_name, BPF_MAP_TYPE_PERCPU_ARRAY, u32, _value_type, _max_entries)
#define BPF_PROG_ARRAY(_name, _max_entries) \
    BPF_MAP(_name, BPF_MAP_TYPE_PROG_ARRAY, u32, u32, _max_entries)
#define BPF_PERF_OUTPUT(_name, _max_entries) \
    BPF_MAP(_name, BPF_MAP_TYPE_PERF_EVENT_ARRAY, int, __u32, _max_entries)
/* ========== STRUCT FIELD DEFINITION ==========*/
/* buf_t that we used in event_data_t */
typedef struct simple_buf
{
    u8 buf[MAX_PERCPU_BUFSIZE];
} buf_t;

/* general context for all hook point */
// pid in the namespace maybe useful
typedef struct data_context
{
    u64 ts;        // timestamp
    u64 cgroup_id; // cgroup_id
    u32 pns;       // in Elkeid, they use pid_inum and root_pid_inum. TODO: go through this
    u32 type;      // type of struct
    u32 pid;       // processid
    u32 tid;       // thread id
    u32 uid;       // user id
    u32 gid;       // group id
    u32 ppid;      // parent pid => which is tpid, pid is for the kernel space. In user space, it's tgid actually
    u32 sessionid;
    char comm[TASK_COMM_LEN];       // command
    char pcomm[TASK_COMM_LEN];      // parent command
    char nodename[MAX_NODENAME];    // uts_name => 64, in tracee, it's 16 here
    u64 retval;                     // return value(useful when it's exit or kill)
    u8 argnum;                      // argnum
} context_t;

/* general field for event */
typedef struct event_data
{
    struct task_struct *task;   // current task_struct
    context_t context;          // context: general fields for all hooks
    buf_t *submit_p;
    u32 buf_off;                // offset of the buf_t
    void *ctx;
} event_data_t;

/* general field for filter string */
typedef struct string
{
    char str[MAX_STR_FILTER_SIZE];
} string_t;

#ifndef CORE
struct mnt_namespace
{
    atomic_t count;
    struct ns_common ns;
    // ...
};

// use this in get_path_str thing...
struct mount
{
    struct hlist_node mnt_hash;
    struct mount *mnt_parent;
    struct dentry *mnt_mountpoint;
    struct vfsmount mnt;
    // ...
};
#endif

typedef struct network_connection_v4
{
    u32 local_address;
    u16 local_port;
    u32 remote_address;
    u16 remote_port;
} net_conn_v4_t;

typedef struct network_connection_v6
{
    struct in6_addr local_address;
    u16 local_port;
    struct in6_addr remote_address;
    u16 remote_port;
    u32 flowinfo;
    u32 scope_id;
} net_conn_v6_t;

struct pid_cache_t
{
    u32 ppid;
    char pcomm[TASK_COMM_LEN];
};

/* filters that communicate with user_space prog */
BPF_ARRAY(path_filter, string_t, 32);
BPF_HASH(pid_filter, u32, u32, 32);
BPF_HASH(cgroup_id_filter, u64, u32, 32);
/* for pid -> parent cmdline */
BPF_LRU_HASH(pid_cache_lru, u32, struct pid_cache_t, 1024);
/* BPF_PERF_OUTPUT */
BPF_PERF_OUTPUT(exec_events, 1024);
BPF_PERF_OUTPUT(file_events, 1024);
BPF_PERF_OUTPUT(net_events, 1024);
BPF_PERCPU_ARRAY(bufs, buf_t, 3);
BPF_PERCPU_ARRAY(bufs_off, u32, MAX_BUFFERS);

// kconfig

#ifdef CORE
#define get_kconfig(x) get_kconfig_val(x)
#else
#define get_kconfig(x) CONFIG_##x
#endif

#ifdef CORE

#define ARCH_HAS_SYSCALL_WRAPPER        1000U

#else

#ifndef CONFIG_ARCH_HAS_SYSCALL_WRAPPER
#define CONFIG_ARCH_HAS_SYSCALL_WRAPPER 0
#endif

#endif // CORE

// CORE, just like in tracee
// https://blog.aquasec.com/ebf-portable-code
// In bpf_probe_read we do not exceed the 512 bytes BPF stack limit.
// But in bpf_core_read we hit the limit in a pretty weird way.
#ifndef CORE

#define GET_FIELD_ADDR(field) &field

#define READ_KERN(ptr)                                                  \
    ({                                                                  \
        typeof(ptr) _val;                                               \
        __builtin_memset((void *)&_val, 0, sizeof(_val));               \
        bpf_probe_read((void *)&_val, sizeof(_val), &ptr);              \
        _val;                                                           \
    })

#define READ_USER(ptr)                                                  \
    ({                                                                  \
        typeof(ptr) _val;                                               \
        __builtin_memset((void *)&_val, 0, sizeof(_val));               \
        bpf_probe_read_user((void *)&_val, sizeof(_val), &ptr);         \
        _val;                                                           \
    })

#else // CORE

#define GET_FIELD_ADDR(field) __builtin_preserve_access_index(&field)

#define READ_KERN(ptr)                                                  \
    ({                                                                  \
        typeof(ptr) _val;                                               \
        __builtin_memset((void *)&_val, 0, sizeof(_val));               \
        bpf_core_read((void *)&_val, sizeof(_val), &ptr);               \
        _val;                                                           \
    })

#define READ_USER(ptr)                                                  \
    ({                                                                  \
        typeof(ptr) _val;                                               \
        __builtin_memset((void *)&_val, 0, sizeof(_val));               \
        bpf_core_read_user((void *)&_val, sizeof(_val), &ptr);          \
        _val;                                                           \
    })
#endif

/* array related function */
static __always_inline buf_t *get_buf(int idx)
{
    return bpf_map_lookup_elem(&bufs, &idx);
}

static __always_inline void set_buf_off(int buf_idx, u32 new_off)
{
    bpf_map_update_elem(&bufs_off, &buf_idx, &new_off, BPF_ANY);
}

static __always_inline u32 *get_buf_off(int buf_idx)
{
    return bpf_map_lookup_elem(&bufs_off, &buf_idx);
}

// mount
static inline struct mount *real_mount(struct vfsmount *mnt)
{
    // @Note
    // #define container_of(ptr, type, member) ({ \ const typeof( ((type *)0)->member ) *__mptr = (ptr); \ (type *)( (char *)__mptr - offsetof(type,member) );})
    // 从结构体的一个成员变量地址, 获取到一个结构体的首地址
    return container_of(mnt, struct mount, mnt);
}

/* hook point id */
#define SYS_ENTER_PTRACE          164
#define SYS_ENTER_PRCTL           200
#define SCHED_PROCESS_FORK        317
#define SYS_ENTER_MEMFD_CREATE    614
#define SYS_ENTER_EXECVEAT        698
#define SYS_ENTER_EXECVE          700
#define COMMIT_CREDS              1011
#define SECURITY_SOCKET_CONNECT   1022
#define SECURITY_SOCKET_BIND      1024
#define UDP_RECVMSG               1025
#define SECURITY_KERNEL_READ_FILE 1027
#define SECURITY_INODE_CREATE     1028
#define SECURITY_SB_MOUNT         1029
#define CALL_USERMODEHELPER       1030
// uprobe
#define BASH_READLINE             2000

#endif //__DEFINE_H