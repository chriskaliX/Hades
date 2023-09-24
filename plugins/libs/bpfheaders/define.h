// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Authors: chriskalix@protonmail.com
 */
#ifndef __DEFINE_H
#define __DEFINE_H
#ifndef CORE
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/kconfig.h>
#include <linux/mount.h>
#include <linux/ns_common.h>
#include <linux/nsproxy.h>
#include <linux/path.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/string.h>
#include <linux/tty.h>
#include <linux/types.h>
#include <linux/utsname.h>
#include <net/inet_sock.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/btf.h>
#include <uapi/linux/un.h>
#else
#include <missing_definitions.h>
#include <vmlinux.h>
#endif

#include "bpf_core_read.h"
#include "bpf_helpers.h"

#define TASK_COMM_LEN           16
#define MAX_STR_FILTER_SIZE     128
#define MAX_PERCPU_BUFSIZE      (1 << 15)
#define MAX_STRING_SIZE         256
#define MAX_STR_ARR_ELEM        32
#define MAX_PATH_COMPONENTS     16
#define MAX_PATH_COMPONENTS_SIM 10
#define MAX_NODENAME            64
#define MAX_PID_TREE_TRACE      12
#define MAX_PID_TREE_TRACE_SIM  8

#define MAX_BUFFERS    3
#define TMP_BUF_IDX    1
#define SUBMIT_BUF_IDX 0
#define STRING_BUF_IDX 1
#define ARGS_IDX       2
#define ENVP_IDX       3

#define EXECVE_GET_SOCK_FD_LIMIT  8
#define EXECVE_GET_SOCK_PID_LIMIT 4

enum hades_ebpf_config { CONFIG_HADES_PID, CONFIG_FILTERS };

/* map macro defination */
#define BPF_MAP(_name, _type, _key_type, _value_type, _max_entries)            \
    struct {                                                                   \
        __uint(type, _type);                                                   \
        __uint(max_entries, _max_entries);                                     \
        __type(key, _key_type);                                                \
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
typedef struct simple_buf {
    __u8 buf[MAX_PERCPU_BUFSIZE];
} buf_t;

/* general context for all events */
typedef struct data_context {
    __u64 ts;        // timestamp
    __u64 cgroup_id; // cgroup_id
    __u32 pns;       // in Elkeid, they use pid_inum and root_pid_inum. TODO: go
                     // through this
    __u32 dt;        // type of struct
    __u32 pid;       // processid
    __u32 tid;       // thread id
    __u32 uid;       // user id
    __u32 gid;       // group id
    __u32 ppid; // parent pid => which is tpid, pid is for the kernel space. In
                // user space, it's tgid actually
    __u32 pgid; // process group id
    __u32 sessionid;
    char comm[TASK_COMM_LEN];    // command
    char pcomm[TASK_COMM_LEN];   // parent command
    char nodename[MAX_NODENAME]; // uts_name => 64, in tracee, it's 16 here
    __s64 retval;                // return value(useful when it's exit or kill)
    __u8 argnum;                 // argnum
} context_t;

/* general field for event */
typedef struct event_data {
    struct task_struct *task; // current task_struct
    context_t context;        // context: general fields for all hooks
    buf_t *submit_p;
    __u32 buf_off; // offset of the buf_t
    void *ctx;
} event_data_t;

/* general field for filter string */
typedef struct string {
    char str[MAX_STR_FILTER_SIZE];
} string_t;

/*
 * mnt_namespace changes since kernel version 5.11
 */
#ifndef CORE
struct mnt_namespace {
    atomic_t count;
    struct ns_common ns;
};

struct mount {
    struct hlist_node mnt_hash;
    struct mount *mnt_parent;
    struct dentry *mnt_mountpoint;
    struct vfsmount mnt;
};
#endif

typedef struct network_connection_v4 {
    __u32 local_address;
    __u16 local_port;
    __u32 remote_address;
    __u16 remote_port;
} net_conn_v4_t;

typedef struct network_connection_v6 {
    struct in6_addr local_address;
    __u16 local_port;
    struct in6_addr remote_address;
    __u16 remote_port;
    __u32 flowinfo;
    __u32 scope_id;
} net_conn_v6_t;

/* configs */
BPF_HASH(config_map, __u32, __u64, 512);

/* filters */
BPF_HASH(pid_filter, __u32, __u32, 512);
BPF_HASH(uid_filter, __u32, __u32, 512);
BPF_HASH(cgroup_id_filter, __u64, __u32, 512);
BPF_HASH(pns_filter, __u32, __u32, 512);
BPF_ARRAY(path_filter, string_t, 3);
/*internal maps (caches) */

/* perf_output for events */
BPF_PERF_OUTPUT(exec_events, 1024);
BPF_PERF_OUTPUT(file_events, 1024);
BPF_PERF_OUTPUT(net_events, 1024);
/* optimize the performance with ringbuf */
#ifdef ENABLE_RINGBUF
#define BPF_RINGBUF_OUTPUT(_name, _key_type, _value_type, _max_entries)   \
    BPF_MAP(_name, BPF_MAP_TYPE_RINGBUF, _key_type, _value_type, _max_entries)
BPF_RINGBUF_OUTPUT(exec_events_ringbuf, 1024);
BPF_RINGBUF_OUTPUT(file_events_ringbuf, 1024);
BPF_RINGBUF_OUTPUT(net_events_ringbuf, 1024);
#endif

BPF_PERCPU_ARRAY(bufs, buf_t, 4);
BPF_PERCPU_ARRAY(bufs_off, __u32, MAX_BUFFERS);

#ifdef CORE
#define get_kconfig(x) get_kconfig_val(x)
#else
#define get_kconfig(x) CONFIG_##x
#endif

#ifdef CORE
#define ARCH_HAS_SYSCALL_WRAPPER 1000U
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
#define READ_KERN(ptr)                                                         \
    ({                                                                         \
        typeof(ptr) _val;                                                      \
        __builtin_memset((void *)&_val, 0, sizeof(_val));                      \
        bpf_probe_read((void *)&_val, sizeof(_val), &ptr);                     \
        _val;                                                                  \
    })
#define READ_USER(ptr)                                                         \
    ({                                                                         \
        typeof(ptr) _val;                                                      \
        __builtin_memset((void *)&_val, 0, sizeof(_val));                      \
        bpf_probe_read_user((void *)&_val, sizeof(_val), &ptr);                \
        _val;                                                                  \
    })
#else // CORE
#define GET_FIELD_ADDR(field) __builtin_preserve_access_index(&field)
#define READ_KERN(ptr)                                                         \
    ({                                                                         \
        typeof(ptr) _val;                                                      \
        __builtin_memset((void *)&_val, 0, sizeof(_val));                      \
        bpf_core_read((void *)&_val, sizeof(_val), &ptr);                      \
        _val;                                                                  \
    })
#define READ_USER(ptr)                                                         \
    ({                                                                         \
        typeof(ptr) _val;                                                      \
        __builtin_memset((void *)&_val, 0, sizeof(_val));                      \
        bpf_core_read_user((void *)&_val, sizeof(_val), &ptr);                 \
        _val;                                                                  \
    })
#endif

/* array related function */
static __always_inline buf_t *get_buf(int idx)
{
    return bpf_map_lookup_elem(&bufs, &idx);
}

static __always_inline void set_buf_off(int buf_idx, __u32 new_off)
{
    bpf_map_update_elem(&bufs_off, &buf_idx, &new_off, BPF_ANY);
}

static __always_inline __u32 *get_buf_off(int buf_idx)
{
    return bpf_map_lookup_elem(&bufs_off, &buf_idx);
}

// mount
static inline struct mount *real_mount(struct vfsmount *mnt)
{
    // get address from member
    return container_of(mnt, struct mount, mnt);
}

static __always_inline __u64 *get_config(__u32 key)
{
    return bpf_map_lookup_elem(&config_map, &key);
}

/* config */
// #define DENY_BPF                  0
#define STEXT                     0
#define ETEXT                     1
#define HADES_PGID_KEY            2
/* hook point id */
#define SYS_ENTER_MEMFD_CREATE    614
#define SYS_ENTER_EXECVEAT        698
#define SYS_ENTER_EXECVE          700
#define COMMIT_CREDS              1011
#define SYS_ENTER_PRCTL           1020
#define SYS_ENTER_PTRACE          1021
#define SYSCONNECT                1022
#define SECURITY_SOCKET_BIND      1024
#define UDP_RECVMSG               1025
#define DO_INIT_MODULE            1026
#define SECURITY_KERNEL_READ_FILE 1027
#define SECURITY_INODE_CREATE     1028
#define SECURITY_SB_MOUNT         1029
#define CALL_USERMODEHELPER       1030
#define SECURITY_INODE_RENAME     1031
#define SECURITY_INODE_LINK       1032
// uprobe
#define BASH_READLINE             2000
// rootkit field
#define ANTI_RKT_SCT              1200
#define ANTI_RKT_IDT              1201
#define ANTI_RKT_FOPS             1202
#define ANTI_RKT_MODULE           1203
#define SYS_BPF                   1204
// honeypot
#define HONEYPOT_PORTSCAN_DETECT  3000

struct syscall_enter_args {
	unsigned long long common_tp_fields;
	long		       syscall_nr;
	unsigned long	   args[6];
};

struct syscall_exit_args {
    unsigned long long unused;
    long syscall_nr;
    long ret;
};

#endif //__DEFINE_H