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

#include "common.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"

#define TASK_COMM_LEN 16
#define UTS_NAME_LEN 64
#define TTY_NAME_LEN 64

// describe the data from task_struct 
struct task_context {
    __u64 ts;       // timestamp
    __u64 uts_inum; // unix-time-sharing nsproxy inum
    __u64 parent_uts_inum;
    __u64 cgroup_id;
    __u32 pid;      // process id
    __u32 tid;      // thread id
    __u32 ppid;     // parent id
    __u32 uid;      // user id
    __u32 gid;      // group id
    __u32 sessionid;
    char comm[TASK_COMM_LEN];   // command
    char pcomm[TASK_COMM_LEN];  // parent command
    /*
        The length of the fields in the struct varies. Some operating systems or libraries use a
       hardcoded 9 or 33 or 65 or 257.  Other systems use SYS_NMLN or _SYS_NMLN or UTSLEN or
       _UTSNAME_LENGTH
       But a post from 2006 says that it's 64(with the termininating of \0, so 65 bytes)
       but I find that it's always 65 in vmlinux.h. And I set this as 65
    */
    char nodename[UTS_NAME_LEN + 1];
    char ttyname[TTY_NAME_LEN];
}