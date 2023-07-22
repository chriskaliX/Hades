#ifndef __UTILS_H
#define __UTILS_H
#ifndef CORE
#include <linux/sched.h>
#include <linux/fdtable.h>
#include <linux/mm_types.h>
#include <net/ipv6.h>
#include <linux/ipv6.h>
#include <linux/pid_namespace.h>
#include <uapi/linux/magic.h>
#else
#include <vmlinux.h>
#include <missing_definitions.h>
#endif

#include <utils_buf.h>
#include "bpf_helpers.h"
#include "bpf_core_read.h"
#include "bpf_endian.h"

#ifdef CORE
    #define PIPEFS_MAGIC 0x50495045
    #define SOCKFS_MAGIC 0x534F434B
#endif

static __always_inline int get_task_pgid(const struct task_struct *cur_task)
{
    int pgid = 0;

    /* ns info from thread_pid */
    struct pid *thread_pid = READ_KERN(cur_task->thread_pid);
    struct pid_namespace *ns_info = (struct pid_namespace *)0;
    if (thread_pid != 0) {
        int l = READ_KERN(thread_pid->level);
        struct upid thread_upid = READ_KERN(thread_pid->numbers[l]);
        ns_info = thread_upid.ns;
    }
    /* upid info from signal */
    struct signal_struct *signal = READ_KERN(cur_task->signal);
    struct pid *pid_p = (struct pid *)0;
    bpf_probe_read(&pid_p, sizeof(struct pid *), &signal->pids[PIDTYPE_PGID]);
    int level = READ_KERN(pid_p->level);
    struct upid upid = READ_KERN(pid_p->numbers[level]);
    if (upid.ns == ns_info) {
        pgid = upid.nr;
    }
    return pgid;
}

/* R3 max value is outside of the array range */
// 这个地方非常非常的坑，都因为 bpf_verifier 机制, 之前 buf_off > MAX_PERCPU_BUFSIZE - sizeof(int) 本身都是成立的
// 前面明明有一个更为严格的 data->buf_off > (MAX_PERCPU_BUFSIZE) - (MAX_STRING_SIZE) - sizeof(int)，但是不行
// 在每次调 index 之前都需要 check 一下，所以看源码的时候很多地方会写：To satisfied the verifier...
// TODO: 写一个文章记录一下这个...

/* init_context */
static __always_inline int init_context(context_t *context,
                                        struct task_struct *task)
{
    struct task_struct *realparent = READ_KERN(task->real_parent);
    context->ppid = READ_KERN(realparent->tgid);
    context->ts = bpf_ktime_get_ns();
    u64 id = bpf_get_current_uid_gid();
    context->uid = id;
    context->gid = id >> 32;
    id = bpf_get_current_pid_tgid();
    context->pid = id;
    context->tid = id >> 32;
    context->cgroup_id = bpf_get_current_cgroup_id();
    context->pgid = get_task_pgid(task);
    // namespace information
    // Elkeid - ROOT_PID_NS_INUM = task->nsproxy->pid_ns_for_children->ns.inum;
    // namespace: https://zhuanlan.zhihu.com/p/307864233
    struct nsproxy *nsp = READ_KERN(task->nsproxy);
    struct uts_namespace *uts_ns = READ_KERN(nsp->uts_ns);
    struct pid_namespace *pid_ns = READ_KERN(nsp->pid_ns_for_children);
    // nodename
    bpf_probe_read_str(&context->nodename, sizeof(context->nodename),
                       &uts_ns->name.nodename);
    // pid_namespace
    context->pns = READ_KERN(pid_ns->ns.inum);
    // For root pid_namespace, it's not that easy in eBPF. The way that we can get pid=1 task
    // is to lookup (task->parent) recursively. And We should not do this for every time. (cache)
    // Also, we should considered the situation that we can not get in the very first time
    // since we used a bounded loop to get the root pid (The NUM 1 pid)
    // Still, I think it's fine if we just get the root pid_namespace from usersapce. I do not
    // catch the reason that Elkeid get this in root.
    // sessionid
    bpf_probe_read(&context->sessionid, sizeof(context->sessionid),
                   &task->sessionid);
    // This may changed since
    bpf_probe_read_str(&context->pcomm, sizeof(context->pcomm),
                       &realparent->comm);
    bpf_get_current_comm(&context->comm, sizeof(context->comm));
    context->argnum = 0;
    return 0;
}

// this is kernel space simple filter, also userspace filter will be supported
// 0 on false & 1 on true
static __always_inline int context_filter(context_t *context)
{
    u64 *pgid_p = get_config(HADES_PGID_KEY);
    if (pgid_p == NULL) {
        return 0;
    }
    // filter by the pgid, all agent and plugins are reliable by default
    if (context->pgid == *pgid_p)
        return 1;
    // ID filter for all
    if (bpf_map_lookup_elem(&pid_filter, &context->tid) != 0)
        return 1;
    if (bpf_map_lookup_elem(&uid_filter, &context->uid) != 0)
        return 1;
    if (bpf_map_lookup_elem(&cgroup_id_filter, &context->cgroup_id) != 0)
        return 1;
    if (bpf_map_lookup_elem(&pns_filter, &context->pns) != 0)
        return 1;
    return 0;
}

/*
 * Filter in kernel space, mainly for remote addr, cidr
 * is supported as well. Now, it's only ipv4, for test
 */
static __always_inline int ipfilter(__u32 ip)
{
#ifdef CORE

#endif
    return 0;
}

/* ==== get ==== */

static __always_inline void *get_task_tty_str(struct task_struct *task)
{
    // Get per-cpu string buffer
    buf_t *string_p = get_buf(STRING_BUF_IDX);
    int size = 0;
    if (string_p == NULL)
        return NULL;
    struct signal_struct *signal =
            (struct signal_struct *)READ_KERN(task->signal);
    if (signal == NULL)
        goto exit;
    struct tty_struct *tty = (struct tty_struct *)READ_KERN(signal->tty);
    if (tty == NULL)
        goto exit;
    size = bpf_probe_read_str(&(string_p->buf[0]), 64, &tty->name);
exit:
    if (size < 1) {
        char nothing[] = "-1";
        bpf_probe_read_str(&(string_p->buf[0]), MAX_STRING_SIZE, nothing);
    }
    return &string_p->buf[0];
}

static __always_inline unsigned long
get_inode_nr_from_dentry(struct dentry *dentry)
{
    struct inode *d_inode = READ_KERN(dentry->d_inode);
    return READ_KERN(d_inode->i_ino);
}

// source code: __prepend_path
// http://blog.sina.com.cn/s/blog_5219094a0100calt.html
// get_path_str for now is only used by get_fraw_str, so we need to extract the inode to userspace
// let the userspace cope with the string convert, which is inproper in kernel space.
static __always_inline void *get_path_str(struct path *path, event_data_t *data, u8 index)
{
    struct path f_path;
    bpf_probe_read(&f_path, sizeof(struct path), path);
    char slash = '/';
    int zero = 0;
    struct dentry *dentry = f_path.dentry;
    struct vfsmount *vfsmnt = f_path.mnt;
    struct mount *mnt_parent_p;
    struct mount *mnt_p = real_mount(vfsmnt); // get mount by vfsmnt
    bpf_probe_read(&mnt_parent_p, sizeof(struct mount *), &mnt_p->mnt_parent);
    // from the middle, to avoid rewrite by this
    u32 buf_off = (MAX_PERCPU_BUFSIZE >> 1);
    struct dentry *mnt_root;
    struct dentry *d_parent;
    struct qstr d_name;
    unsigned int len;
    unsigned int off;
    int sz;
    // get per-cpu string buffer
    buf_t *string_p = get_buf(STRING_BUF_IDX);
    if (string_p == NULL)
        return NULL;
    // inode for the magic
    unsigned long inode = 0;
    char pipe_prefix[] = "pipe:";
    char socket_prefix[] = "socket:";

#pragma unroll
    for (int i = 0; i < MAX_PATH_COMPONENTS; i++) { // const to debug
        mnt_root = READ_KERN(vfsmnt->mnt_root);
        d_parent = READ_KERN(dentry->d_parent);
        // 1. dentry == d_parent means we reach the dentry root
        // 2. dentry == mnt_root means we reach the mount root, they share the same dentry
        if (dentry == mnt_root || dentry == d_parent) {
            // We reached root, but not mount root - escaped?
            if (dentry != mnt_root) {
                break;
            }
            // dentry == mnt_root, but the mnt has not reach it's root
            // so update the dentry as the mnt_mountpoint(in order to continue the dentry loop for the mountpoint)
            // We reached root, but not global root - continue with mount point path
            if (mnt_p != mnt_parent_p) {
                bpf_probe_read(&dentry, sizeof(struct dentry *), &mnt_p->mnt_mountpoint);
                bpf_probe_read(&mnt_p, sizeof(struct mount *), &mnt_p->mnt_parent);
                bpf_probe_read(&mnt_parent_p, sizeof(struct mount *), &mnt_p->mnt_parent);
                vfsmnt = &mnt_p->mnt;
                continue;
            }
            // dentry == mnt_root && mnt_p == mnt_parent_p, real root for all
            // Global root - path fully parsed
            break;
        }
        // Add this dentry name to path
        d_name = READ_KERN(dentry->d_name);
        len = (d_name.len + 1) & (MAX_STRING_SIZE - 1);
        off = buf_off - len;
        sz = 0;
        if (off <= buf_off) { // verify no wrap occurred
            len = len & (((MAX_PERCPU_BUFSIZE) >> 1) - 1);
            sz = bpf_probe_read_str(
                    &(string_p->buf[off & ((MAX_PERCPU_BUFSIZE >> 1) - 1)]),
                    len, (void *)d_name.name);
        } else
            break;
        if (sz > 1) {
            buf_off -= 1; // remove null byte termination with slash sign
            bpf_probe_read(&(string_p->buf[buf_off & (MAX_PERCPU_BUFSIZE - 1)]),
                           1, &slash);
            buf_off -= sz - 1;
        } else {
            // If sz is 0 or 1 we have an error (path can't be null nor an empty string)
            break;
        }
        dentry = d_parent;
    }

    // no path avaliable.
    // let the userspace to checkout this
    if (buf_off == (MAX_PERCPU_BUFSIZE >> 1)) {
        // memfd files have no path in the filesystem -> extract their name
        buf_off = 0;
        // Handle pipe with d_name.len = 0
        struct super_block *d_sb = READ_KERN(dentry->d_sb);
        if (d_sb != 0) {
            unsigned long s_magic = READ_KERN(d_sb->s_magic);
             // here, we just need `PIPE` & `SOCKET`. see more magic: https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/magic.h#L86
            switch (s_magic) {
            case PIPEFS_MAGIC:
                bpf_probe_read_str(&(string_p->buf[0]), MAX_STRING_SIZE, (void *)pipe_prefix);
            case SOCKFS_MAGIC:
                bpf_probe_read_str(&(string_p->buf[0]), MAX_STRING_SIZE, (void *)socket_prefix);
            default:
                goto out;                    
            }
            inode = get_inode_nr_from_dentry(dentry);
            goto out;
        }
        d_name = READ_KERN(dentry->d_name);
        if (d_name.len > 0) {
            bpf_probe_read_str(&(string_p->buf[0]), MAX_STRING_SIZE, (void *)d_name.name);
            goto out;
        }
    } else {
        // Add leading slash
        buf_off -= 1;
        bpf_probe_read(&(string_p->buf[buf_off & ((MAX_PERCPU_BUFSIZE)-1)]), 1, &slash);
        // Null terminate the path string
        bpf_probe_read(&(string_p->buf[((MAX_PERCPU_BUFSIZE) >> 1) - 1]), 1, &zero);
    }

out:
    set_buf_off(STRING_BUF_IDX, buf_off);
    save_str_to_buf(data, (void *)&string_p->buf[buf_off & (MAX_PERCPU_BUFSIZE - 1)], index);
    if (inode > 0) {
        save_to_submit_buf(data, &inode, sizeof(inode), index);
    }
    return NULL;

}

// strip fs judgement version, for shorter insts
static __always_inline void *get_path_str_simple(struct path *path)
{
    struct path f_path;
    bpf_probe_read(&f_path, sizeof(struct path), path);
    char slash = '/';
    int zero = 0;
    struct dentry *dentry = f_path.dentry;
    struct vfsmount *vfsmnt = f_path.mnt;
    struct mount *mnt_parent_p;
    struct mount *mnt_p = real_mount(vfsmnt); // get mount by vfsmnt
    bpf_probe_read(&mnt_parent_p, sizeof(struct mount *), &mnt_p->mnt_parent);
    // from the middle, to avoid rewrite by this
    u32 buf_off = (MAX_PERCPU_BUFSIZE >> 1);
    struct dentry *mnt_root;
    struct dentry *d_parent;
    struct qstr d_name;
    unsigned int len;
    unsigned int off;
    int sz;
    // get per-cpu string buffer
    buf_t *string_p = get_buf(STRING_BUF_IDX);
    if (string_p == NULL)
        return NULL;

#pragma unroll
    for (int i = 0; i < MAX_PATH_COMPONENTS_SIM; i++) {
        mnt_root = READ_KERN(vfsmnt->mnt_root);
        d_parent = READ_KERN(dentry->d_parent);
        // 1. dentry == d_parent means we reach the dentry root
        // 2. dentry == mnt_root means we reach the mount root, they share the same dentry
        if (dentry == mnt_root || dentry == d_parent) {
            // We reached root, but not mount root - escaped?
            if (dentry != mnt_root) {
                break;
            }
            // dentry == mnt_root, but the mnt has not reach it's root
            // so update the dentry as the mnt_mountpoint(in order to continue the dentry loop for the mountpoint)
            // We reached root, but not global root - continue with mount point path
            if (mnt_p != mnt_parent_p) {
                bpf_probe_read(&dentry, sizeof(struct dentry *),
                               &mnt_p->mnt_mountpoint);
                bpf_probe_read(&mnt_p, sizeof(struct mount *),
                               &mnt_p->mnt_parent);
                bpf_probe_read(&mnt_parent_p, sizeof(struct mount *),
                               &mnt_p->mnt_parent);
                vfsmnt = &mnt_p->mnt;
                continue;
            }
            // dentry == mnt_root && mnt_p == mnt_parent_p, real root for all
            // Global root - path fully parsed
            break;
        }
        // Add this dentry name to path
        d_name = READ_KERN(dentry->d_name);
        len = (d_name.len + 1) & (MAX_STRING_SIZE - 1);
        off = buf_off - len;
        sz = 0;
        if (off <= buf_off) { // verify no wrap occurred
            len = len & (((MAX_PERCPU_BUFSIZE) >> 1) - 1);
            sz = bpf_probe_read_str(
                    &(string_p->buf[off & ((MAX_PERCPU_BUFSIZE >> 1) - 1)]),
                    len, (void *)d_name.name);
        } else
            break;
        if (sz > 1) {
            buf_off -= 1; // remove null byte termination with slash sign
            bpf_probe_read(&(string_p->buf[buf_off & (MAX_PERCPU_BUFSIZE - 1)]),
                           1, &slash);
            buf_off -= sz - 1;
        } else {
            // If sz is 0 or 1 we have an error (path can't be null nor an empty string)
            break;
        }
        dentry = d_parent;
    }

    // no path avaliable.
    if (buf_off == (MAX_PERCPU_BUFSIZE >> 1)) {
        buf_off = 0;
        d_name = READ_KERN(dentry->d_name);
        bpf_probe_read_str(&(string_p->buf[0]), MAX_STRING_SIZE, (void *) d_name.name);
    } else {
        // Add leading slash
        buf_off -= 1;
        bpf_probe_read(&(string_p->buf[buf_off & ((MAX_PERCPU_BUFSIZE)-1)]), 1,
                       &slash);
        // Null terminate the path string
        bpf_probe_read(&(string_p->buf[((MAX_PERCPU_BUFSIZE) >> 1) - 1]), 1,
                       &zero);
    }
    set_buf_off(STRING_BUF_IDX, buf_off);
    return &string_p->buf[buf_off];
}

// all from tracee
static __always_inline void *get_dentry_path_str(struct dentry *dentry)
{
    char slash = '/';
    int zero = 0;

    u32 buf_off = (MAX_PERCPU_BUFSIZE >> 1);

    // Get per-cpu string buffer
    buf_t *string_p = get_buf(STRING_BUF_IDX);
    if (string_p == NULL)
        return NULL;

#pragma unroll
    for (int i = 0; i < MAX_PATH_COMPONENTS; i++) {
        struct dentry *d_parent = READ_KERN(dentry->d_parent);
        if (dentry == d_parent) {
            break;
        }
        // Add this dentry name to path
        struct qstr d_name = READ_KERN(dentry->d_name);
        unsigned int len = (d_name.len + 1) & (MAX_STRING_SIZE - 1);
        unsigned int off = buf_off - len;
        // Is string buffer big enough for dentry name?
        int sz = 0;
        if (off <= buf_off) { // verify no wrap occurred
            len = len & ((MAX_PERCPU_BUFSIZE >> 1) - 1);
            sz = bpf_probe_read_str(
                    &(string_p->buf[off & ((MAX_PERCPU_BUFSIZE >> 1) - 1)]),
                    len, (void *)d_name.name);
        } else
            break;
        if (sz > 1) {
            buf_off -= 1; // remove null byte termination with slash sign
            bpf_probe_read(&(string_p->buf[buf_off & (MAX_PERCPU_BUFSIZE - 1)]),
                           1, &slash);
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
        struct qstr d_name = READ_KERN(dentry->d_name);
        bpf_probe_read_str(&(string_p->buf[0]), MAX_STRING_SIZE,
                           (void *)d_name.name);
    } else {
        // Add leading slash
        buf_off -= 1;
        bpf_probe_read(&(string_p->buf[buf_off & (MAX_PERCPU_BUFSIZE - 1)]), 1,
                       &slash);
        // Null terminate the path string
        bpf_probe_read(&(string_p->buf[(MAX_PERCPU_BUFSIZE >> 1) - 1]), 1,
                       &zero);
    }

    set_buf_off(STRING_BUF_IDX, buf_off);
    return &string_p->buf[buf_off];
}

/* Be careful about inet_rcv_addr & inet_saddr
 * There are some differences between inet_rcv_addr/inet_saddr and inet_num/inet_sport
 * For inet_num & inet_sport: inet_sport = hton(inet_num)
 * For inet_rcv_addr & inet_saddr: 
 *     inet_rcv_addr: Bound local IPv4 addr
 *     inet_saddr: Sending source
 */ 
static __always_inline int
get_network_details_from_sock_v4(struct sock *sk, net_conn_v4_t *net_details,
                                 int peer)
{
    struct inet_sock *inet = (struct inet_sock *)sk;
    if (!peer) {
        net_details->local_address = READ_KERN(inet->inet_rcv_saddr);
        net_details->local_port = bpf_ntohs(READ_KERN(inet->inet_num));
        net_details->remote_address = READ_KERN(inet->inet_daddr);
        net_details->remote_port = READ_KERN(inet->inet_dport);
    } else {
        net_details->remote_address = READ_KERN(inet->inet_rcv_saddr);
        net_details->remote_port = bpf_ntohs(READ_KERN(inet->inet_num));
        net_details->local_address = READ_KERN(inet->inet_daddr);
        net_details->local_port = READ_KERN(inet->inet_dport);
    }
    return 0;
}

/* all down here is for the tracee */
/* for the ipv6 thing */
static __always_inline volatile unsigned char get_sock_state(struct sock *sock)
{
    volatile unsigned char sk_state_own_impl;
    bpf_probe_read((void *)&sk_state_own_impl, sizeof(sk_state_own_impl),
                   (const void *)&sock->sk_state);
    return sk_state_own_impl;
}

static __always_inline struct ipv6_pinfo *
get_inet_pinet6(struct inet_sock *inet)
{
    struct ipv6_pinfo *pinet6_own_impl;
    bpf_probe_read(&pinet6_own_impl, sizeof(pinet6_own_impl), &inet->pinet6);
    return pinet6_own_impl;
}

static __always_inline struct ipv6_pinfo *
inet6_sk_own_impl(struct sock *__sk, struct inet_sock *inet)
{
    volatile unsigned char sk_state_own_impl;
    sk_state_own_impl = get_sock_state(__sk);

    struct ipv6_pinfo *pinet6_own_impl;
    pinet6_own_impl = get_inet_pinet6(inet);

    bool sk_fullsock =
            (1 << sk_state_own_impl) & ~(TCPF_TIME_WAIT | TCPF_NEW_SYN_RECV);
    return sk_fullsock ? pinet6_own_impl : NULL;
}

// From tracee
static __always_inline int
get_network_details_from_sock_v6(struct sock *sk, net_conn_v6_t *net_details,
                                 int peer)
{
    struct inet_sock *inet = (struct inet_sock *)sk;
    struct ipv6_pinfo *np = inet6_sk_own_impl(sk, inet);
    struct in6_addr addr = {};
    addr = READ_KERN(sk->sk_v6_rcv_saddr);
    if (ipv6_addr_any(&addr)) {
        addr = READ_KERN(np->saddr);
    }
    // the flowinfo field can be specified by the user to indicate a network
    // flow. how it is used by the kernel, or whether it is enforced to be
    // unique is not so obvious.  getting this value is only supported by the
    // kernel for outgoing packets using the 'struct ipv6_pinfo'.  in any case,
    // leaving it with value of 0 won't affect our representation of network
    // flows.
    net_details->flowinfo = 0;

    // the scope_id field can be specified by the user to indicate the network
    // interface from which to send a packet. this only applies for link-local
    // addresses, and is used only by the local kernel.  getting this value is
    // done by using the 'ipv6_iface_scope_id(const struct in6_addr *addr, int
    // iface)' function.  in any case, leaving it with value of 0 won't affect
    // our representation of network flows.
    net_details->scope_id = 0;
    if (peer) {
        net_details->local_address = READ_KERN(sk->sk_v6_daddr);
        net_details->local_port = READ_KERN(inet->inet_dport);
        net_details->remote_address = addr;
        net_details->remote_port = READ_KERN(inet->inet_sport);
    } else {
        net_details->local_address = addr;
        net_details->local_port = READ_KERN(inet->inet_sport);
        net_details->remote_address = READ_KERN(sk->sk_v6_daddr);
        net_details->remote_port = READ_KERN(inet->inet_dport);
    }
    return 0;
}

static __always_inline int get_remote_sockaddr_in_from_network_details(
        struct sockaddr_in *addr, net_conn_v4_t *net_details, u16 family)
{
    addr->sin_family = family;
    addr->sin_port = net_details->remote_port;
    addr->sin_addr.s_addr = net_details->remote_address;
    return 0;
}

static __always_inline int get_remote_sockaddr_in6_from_network_details(
        struct sockaddr_in6 *addr, net_conn_v6_t *net_details, u16 family)
{
    addr->sin6_family = family;
    addr->sin6_port = net_details->remote_port;
    addr->sin6_flowinfo = net_details->flowinfo;
    addr->sin6_addr = net_details->remote_address;
    addr->sin6_scope_id = net_details->scope_id;

    return 0;
}

static __always_inline int get_local_sockaddr_in_from_network_details(
        struct sockaddr_in *addr, net_conn_v4_t *net_details, u16 family)
{
    addr->sin_family = family;
    addr->sin_port = net_details->local_port;
    addr->sin_addr.s_addr = net_details->local_address;

    return 0;
}

static __always_inline struct file *file_get_raw(u64 fd_num)
{
    // get current task
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (task == NULL)
        return NULL;
    // get files
    struct files_struct *files = (struct files_struct *)READ_KERN(task->files);
    if (files == NULL)
        return NULL;
    // get fdtable
    struct fdtable *fdt = (struct fdtable *)READ_KERN(files->fdt);
    if (fdt == NULL)
        return NULL;
    struct file **fd = (struct file **)READ_KERN(fdt->fd);
    if (fd == NULL)
        return NULL;
    struct file *f = (struct file *)READ_KERN(fd[fd_num]);
    if (f == NULL)
        return NULL;

    return f;
}

static __always_inline struct fs_struct *get_task_fs(struct task_struct *task)
{
    return READ_KERN(task->fs);
}

static __always_inline const struct cred *
get_task_real_cred(struct task_struct *task)
{
    return READ_KERN(task->real_cred);
}

// change this as filename rather than f_path
static __always_inline void *get_fraw_str(u64 num, event_data_t *data, u8 index)
{
    char nothing[] = "-1";
    // This should not happen
    buf_t *string_p = get_buf(STRING_BUF_IDX);
    if (string_p == NULL)
        return NULL;
    // get the fd if it exists, then return nothing
    struct file *file = file_get_raw(num);
    if (!file) {
        save_str_to_buf(data, nothing, index);
        return NULL;
    }
    // the real get path function, send inside this
    struct path p = READ_KERN(file->f_path);
    get_path_str(GET_FIELD_ADDR(p), data, index); // for debug
    return NULL;
}

/* Reference: http://jinke.me/2018-08-23-socket-and-linux-file-system/ */
static __always_inline int get_socket_info_sub(event_data_t *data,
                                               struct fdtable *fdt, u8 index)
{
    struct socket *socket;
    struct sock *sk;
    struct file **fd;
    struct file *file;
    struct path f_path;
    struct dentry *dentry;

    u16 family;
    int state;
    // 跨 bpf program 做 read 数据传输
    buf_t *string_p = get_buf(STRING_BUF_IDX);
    if (string_p == NULL)
        return -1;
    // get max fds, but max_fds seems to be way too large than 8
    unsigned long max_fds;
    bpf_probe_read(&max_fds, sizeof(max_fds), &fdt->max_fds);
    fd = (struct file **)READ_KERN(fdt->fd);
    if (fd == NULL)
        return 0;
// unroll since unbounded loop is not supported < kernel version 5.3
#pragma unroll
    for (int i = 0; i < 8; i++) {
        if (i == max_fds)
            break;
        file = (struct file *)READ_KERN(fd[i]);
        if (!file)
            continue;
        bpf_probe_read(&f_path, sizeof(struct path), &file->f_path);
        dentry = f_path.dentry;
        // change to magic, maybe better since their is no string comparison
        struct super_block *d_sb = READ_KERN(dentry->d_sb);
        if (d_sb != 0) {
            unsigned long s_magic = READ_KERN(d_sb->s_magic);
            if (s_magic == SOCKFS_MAGIC) {
                socket = READ_KERN(file->private_data);
                if (socket == NULL)
                    continue;
                state = READ_KERN(socket->state);
                if (state != SS_CONNECTING && state != SS_CONNECTED &&
                    state != SS_DISCONNECTING)
                    continue;
                sk = READ_KERN(socket->sk);
                if (!sk)
                    continue;
                family = READ_KERN(sk->sk_family);
                if (family == AF_INET) {
                    net_conn_v4_t net_details = {};
                    save_to_submit_buf(data, &family, sizeof(u16), index);
                    get_network_details_from_sock_v4(sk, &net_details, 0);
                    save_to_submit_buf(data, &net_details, sizeof(struct network_connection_v4), index);
                    return 1;
                } else if (family == AF_INET6) {
                    net_conn_v6_t net_details = {};
                    save_to_submit_buf(data, &family, sizeof(u16), index);
                    get_network_details_from_sock_v6(sk, &net_details, 0);
                    save_to_submit_buf(data, &net_details, sizeof(struct network_connection_v6), index);
                    return 1;
                }
            }
        }
    }
    return 0;
}

/* get socket information by going though the process tree
 * only process known states: SS_CONNECTING/SS_CONNECTED/SS_DISCONNECTING,
 * SS_FREE/SS_UNCONNECTED or any possible new states are to be skipped */
static __always_inline __u32 get_socket_info(event_data_t *data, u8 index)
{
    net_conn_v4_t net_details = {};
    struct files_struct *files = NULL;
    struct fdtable *fdt = NULL;
    int family = 0;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (task == NULL)
        goto exit;
    __u32 pid;
    int flag;
#pragma unroll
    for (int i = 0; i < 4; i++) {
        pid = READ_KERN(task->pid);
        // 0 for failed...
        if (pid == 1)
            break;
        // get files
        files = (struct files_struct *)READ_KERN(task->files);
        if (files == NULL)
            goto next_task;
        // get fdtable
        fdt = (struct fdtable *)READ_KERN(files->fdt);
        if (fdt == NULL)
            goto next_task;
        // find out
        flag = get_socket_info_sub(data, fdt, index);
        if (flag == 1)
            return pid;
    next_task:
        task = READ_KERN(task->real_parent);
    }
exit:
    save_to_submit_buf(data, &family, sizeof(u16), index);
    save_to_submit_buf(data, &net_details, sizeof(struct network_connection_v4), index);
    return 0;
}

// it's somehow interesting in Elkeid code(by the good way). it changes from versions
// to versions. Firstly, kernel version range from 4.1.0 - 5.15.0, `get_mm_exe_file`
// is used. internal thing about `rcu` will be introduced in my repo(which I would learn)
// but in bpf, unfortunately, there is no lock we can operate, and no external function
// we can use as well. So I assume that we can only get the exe from task_struct by no
// lock, which may be inaccurate in some situtation.
static __always_inline void *get_exe_from_task(struct task_struct *task)
{
    buf_t *string_p = get_buf(STRING_BUF_IDX);
    if (string_p == NULL)
        return NULL;

    char nothing[] = "-1";
    bpf_probe_read_str(&(string_p->buf[0]), MAX_STRING_SIZE, nothing);

    struct mm_struct *mm = READ_KERN(task->mm);
    if (mm == NULL)
        return &string_p->buf[0];
    struct file *file = READ_KERN(mm->exe_file);
    if (file == NULL)
        return &string_p->buf[0];
    struct path p = READ_KERN(file->f_path);
    void *path = get_path_str_simple(GET_FIELD_ADDR(p));
    if (path == NULL)
        return &string_p->buf[0];
    return path;
}

// Hades wrapper of kernel sockfd_lookup with sock return
static __always_inline struct sock *hades_sockfd_lookup(int fd)
{
    struct file *file = file_get_raw(fd);
    if (file == NULL)
        return NULL;
    // socket_from_file
    const struct file_operations *f_op = READ_KERN(file->f_op);
    if (f_op == NULL)
        return NULL;
    // missing f_op check here
    struct socket *socket = READ_KERN(file->private_data);
    if (socket == NULL)
        return NULL;
    struct sock *sock = READ_KERN(socket->sk);
    return sock;
}

// In tracee, the field protocol is generate by the function `get_sock_protocol`
// which differ from kernel version, kinda interestring, let's find out.
// the sock struct is defined in `net/sock.h`. It's a massive struct, but what
// we need is only protocol.
// In kernel version 4.18, it's like
/*
unsigned int		sk_padding : 1,
            sk_kern_sock : 1,
            sk_no_check_tx : 1,
            sk_no_check_rx : 1,
            sk_userlocks : 4,
            sk_protocol  : 8,
            sk_type      : 16;
#define SK_PROTOCOL_MAX U8_MAX
u16			sk_gso_max_segs;
*/
// while in kernel version 5.6, it changes:
/*
u8			sk_padding : 1,
            sk_kern_sock : 1,
            sk_no_check_tx : 1,
            sk_no_check_rx : 1,
            sk_userlocks : 4;
u8			sk_pacing_shift;
u16			sk_type;
u16			sk_protocol;
*/
// But in lower kernel version, sk_protocol seems change too.
// By the way, CO-RE is not archieve in Hades...But maybe someday would change(soon)...
// So it's going to change when CO-RE enabled.
static __always_inline u16 get_sock_protocol(struct sock *sock)
{
    u16 protocol = 0;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 6, 0))
    bpf_probe_read(&protocol, 1, (void *)(&sock->sk_gso_max_segs) - 3);
#else
    protocol = READ_KERN(sock->sk_protocol);
#endif
    return protocol;
}

static __always_inline int init_event_data(event_data_t *data, void *ctx)
{
    data->task = (struct task_struct *)bpf_get_current_task();
    init_context(&data->context, data->task);
    data->ctx = ctx;
    data->buf_off = sizeof(context_t);
    int buf_idx = SUBMIT_BUF_IDX;
    data->submit_p = bpf_map_lookup_elem(&bufs, &buf_idx);
    if (data->submit_p == NULL)
        return 0;
    return 1;
}

static __always_inline int events_perf_submit(event_data_t *data)
{
#ifdef ENABLE_RINGBUF
    bpf_probe_read(&(data->submit_p->buf[0]), sizeof(context_t),
                   &data->context);
    int size = data->buf_off & (MAX_PERCPU_BUFSIZE - 1);
    void *output_data = data->submit_p->buf;
    return bpf_ringbuf_output(&exec_events_ringbuf, output_data, size, BPF_F_CURRENT_CPU);
#else
    bpf_probe_read(&(data->submit_p->buf[0]), sizeof(context_t),
                   &data->context);
    int size = data->buf_off & (MAX_PERCPU_BUFSIZE - 1);
    void *output_data = data->submit_p->buf;
    return bpf_perf_event_output(data->ctx, &exec_events, BPF_F_CURRENT_CPU,
                                 output_data, size);
#endif
}

#endif //__UTILS_BUF_H