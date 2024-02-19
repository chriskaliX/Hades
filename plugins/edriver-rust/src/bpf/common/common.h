#ifndef __COMMON_H__
#define __COMMON_H__

#include <vmlinux.h>
#include <missing_definitions.h>
#include "print.h"
#include "bpf_core_read.h"
#include "bpf_helpers.h"
#include "bpf_endian.h"

static inline struct mount *real_mount(struct vfsmount *mnt)
{
    return container_of(mnt, struct mount, mnt);
}

static inline struct hds_context init_context(void *ctx, int dt)
{
    struct hds_context c = {
        .ctx = ctx,
        .data_type = dt,
        .sbt = get_percpu_buf(PRINT_CACHE)
    };
    return c; 
}

static inline volatile unsigned char get_sock_state(struct sock *sock)
{
    volatile unsigned char sk_state_own_impl;
    bpf_probe_read(
        (void *) &sk_state_own_impl, sizeof(sk_state_own_impl), (const void *) &sock->sk_state);
    return sk_state_own_impl;
}

static inline struct ipv6_pinfo *get_inet_pinet6(struct inet_sock *inet)
{
    struct ipv6_pinfo *pinet6_own_impl;
    bpf_probe_read(&pinet6_own_impl, sizeof(pinet6_own_impl), &inet->pinet6);
    return pinet6_own_impl;
}


static inline struct ipv6_pinfo *inet6_sk_own_impl(struct sock *__sk, struct inet_sock *inet)
{
    volatile unsigned char sk_state_own_impl;
    sk_state_own_impl = get_sock_state(__sk);

    struct ipv6_pinfo *pinet6_own_impl;
    pinet6_own_impl = get_inet_pinet6(inet);

    bool sk_fullsock = (1 << sk_state_own_impl) & ~(TCPF_TIME_WAIT | TCPF_NEW_SYN_RECV);
    return sk_fullsock ? pinet6_own_impl : NULL;
}

/* notice: char * to void * */
static __noinline int do_u32toa(uint32_t v, void *s, int l)
{
    char t[16] = {0};
    int i;

#pragma unroll
    for (i = 0; i < 12; i++) {
        t[12 - i] = 0x30 + (v % 10);
        v = v / 10;
        if (!v)
            break;
    }
    if (i + 1 > l)
        return 0;
    bpf_probe_read(s, (i + 1) & 15, &t[(12 - i) & 15]);
    return (i + 1);
}

/* pgid */
static __always_inline int get_task_pgid(const struct task_struct *cur_task)
{
    int pgid = 0;

    /* ns info from thread_pid */
    struct pid *thread_pid = BPF_CORE_READ(cur_task, thread_pid);
    struct pid_namespace *ns_info = (struct pid_namespace *)0;
    if (thread_pid != 0) {
        int l = BPF_CORE_READ(thread_pid, level);
        struct upid thread_upid = BPF_CORE_READ(thread_pid, numbers[l]);
        ns_info = thread_upid.ns;
    }
    /* upid info from signal */
    struct signal_struct *signal = BPF_CORE_READ(cur_task, signal);
    struct pid *pid_p = (struct pid *)0;
    bpf_probe_read(&pid_p, sizeof(struct pid *), &signal->pids[PIDTYPE_PGID]);
    int level = BPF_CORE_READ(pid_p, level);
    struct upid upid = BPF_CORE_READ(pid_p, numbers[level]);
    if (upid.ns == ns_info) {
        pgid = upid.nr;
    }
    return pgid;
}

/* tty */
static __always_inline void *get_task_tty(struct task_struct *task)
{
    buf_t *cache = get_percpu_buf(LOCAL_CACHE);
    int size = 0;
    if (cache == NULL)
        return NULL;
    struct signal_struct *signal = (struct signal_struct *)BPF_CORE_READ(task, signal);
    if (signal == NULL)
        goto exit;
    struct tty_struct *tty = (struct tty_struct *)BPF_CORE_READ(signal, tty);
    if (tty == NULL)
        goto exit;
    size = bpf_probe_read_str(&(cache->buf[0]), 64, &tty->name);
exit:
    if (size < 1) {
        char nothing[] = "-1";
        bpf_probe_read_str(&(cache->buf[0]), MAX_STRING_SIZE, nothing);
    }
    return &cache->buf[0];
}

/* ===== Socket info methods (From Elkeid) ====== */
/* 
 * use container_of to revert inode into socket_alloc and get the socket part
 * see code like: https://github.com/raspberrypi/linux/blob/223d1247c0b0c0659a65949b6b9c3de53fd14223/include/net/sock.h#L1611
 */
static inline struct socket *SOCKET_I(struct inode *inode)
{
	return &container_of(inode, struct socket_alloc, vfs_inode)->socket;
}
static inline struct inode *SOCK_INODE(struct socket *socket)
{
	return &container_of(socket, struct socket_alloc, socket)->vfs_inode;
}

#define S_IFMT  00170000
#define S_IFSOCK 0140000
#define S_IFLNK	 0120000
#define S_IFREG  0100000
#define S_IFBLK  0060000
#define S_IFDIR  0040000
#define S_IFCHR  0020000
#define S_IFIFO  0010000
#define S_ISUID  0004000
#define S_ISGID  0002000
#define S_ISVTX  0001000

static __noinline struct socket *socket_from_file(struct file *file)
{
    struct inode *inode;
    struct socket *sock = NULL;
    umode_t mode;

    inode = (struct inode *)BPF_CORE_READ(file, f_inode);
    if (!inode)
        goto errorout;

    mode = (umode_t)BPF_CORE_READ(inode, i_mode);
    if (((mode) & S_IFMT) == S_IFSOCK)
        sock = SOCKET_I(inode);
errorout:
    return sock;
}

static __noinline struct sock *find_sock_internal(struct file **fds, int nr, int max)
{
    struct sock *sk = NULL;
    u16 family;
    if (nr >= max)
        goto out;
    struct file *file;
    bpf_core_read(&file, sizeof(void *), &fds[nr]);
    if (!file)
        goto out;

    struct socket *sock = socket_from_file(file);
    if (!sock)
        goto out;
    
    socket_state state = BPF_CORE_READ(sock, state);
    if (state == SS_CONNECTING || state == SS_CONNECTED ||
        state == SS_DISCONNECTING) {
        sk = BPF_CORE_READ(sock, sk);
        if (!sk)
            goto out;
        family = BPF_CORE_READ(sk, sk_family);
        if (family == AF_INET || family == AF_INET6)
            return sk;
    }
        
out:
    return NULL;
}

static __noinline struct sock *find_sockfd(struct task_struct *task)
{
    struct sock *sk;
    int nr, max;

    struct files_struct *files = (void *)BPF_CORE_READ(task, files);
    if (files == NULL)
        return NULL;
    struct fdtable *fdt = (struct fdtable *)BPF_CORE_READ(files, fdt);
    if (fdt == NULL)
        return NULL;
    max = BPF_CORE_READ(fdt, max_fds);
    struct file **fds = (struct file **)BPF_CORE_READ(fdt, fd);
    if (fds == NULL)
        return NULL;

#if LOOPS_UNROLL
#   pragma unroll
#endif
    for (nr = 0; nr < 16; nr++) {
        sk = find_sock_internal(fds, nr, max);
        if (sk)
            break;
    }

    return sk;
}

static __always_inline int get_sock_v4(struct sock *sk, struct hds_socket_info *sinfo)
{
    struct inet_sock *inet = (struct inet_sock *)sk;
    sinfo->local_address = BPF_CORE_READ(inet, inet_rcv_saddr);
    sinfo->local_port = bpf_ntohs(BPF_CORE_READ(inet, inet_num));
    sinfo->remote_address = BPF_CORE_READ(inet, inet_daddr);
    sinfo->remote_port = BPF_CORE_READ(inet, inet_dport);
    return 0;
}

static __always_inline int get_sock_v6(struct sock *sk, struct hds_socket_info_v6 *sinfo)
{
    struct inet_sock *inet = (struct inet_sock *)sk;
    struct ipv6_pinfo *inet6 = inet6_sk_own_impl(sk, inet);
    struct in6_addr addr = {};
    addr = BPF_CORE_READ(sk, __sk_common.skc_v6_rcv_saddr);
    if (ipv6_addr_any(&addr))
        addr = BPF_CORE_READ(inet6, saddr);
    sinfo->local_address = BPF_CORE_READ(sk, __sk_common.skc_v6_daddr);
    sinfo->local_port = BPF_CORE_READ(inet, inet_dport);
    sinfo->remote_address = addr;
    sinfo->remote_port = BPF_CORE_READ(inet, inet_sport);
    return 0;
}

/* ===== END ===== */


static __always_inline struct file *fget_raw(struct task_struct *task, u64 fd_num)
{
    struct file **fd = BPF_CORE_READ(task, files, fdt, fd);
    if (fd == NULL)
        return NULL;
    struct file *file;
    bpf_core_read(&file, sizeof(void *), &fd[fd_num]);
    return file;
}

static __always_inline void *get_path(struct path *path)
{
    struct path f_path;
    bpf_probe_read(&f_path, sizeof(struct path), path);
    int sz = 0, zero = 0, off = 0, rc = 0;
    u32 inode = 0, buf_off = MID_PERCPU_BUFSIZE;
    char pipe_prefix[] = "pipe:[", socket_prefix[] = "socket:[", invalid[] = "-1";
    struct dentry *dentry = f_path.dentry, *mnt_root, *d_parent;
    struct vfsmount *vfsmnt = f_path.mnt;
    struct mount *mnt_p = real_mount(vfsmnt);
    struct mount *mnt_parent_p = BPF_CORE_READ(mnt_p, mnt_parent);
    struct qstr d_name;
    buf_t *cache = get_percpu_buf(LOCAL_CACHE);
    if (!cache)
        return NULL;
#pragma unroll
    for (int i = 0; i < MAX_PATH_COMPONENTS; i++) {
        mnt_root = BPF_CORE_READ(vfsmnt, mnt_root);
        d_parent = BPF_CORE_READ(dentry, d_parent);
        if (dentry == mnt_root || dentry == d_parent) {
            if (dentry != mnt_root)
                break;
            if (mnt_p != mnt_parent_p) {
                bpf_probe_read(&dentry, sizeof(struct dentry *), &mnt_p->mnt_mountpoint);
                bpf_probe_read(&mnt_p, sizeof(struct mount *), &mnt_p->mnt_parent);
                bpf_probe_read(&mnt_parent_p, sizeof(struct mount *), &mnt_p->mnt_parent);
                vfsmnt = &mnt_p->mnt;
                continue;
            }
            break;
        }
        d_name = BPF_CORE_READ(dentry, d_name);
        off = buf_off - (d_name.len + 1);
        sz = 0;
        /* size check */
        off = off & MAX_PERCPU_MASK;
        if (off > MAX_PERCPU_MASK - MAX_STRING_SIZE)
            break;
        sz = bpf_probe_read_str(&(cache->buf[off]), (d_name.len + 1) & MAX_STRING_MASK, (void *)d_name.name);
        if (!sz)
            break;
        cache->buf[(buf_off - 1) & MAX_PERCPU_MASK] = '/';
        buf_off -= sz;
        /* dentry update */
        dentry = d_parent;
    }

    if (buf_off != MID_PERCPU_BUFSIZE) {
        buf_off -= 1;
        cache->buf[buf_off & MAX_PERCPU_MASK] = '/';
        bpf_probe_read(&(cache->buf[((MAX_PERCPU_BUFSIZE) >> 1) - 1]), 1, &zero);
        goto out;
    }

    /* magic handle */
    struct super_block *d_sb = BPF_CORE_READ(dentry, d_sb);
    if (d_sb) {
        u64 s_magic = BPF_CORE_READ(d_sb, s_magic);
        // here, we just need `PIPE` & `SOCKET`. see more magic: https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/magic.h#L86
        switch (s_magic) {
        case PIPEFS_MAGIC:
            rc = bpf_probe_read_str(&(cache->buf[buf_off & MAX_PERCPU_MASK]), MAX_STRING_SIZE, (void *)pipe_prefix);
            break;
        case SOCKFS_MAGIC:
            rc = bpf_probe_read_str(&(cache->buf[buf_off & MAX_PERCPU_MASK]), MAX_STRING_SIZE, (void *)socket_prefix);
            break;
        default:
            bpf_probe_read_str(&(cache->buf[buf_off & MAX_PERCPU_MASK]), MAX_STRING_SIZE, (void *)invalid);
            goto out;                    
        }
        if (!rc)
            goto out;
        buf_off = buf_off + rc - 1;
        inode = BPF_CORE_READ(dentry, d_inode, i_ino);
        rc = do_u32toa(inode, &cache->buf[buf_off & MAX_PERCPU_MASK], 8);
        if (!rc)
            goto out;
        buf_off += rc;
        cache->buf[buf_off & MAX_PERCPU_MASK] = ']';
        bpf_probe_read(&(cache->buf[(buf_off + 1) & MAX_PERCPU_MASK]), 1, &zero);
        buf_off = MID_PERCPU_BUFSIZE; /* rollback the index */
        goto out;
    }
    d_name = BPF_CORE_READ(dentry, d_name);
    if (d_name.len > 0)
        bpf_probe_read_str(&(cache->buf[buf_off & MAX_PERCPU_MASK]), MAX_STRING_SIZE, (void *)d_name.name);
out:
    return &(cache->buf[buf_off & MAX_PERCPU_MASK]);
}

static __always_inline void *get_fd(struct task_struct *task, u64 num)
{
    struct file *file = fget_raw(task, num);
    if (!file)
        return NULL;
    struct path path = BPF_CORE_READ(file, f_path);
    return get_path(__builtin_preserve_access_index(&path));
}

#endif