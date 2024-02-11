#ifndef __COMMON_H__
#define __COMMON_H__

#include <vmlinux.h>
#include <missing_definitions.h>
#include "print.h"
#include "bpf_core_read.h"
#include "bpf_helpers.h"
#include "bpf_endian.h"

#define GET_FIELD_ADDR(field) __builtin_preserve_access_index(&field)

static inline struct mount *real_mount(struct vfsmount *mnt)
{
    return container_of(mnt, struct mount, mnt);
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
}

/* ===== END ===== */


static __always_inline struct file *fget_raw(u64 fd_num)
{
    // get current task
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (task == NULL)
        return NULL;
    struct file **fd = BPF_CORE_READ(task, files, fdt, fd);
    if (fd == NULL)
        return NULL;
    struct file *file;
    bpf_core_read(&file, sizeof(void *), &fd[fd_num]);
    if (file == NULL)
        return NULL;
    return file;
}

static __always_inline void *save_path(struct path *path, struct hds_context *ctx)
{
    struct path f_path;
    bpf_probe_read(&f_path, sizeof(struct path), path);
    char slash = '/';
    int sz = 0, zero = 0;
    unsigned long len = 0, off = 0, inode = 0;
    char pipe_prefix[] = "pipe", socket_prefix[] = "socket", invalid[] = "-1";
    struct dentry *dentry = f_path.dentry;
    struct vfsmount *vfsmnt = f_path.mnt;
    struct mount *mnt_parent_p, *mnt_p = real_mount(vfsmnt);
    bpf_probe_read(&mnt_parent_p, sizeof(struct mount *), &mnt_p->mnt_parent);
    // from the middle, to avoid rewrite by this
    u32 buf_off = MID_PERCPU_BUFSIZE;
    struct dentry *mnt_root, *d_parent;
    struct qstr d_name;
    buf_t *cache = get_percpu_buf(LOCAL_CACHE);
    if (cache == NULL)
        return NULL;
#pragma unroll
    for (int i = 0; i < MAX_PATH_COMPONENTS; i++) {
        mnt_root = BPF_CORE_READ(vfsmnt, mnt_root);
        d_parent = BPF_CORE_READ(dentry, d_parent);
        // 1. dentry == d_parent means we reach the dentry root
        // 2. dentry == mnt_root means we reach the mount root, they share the same dentry
        if (dentry == mnt_root || dentry == d_parent) {
            // We reached root, but not mount root - escaped?
            if (dentry != mnt_root)
                break;
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
        d_name = BPF_CORE_READ(dentry, d_name);
        len = (d_name.len + 1) & (MAX_STRING_SIZE - 1);
        off = buf_off - len;
        sz = 0;
        if (off <= buf_off) {
            len = len & MID_PERCPU_MASK;
            sz = bpf_probe_read_str(&(cache->buf[off & MID_PERCPU_MASK]), len, (void *)d_name.name);
        } else {
            break;
        }
        if (sz > 1) {
            buf_off -= 1; // remove null byte termination with slash sign
            bpf_probe_read(&(cache->buf[buf_off & MAX_PERCPU_MASK]), 1, &slash);
            buf_off -= sz - 1;
        } else {
            // If sz is 0 or 1 we have an error (path can't be null nor an empty string)
            break;
        }
        dentry = d_parent;
    }

    // no path avaliable, let the userspace to checkout this
    // this would be moved into userspace in the future
    if (buf_off == MID_PERCPU_BUFSIZE) {        
        // Handle pipe with d_name.len = 0
        struct super_block *d_sb = BPF_CORE_READ(dentry, d_sb);
        if (d_sb != 0) {
            unsigned long s_magic = BPF_CORE_READ(d_sb, s_magic);
             // here, we just need `PIPE` & `SOCKET`. see more magic: https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/magic.h#L86
            switch (s_magic) {
            case PIPEFS_MAGIC:
                bpf_probe_read_str(&(cache->buf[buf_off & MAX_PERCPU_MASK]), MAX_STRING_SIZE, (void *)pipe_prefix);
                buf_off += sizeof(pipe_prefix) - 1;
            case SOCKFS_MAGIC:
                bpf_probe_read_str(&(cache->buf[buf_off & MAX_PERCPU_MASK]), MAX_STRING_SIZE, (void *)socket_prefix);
                buf_off += sizeof(socket_prefix) - 1;
            default:
                bpf_probe_read_str(&(cache->buf[buf_off & MAX_PERCPU_MASK]), MAX_STRING_SIZE, (void *)invalid);
                goto out;                    
            }
            inode = BPF_CORE_READ(dentry, d_inode, i_ino);
            goto out;
        }
        d_name = BPF_CORE_READ(dentry, d_name);
        if (d_name.len > 0) {
            bpf_probe_read_str(&(cache->buf[0]), MAX_STRING_SIZE, (void *)d_name.name);
            goto out;
        }
    } else {
        // Add leading slash
        buf_off -= 1;
        bpf_probe_read(&(cache->buf[buf_off & MAX_PERCPU_MASK]), 1, &slash);
        // Null terminate the path string
        bpf_probe_read(&(cache->buf[((MAX_PERCPU_BUFSIZE) >> 1) - 1]), 1, &zero);
    }
out:
    SBT_CHAR(ctx ,&(cache->buf[buf_off & MAX_PERCPU_MASK]));
    if (inode > 0)
        SBT(ctx, &inode, S_U64);
    return NULL;
}

static __always_inline void *save_fd(u64 num, struct hds_context *ctx)
{
    char nothing[] = "-1";
    struct file *file = fget_raw(num);
    if (!file) {
        SBT_CHAR(ctx, &nothing);
        return NULL;
    }
    struct path p = BPF_CORE_READ(file, f_path);
    return save_path(GET_FIELD_ADDR(p), ctx);
}

#endif