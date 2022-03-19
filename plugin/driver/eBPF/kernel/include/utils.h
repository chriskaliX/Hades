#ifndef __UTILS_H
#define __UTILS_H
#include "bpf_helpers.h"
#include "bpf_core_read.h"
#include "bpf_endian.h"
#include <linux/sched.h>
#include <linux/fdtable.h>
#include <utils_buf.h>
#include <linux/mm_types.h>
#define KBUILD_MODNAME "hades"
#include <net/ipv6.h>
#include <linux/ipv6.h>

// TODO: 后期改成动态的
/* R3 max value is outside of the array range */
// 这个地方非常非常的坑，都因为 bpf_verifier 机制, 之前 buf_off > MAX_PERCPU_BUFSIZE - sizeof(int) 本身都是成立的
// 前面明明有一个更为严格的 data->buf_off > (MAX_PERCPU_BUFSIZE) - (MAX_STRING_SIZE) - sizeof(int)，但是不行
// 在每次调 index 之前都需要 check 一下，所以看源码的时候很多地方会写：To satisfied the verifier...
// TODO: 写一个文章记录一下这个...

// TODO: 判断 kernel version, 使用 ringbuf, 传输优化
/* init_context */
static __always_inline int init_context(context_t *context, struct task_struct *task)
{
    // 获取 timestamp
    struct task_struct *realparent;
    bpf_probe_read(&realparent, sizeof(realparent), &task->real_parent);
    bpf_probe_read(&context->ppid, sizeof(context->ppid), &realparent->tgid);
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
    // Elkeid - ROOT_PID_NS_INUM = task->nsproxy->pid_ns_for_children->ns.inum;
    // namespace: https://zhuanlan.zhihu.com/p/307864233
    struct nsproxy *nsp;
    struct uts_namespace *uts_ns;
    // nodename
    bpf_probe_read(&nsp, sizeof(nsp), &task->nsproxy);
    bpf_probe_read(&uts_ns, sizeof(uts_ns), &nsp->uts_ns);
    bpf_probe_read_str(&context->nodename, sizeof(context->nodename), &uts_ns->name.nodename);
    // pid_namespace
    bpf_probe_read(&context->uts_inum, sizeof(context->uts_inum), &uts_ns->ns.inum);
    // sessionid
    bpf_probe_read(&context->sessionid, sizeof(context->sessionid), &task->sessionid);
    struct pid_cache_t *parent = bpf_map_lookup_elem(&pid_cache_lru, &context->pid);
    if (parent)
        bpf_probe_read_str(&context->pcomm, sizeof(context->pcomm), &parent->pcomm);
    else
        bpf_probe_read_str(&context->pcomm, sizeof(context->pcomm), &realparent->comm);
    bpf_get_current_comm(&context->comm, sizeof(context->comm));
    context->argnum = 0;
    return 0;
}

// this is kernel space simple filter, also userspace filter will be supported
// 0 on false & 1 on true
static __always_inline int filter(context_t context)
{
    // pid filter
    u8 *equality = bpf_map_lookup_elem(&pid_filter, &context.pid);
    if (equality != NULL)
        return 1;
    return 0;
}

/* ==== get ==== */

static __always_inline void *get_task_tty_str(struct task_struct *task)
{
    struct signal_struct *signal;
    bpf_probe_read(&signal, sizeof(signal), &task->signal);
    struct tty_struct *tty;
    bpf_probe_read(&tty, sizeof(tty), &signal->tty);
    // Get per-cpu string buffer
    buf_t *string_p = get_buf(STRING_BUF_IDX);
    if (string_p == NULL)
        return NULL;
    int size = bpf_probe_read_str(&(string_p->buf[0]), 64, &tty->name);
    char nothing[] = "-1";
    if (size < 1)
        bpf_probe_read_str(&(string_p->buf[0]), MAX_STRING_SIZE, nothing);
    return &string_p->buf[0];
}

// source code: __prepend_path
// http://blog.sina.com.cn/s/blog_5219094a0100calt.html
static __always_inline void *get_path_str(struct path *path)
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
    for (int i = 0; i < MAX_PATH_COMPONENTS; i++)
    {
        mnt_root = READ_KERN(vfsmnt->mnt_root);
        d_parent = READ_KERN(dentry->d_parent);
        // 1. dentry == d_parent means we reach the dentry root
        // 2. dentry == mnt_root means we reach the mount root, they share the same dentry
        if (dentry == mnt_root || dentry == d_parent)
        {
            // We reached root, but not mount root - escaped?
            if (dentry != mnt_root)
            {
                break;
            }
            // dentry == mnt_root, but the mnt has not reach it's root
            // so update the dentry as the mnt_mountpoint(in order to continue the dentry loop for the mountpoint)
            // We reached root, but not global root - continue with mount point path
            if (mnt_p != mnt_parent_p)
            {
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
        if (off <= buf_off)
        { // verify no wrap occurred
            len = len & (((MAX_PERCPU_BUFSIZE) >> 1) - 1);
            sz = bpf_probe_read_str(&(string_p->buf[off & ((MAX_PERCPU_BUFSIZE >> 1) - 1)]), len, (void *)d_name.name);
        }
        else
            break;
        if (sz > 1)
        {
            buf_off -= 1; // remove null byte termination with slash sign
            bpf_probe_read(&(string_p->buf[buf_off & (MAX_PERCPU_BUFSIZE-1)]), 1, &slash);
            buf_off -= sz - 1;
        }
        else
        {
            // If sz is 0 or 1 we have an error (path can't be null nor an empty string)
            break;
        }
        dentry = d_parent;
    }
    // no path avaliable.
    if (buf_off == (MAX_PERCPU_BUFSIZE >> 1))
    {
        // memfd files have no path in the filesystem -> extract their name
        buf_off = 0;
        d_name = READ_KERN(dentry->d_name);
        bpf_probe_read_str(&(string_p->buf[0]), MAX_STRING_SIZE, (void *)d_name.name);
        // 2022-02-24 added. return "-1" if it's added
    }
    else
    {
        // Add leading slash
        buf_off -= 1;
        bpf_probe_read(&(string_p->buf[buf_off & ((MAX_PERCPU_BUFSIZE)-1)]), 1, &slash);
        // Null terminate the path string
        bpf_probe_read(&(string_p->buf[((MAX_PERCPU_BUFSIZE) >> 1) - 1]), 1, &zero);
    }

    set_buf_off(STRING_BUF_IDX, buf_off);
    return &string_p->buf[buf_off];
}

// all from tracee
static __always_inline void* get_dentry_path_str(struct dentry* dentry)
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
        unsigned int len = (d_name.len+1) & (MAX_STRING_SIZE-1);
        unsigned int off = buf_off - len;
        // Is string buffer big enough for dentry name?
        int sz = 0;
        if (off <= buf_off) { // verify no wrap occurred
            len = len & ((MAX_PERCPU_BUFSIZE >> 1)-1);
            sz = bpf_probe_read_str(&(string_p->buf[off & ((MAX_PERCPU_BUFSIZE >> 1)-1)]), len, (void *)d_name.name);
        }
        else
            break;
        if (sz > 1) {
            buf_off -= 1; // remove null byte termination with slash sign
            bpf_probe_read(&(string_p->buf[buf_off & (MAX_PERCPU_BUFSIZE-1)]), 1, &slash);
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
        bpf_probe_read_str(&(string_p->buf[0]), MAX_STRING_SIZE, (void *)d_name.name);
    } else {
        // Add leading slash
        buf_off -= 1;
        bpf_probe_read(&(string_p->buf[buf_off & (MAX_PERCPU_BUFSIZE-1)]), 1, &slash);
        // Null terminate the path string
        bpf_probe_read(&(string_p->buf[(MAX_PERCPU_BUFSIZE >> 1)-1]), 1, &zero);
    }

    set_buf_off(STRING_BUF_IDX, buf_off);
    return &string_p->buf[buf_off];
}

static __always_inline int get_network_details_from_sock_v4(struct sock *sk, net_conn_v4_t *net_details, int peer)
{
    struct inet_sock *inet = (struct inet_sock *)sk;
    if (!peer)
    {
        net_details->local_address = READ_KERN(inet->inet_rcv_saddr);
        net_details->local_port = bpf_ntohs(READ_KERN(inet->inet_num));
        net_details->remote_address = READ_KERN(inet->inet_daddr);
        net_details->remote_port = READ_KERN(inet->inet_dport);
    }
    else
    {
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
    bpf_probe_read((void *)&sk_state_own_impl, sizeof(sk_state_own_impl), (const void *)&sock->sk_state);
    return sk_state_own_impl;
}

static __always_inline struct ipv6_pinfo* get_inet_pinet6(struct inet_sock *inet)
{
    struct ipv6_pinfo *pinet6_own_impl;
    bpf_probe_read(&pinet6_own_impl, sizeof(pinet6_own_impl), &inet->pinet6);
    return pinet6_own_impl;
}

static __always_inline struct ipv6_pinfo *inet6_sk_own_impl(struct sock *__sk, struct inet_sock *inet)
{
    volatile unsigned char sk_state_own_impl;
    sk_state_own_impl = get_sock_state(__sk);

    struct ipv6_pinfo *pinet6_own_impl;
    pinet6_own_impl = get_inet_pinet6(inet);

    bool sk_fullsock = (1 << sk_state_own_impl) & ~(TCPF_TIME_WAIT | TCPF_NEW_SYN_RECV);
    return sk_fullsock ? pinet6_own_impl : NULL;
}

// static inline bool ipv6_addr_any(const struct in6_addr *a)
// {
//     return (a->in6_u.u6_addr32[0] | a->in6_u.u6_addr32[1] | a->in6_u.u6_addr32[2] | a->in6_u.u6_addr32[3]) == 0;
// }

static __always_inline int get_network_details_from_sock_v6(struct sock *sk, net_conn_v6_t *net_details, int peer)
{
    struct inet_sock *inet = (struct inet_sock *)sk;
    struct ipv6_pinfo *np = inet6_sk_own_impl(sk, inet);
    struct in6_addr addr = {};
    addr = READ_KERN(sk->sk_v6_rcv_saddr);
    if (ipv6_addr_any(&addr)){
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
    }
    else {
        net_details->local_address = addr;
        net_details->local_port = READ_KERN(inet->inet_sport);
        net_details->remote_address = READ_KERN(sk->sk_v6_daddr);
        net_details->remote_port = READ_KERN(inet->inet_dport);
    }
    return 0;
}

static __always_inline int get_remote_sockaddr_in_from_network_details(struct sockaddr_in *addr, net_conn_v4_t *net_details, u16 family)
{
    addr->sin_family = family;
    addr->sin_port = net_details->remote_port;
    addr->sin_addr.s_addr = net_details->remote_address;
    return 0;
}

static __always_inline int get_remote_sockaddr_in6_from_network_details(struct sockaddr_in6 *addr, net_conn_v6_t *net_details, u16 family)
{
    addr->sin6_family = family;
    addr->sin6_port = net_details->remote_port;
    addr->sin6_flowinfo = net_details->flowinfo;
    addr->sin6_addr = net_details->remote_address;
    addr->sin6_scope_id = net_details->scope_id;

    return 0;
}

static __always_inline int get_local_sockaddr_in_from_network_details(struct sockaddr_in *addr, net_conn_v4_t *net_details, u16 family)
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
    {
        return NULL;
    }
    // get files
    struct files_struct *files = (struct files_struct *)READ_KERN(task->files);
    if (files == NULL)
    {
        return NULL;
    }
    // get fdtable
    struct fdtable *fdt = (struct fdtable *)READ_KERN(files->fdt);
    if (fdt == NULL)
    {
        return NULL;
    }
    struct file **fd = (struct file **)READ_KERN(fdt->fd);
    if (fd == NULL)
    {
        return NULL;
    }
    struct file *f = (struct file *)READ_KERN(fd[fd_num]);
    if (f == NULL)
    {
        return NULL;
    }

    return f;
}

// TODO: op
static __always_inline void *get_fraw_str(u64 num)
{
    char nothing[] = "-1";
    buf_t *string_p = get_buf(STRING_BUF_IDX);
    if (string_p == NULL)
        return NULL;
    bpf_probe_read_str(&(string_p->buf[0]), MAX_STRING_SIZE, nothing);
    // get the fd if it exists
    struct file *_file = file_get_raw(num);
    // if null read the fd
    if (!_file)
        return &string_p->buf[0];
    struct path p = READ_KERN(_file->f_path);
    void *path = get_path_str(GET_FIELD_ADDR(p));
    if (!path)
        return &string_p->buf[0];
    // Another thing is that the length of path might be 0.
    return path;
}

/* Reference: http://jinke.me/2018-08-23-socket-and-linux-file-system/ */
static __always_inline int get_socket_info_sub(event_data_t *data, struct fdtable *fdt, u8 index)
{
    u16 family;
    struct socket *socket;
    struct sock *sk;
    struct file **fd;
    struct file *file;
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
    for (int i = 0; i < 8; i++)
    {
        if (i == max_fds)
            break;
        file = (struct file *)READ_KERN(fd[i]);
        if (!file)
            continue;
        struct path f_path;
        struct dentry *dentry;
        struct qstr d_name;
        bpf_probe_read(&f_path, sizeof(struct path), &file->f_path);
        dentry = f_path.dentry;
        d_name = READ_KERN(dentry->d_name);
        unsigned int len = (d_name.len + 1) & (MAX_STRING_SIZE - 1);
        int size = bpf_probe_read_str(&(string_p->buf[0]), len, (void *)d_name.name);
        if (size <= 0)
            continue;
        // TODO: TCP4/6
        if (prefix("TCP", &(string_p->buf[0]), 3))
        {
            bpf_probe_read(&socket, sizeof(socket), &file->private_data);
            if (socket == NULL)
                continue;
            // check state
            // in Elkeid v1.7. Only SS_CONNECTING/SS_CONNECTED/SS_DISCONNECTING is considered.
            bpf_probe_read(&state, sizeof(state), &socket->state);
            if (state != SS_CONNECTING && state != SS_CONNECTED && state != SS_DISCONNECTING)
                continue;
            bpf_probe_read(&sk, sizeof(sk), &socket->sk);
            if (!sk)
                continue;
            // 先不支持 IPv6, 跑通先
            family = READ_KERN(sk->sk_family);
            if (family == AF_INET)
            {
                net_conn_v4_t net_details = {};
                get_network_details_from_sock_v4(sk, &net_details, 0);
                // remote we need to send
                struct sockaddr_in remote;
                get_remote_sockaddr_in_from_network_details(&remote, &net_details, family);
                save_to_submit_buf(data, &remote, sizeof(struct sockaddr_in), index);
                return 1;
            }
            else if (family == AF_INET6)
            {
                net_conn_v6_t net_details = {};
                struct sockaddr_in6 remote;
                get_network_details_from_sock_v6(sk, &net_details, 0);
                get_remote_sockaddr_in6_from_network_details(&remote, &net_details, family);
                save_to_submit_buf(data, &remote, sizeof(struct sockaddr_in6), index);
                return 1;
            }
        }
    }
    return 0;
}

// 向上溯源获取 socket 信息, 参考字节 Elkeid & trace 代码
// 需要做 lru 加速
// In Elkeid 1.7 later, it changes
/* only process known states: SS_CONNECTING/SS_CONNECTED/SS_DISCONNECTING,
    SS_FREE/SS_UNCONNECTED or any possible new states are to be skipped */
static __always_inline int get_socket_info(event_data_t *data, u8 index)
{
    struct sockaddr_in remote;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (task == NULL)
        goto exit;
    u32 pid;
    int flag;
#pragma unroll
    for (int i = 0; i < 4; i++)
    {
        bpf_probe_read(&pid, sizeof(pid), &task->pid);
        // 0 for failed...
        if (pid == 1)
            break;
        // get files
        struct files_struct *files = (struct files_struct *)READ_KERN(task->files);
        if (files == NULL)
            goto next_task;
        // get fdtable
        struct fdtable *fdt = (struct fdtable *)READ_KERN(files->fdt);
        if (fdt == NULL)
            goto next_task;
        // find out
        flag = get_socket_info_sub(data, fdt, index);
        if (flag == 1)
            return 0;
    next_task:
        bpf_probe_read(&task, sizeof(task), &task->real_parent);
    }
exit:
    remote.sin_family = 0;
    remote.sin_port = 0;
    remote.sin_addr.s_addr = 0;
    save_to_submit_buf(data, &remote, sizeof(struct sockaddr_in), index);
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

    struct mm_struct *mm;
    struct file *_file;
    bpf_probe_read(&mm, sizeof(mm), &task->mm);
    if (!mm)
        return &string_p->buf[0];
    bpf_probe_read(&_file, sizeof(_file), &mm->exe_file);
    if (!_file)
        return &string_p->buf[0];
    struct path p = READ_KERN(_file->f_path);
    void *path = get_path_str(GET_FIELD_ADDR(p));
    if (!path)
        return &string_p->buf[0];
    return path;
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
    bpf_probe_read(&(data->submit_p->buf[0]), sizeof(context_t), &data->context);
    int size = data->buf_off & (MAX_PERCPU_BUFSIZE - 1);
    void *output_data = data->submit_p->buf;
    return bpf_perf_event_output(data->ctx, &exec_events, BPF_F_CURRENT_CPU, output_data, size);
}

#endif //__UTILS_BUF_H