#include "utils_buf.h"
#include "utils.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"
#include "bpf_tracing.h"

// By the way, notes for pt_regs. Kernel version over 4.17 is supported.
// finished
SEC("kprobe/security_socket_connect")
int kprobe_security_socket_connect(struct pt_regs *ctx)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;
    data.context.type = 1022;

    struct sockaddr *address = (struct sockaddr *)PT_REGS_PARM2(ctx);
    if (!address)
        return 0;

    sa_family_t sa_fam = READ_KERN(address->sa_family);
    if ((sa_fam != AF_INET) && (sa_fam != AF_INET6))
    {
        return 0;
    }
    switch (sa_fam)
    {
    case AF_INET:
        save_to_submit_buf(&data, (void *)address, sizeof(struct sockaddr_in), 0);
        break;
    case AF_INET6:
        save_to_submit_buf(&data, (void *)address, sizeof(struct sockaddr_in6), 0);
        break;
    // In Elkeid, connect_syscall_handler, only AF_INET and AF_INET6 are added. But in
    // tracee, AF_UNIX is also considered.
    default:
        break;
    }
    // get exe from task
    void *exe = get_exe_from_task(data.task);
    int ret = save_str_to_buf(&data, exe, 1);
    if (ret == 0)
    {
        char nothing[] = "-1";
        save_str_to_buf(&data, nothing, 1);
    }
    return events_perf_submit(&data);
}

SEC("kprobe/security_socket_bind")
int kprobe_security_socket_bind(struct pt_regs *ctx)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;
    data.context.type = 1024;

    // this is for getting protocol
    struct socket *sock = (struct socket *)PT_REGS_PARM1(ctx);
    struct sock *sk = READ_KERN(sock->sk);

    struct sockaddr *address = (struct sockaddr *)PT_REGS_PARM2(ctx);
    sa_family_t sa_fam = READ_KERN(address->sa_family);
    if ((sa_fam != AF_INET) && (sa_fam != AF_INET6))
    {
        return 0;
    }
    switch (sa_fam)
    {
    case AF_INET:
        save_to_submit_buf(&data, (void *)address, sizeof(struct sockaddr_in), 0);
        break;
    case AF_INET6:
        save_to_submit_buf(&data, (void *)address, sizeof(struct sockaddr_in6), 0);
        break;
    default:
        break;
    }
    // get exe from task_struct
    void *exe = get_exe_from_task(data.task);
    int ret = save_str_to_buf(&data, exe, 1);
    if (ret == 0)
    {
        char nothing[] = "-1";
        save_str_to_buf(&data, nothing, 1);
    }

    return events_perf_submit(&data);
}

// kprobe/kretprobe are used for get dns data. Proper way to get udp data,
// is to hook the kretprobe of the udp_recvmsg just like Elkeid does. But
// still, a uprobe of udp (like getaddrinfo and gethostbyname) to get this
// all.
// TODO: unfinished
SEC("kprobe/udp_recvmsg")
int kprobe_udp_recvmsg(struct pt_regs *ctx)
{
    // get the sock
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    u16 dport = 0;
    struct inet_sock *inet = (struct inet_sock *)sk;
    // only port 53 and 5353 is considered useful here. Port 53 is well
    // known for dns while 5353 is the mDNS
    if (inet->inet_dport == 13568 || inet->inet_dport == 59668)
    {
        // Here are some information about msghdr:
        // @Reference: https://www.cnblogs.com/wanpengcoder/p/11749287.html
        // Shortly, the information that we need is in msghdr->msg_iter which
        // stores the data. For the field in iovter, an article is here:
        // @Reference: https://lwn.net/Articles/625077/
        // iov_iter: iterator for working through an iovec structure
        // Also something interestring: https://github.com/dmliscinsky/lkm-rootkit
        // something funny is that the msg_iter.type was changed into iter_type
        // in kernel 5.14, a define macro should be used to fix this...
        // A reference here:
        // @Reference: https://github.com/iovisor/bcc/issues/3859
        //
        // By the way this struct(msghdr) is defined in socket.h
        struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2(ctx);
        // in msghdr->iov_iter. There are different way to filter. What we need
        // is iovec. In Elkeid, they judge by the iov_len. In ehids-agent or
        // https://github.com/trichimtrich/dns-tcp-ebpf, they judge by the
        // (type != ITER_IOVEC). But just as I said, be careful about the name of
        // `type` or `iter_type`
        struct iov_iter msg_iter;
        struct iovec *iov;
        int ret = 0;
        ret = bpf_probe_read(&msg_iter, &sizeof(msg_iter), &msg->msg_iter);
        if (ret != 0)
            return 0;
        ret = bpf_probe_read(&iov, &sizeof(iov), msg_iter.iov);
        if (ret != 0)
            return 0;
        if (iov.iov_len == 0)
            return 0;
        // TODO: update map here
    }
    // inet_dport is considered which https://github.com/trichimtrich/dns-tcp-ebpf
    // just pass this.
    else if (inet->inet_dport == 0)
    {
    };
}

// ===== 暂时不开启, 不做 HOOK ====
// SEC("kprobe/security_socket_accept")
// int kprobe_security_socket_accept(struct pt_regs *ctx)
// {
//     event_data_t data = {};
//     if (!init_event_data(&data, ctx))
//         return 0;
//     data.context.type = 8;

//     struct socket *sock = (struct socket *)PT_REGS_PARM1(ctx);
//     struct sock *sk = READ_KERN(sock->sk);

//     sa_family_t sa_fam = READ_KERN(sk->sk_family);
//     if ((sa_fam != AF_INET) && (sa_fam != AF_INET6))
//     {
//         return 0;
//     }
//     switch (sa_fam)
//     {
//     case AF_INET:
//         net_conn_v4_t net_details = {};
//         struct sockaddr_in local;
//         get_network_details_from_sock_v4(sk, &net_details, 0);
//         get_local_sockaddr_in_from_network_details(&local, &net_details, family);
//         save_to_submit_buf(&data, (void *)&local, sizeof(struct sockaddr_in), 0);
//         break;
//     // case AF_INET6:
//     //     net_conn_v6_t net_details = {};
//     //     struct sockaddr_in6 local;
//     //     get_network_details_from_sock_v6(sk, &net_details, 0);
//     //     // get_local_sockaddr_in6_from_network_details(&local, &net_details, family);
//     //     save_to_submit_buf(&data, (void *)&local, sizeof(struct sockaddr_in6), 0);
//     //     break;
//     default:
//         break;
//     }
// }