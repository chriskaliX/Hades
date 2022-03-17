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
        return 0;
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

    // This is for getting protocol
    // In Elkeid, the protocol is not concerned, only sa_family, sip, sport, res
    // Maybe it's useful, so we need to work on this.
    struct socket *sock = (struct socket *)PT_REGS_PARM1(ctx);
    struct sock *sk = READ_KERN(sock->sk);
    u16 protocol = get_sock_protocol(sk);

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
        return 0;
    }
    // get exe from task_struct
    void *exe = get_exe_from_task(data.task);
    int ret = save_str_to_buf(&data, exe, 1);
    if (ret == 0)
    {
        char nothing[] = "-1";
        save_str_to_buf(&data, nothing, 1);
    }
    save_to_submit_buf(&data, (void *)&protocol, sizeof(protocol), 2);

    return events_perf_submit(&data);
}

/* For DNS */
BPF_LRU_HASH(udpmsg, u64, struct msghdr *, 1024);
// kprobe/kretprobe are used for get dns data. Proper way to get udp data,
// is to hook the kretprobe of the udp_recvmsg just like Elkeid does. But
// still, a uprobe of udp (like getaddrinfo and gethostbyname) to get this
// all.
// @Reference: https://www.nlnetlabs.nl/downloads/publications/DNS-augmentation-with-eBPF.pdf
SEC("kprobe/udp_recvmsg")
int kprobe_udp_recvmsg(struct pt_regs *ctx)
{
    // get the sock
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct inet_sock *inet = (struct inet_sock *)sk;
    // only port 53 and 5353 is considered useful here. Port 53 is well
    // known for dns while 5353 is the mDNS
    u16 dport = READ_KERN(inet->inet_dport);
    // @ Notice:
    // In some situation, when we use command 'dig', 'nslookup' etc., it actually
    // comes from other ports(not 53 or 5353).
    // if all udp traffic is required, remove the dport thing.
    // By the way, I capture the Query part of dns structure and ignore TC flag,
    // which is somehow inaccurate though, but I'll do a uprobe hook for this all.
    if (dport == 13568 || dport == 59668)
    {
        struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2(ctx);
        // in msghdr->iov_iter. There are different way to filter. What we need
        // is iovec. In Elkeid, they judge by the iov_len. In ehids-agent or
        // https://github.com/trichimtrich/dns-tcp-ebpf, they judge by the
        // (type != ITER_IOVEC). But just as I said, be careful about the name of
        // `type` or `iter_type`
        struct iov_iter msg_iter;
        struct iovec *iov;
        int ret = bpf_probe_read(&msg_iter, sizeof(msg_iter), &msg->msg_iter);
        if (ret != 0)
            return 0;
        ret = bpf_probe_read(&iov, sizeof(iov), msg_iter.iov);
        if (ret != 0)
            return 0;
        unsigned long iov_len;
        bpf_probe_read(&iov_len, sizeof(iov_len), &iov->iov_len);
        if (iov_len == 0)
            return 0;
        // maybe bpf_get_prandom_u32() as a key...
        u64 pid_tgid = bpf_get_current_pid_tgid();
        bpf_map_update_elem(&udpmsg, &pid_tgid, &msg, BPF_ANY);
    }
    return 0;
}

// in Elkeid, ip infomration is also collected, we'll add this later.
struct udpdata
{
    int opcode;
    int rcode;
};

// @Reference: https://en.wikipedia.org/wiki/Domain_Name_System
SEC("kretprobe/udp_recvmsg")
int kretprobe_udp_recvmsg(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct msghdr **msgpp = bpf_map_lookup_elem(&udpmsg, &pid_tgid);
    if (msgpp == 0)
        return 0;
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
    struct msghdr *msg = (struct msghdr *)*msgpp;
    // Check the msghdr length
    struct iov_iter msg_iter;
    // struct iovec
    // {
    // 	void __user *iov_base;	/* BSD uses caddr_t (1003.1g requires void *) */
    // 	__kernel_size_t iov_len; /* Must be size_t (1003.1g) */
    // };
    struct iovec *iov;
    int ret = bpf_probe_read(&msg_iter, sizeof(msg_iter), &msg->msg_iter);
    if (ret != 0)
        goto delete;
    ret = bpf_probe_read(&iov, sizeof(iov), msg_iter.iov);
    if (ret != 0)
        goto delete;
    unsigned long iov_len;
    bpf_probe_read(&iov_len, sizeof(iov_len), &iov->iov_len);
    if (iov_len < 20)
        goto delete;
    // truncated here, do not drop, as in dns
    if (iov_len > 512)
        iov_len = 512;
    // Firstly, we need to understand the dns data struct
    // The reference is here: http://c.biancheng.net/view/6457.html
    // |QR|Opcode|AA|TC|RD|RA|Z|rcode|
    // QR equals 1 means is a response, so it's what we need
    buf_t *string_p = get_buf(STRING_BUF_IDX);
    if (string_p == NULL)
        goto delete;
    // TODO: upgrade here
    bpf_probe_read(&(string_p->buf[0]), iov_len & (512), &iov->iov_base);
    // The data structure of dns is here...
    // |SessionID(2 bytes)|Flags(2 bytes)|Data(8 bytes)|Querys...|
    // The datas that we need are flags & querys
    int qr = (string_p->buf[2] & 0x80) ? 1 : 0;
    if (qr == 1)
    {
        event_data_t data = {};
        if (!init_event_data(&data, ctx))
            return 0;
        data.context.type = 1025;

        int opcode = (string_p->buf[2] >> 3) & 0x0f;
        int rcode = string_p->buf[3] & 0x0f;
        struct udpdata udata = {};
        udata.opcode = opcode;
        udata.rcode = rcode;
        save_to_submit_buf(&data, &udata, sizeof(struct udpdata), 0);
        int len;
        int templen;
// change the data to a string, as max, we support 10
#pragma unroll
        for (int i = 0; i < 10; i++)
        {
            // firstly get the length
            if (i == 0)
            {
                len = string_p->buf[12];
                len = 12 + len;
            }
            else
            {
                templen = string_p->buf[(len + 1) & (MAX_PERCPU_BUFSIZE - 1)];
                if (templen == 0)
                {
                    break;
                }
                string_p->buf[(len + 1) & (MAX_PERCPU_BUFSIZE - 1)] = 46;
                len = len + templen + 1;
            }
        }
        save_str_to_buf(&data, (void *)&string_p->buf[13], 1);
        // get exe from task
        void *exe = get_exe_from_task(data.task);
        int ret = save_str_to_buf(&data, exe, 1);
        if (ret == 0)
        {
            char nothing[] = "-1";
            save_str_to_buf(&data, nothing, 1);
        }
        events_perf_submit(&data);
    }
    delete : bpf_map_delete_elem(&udpmsg, &pid_tgid);
    return 0;
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