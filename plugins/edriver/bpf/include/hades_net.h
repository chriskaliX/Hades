// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Authors: chriskalix@protonmail.com
 */
#ifndef CORE
#include <net/sock.h>
#include <linux/uio.h>
#else
#include <vmlinux.h>
#include <missing_definitions.h>
#endif

#include "define.h"
#include "utils_buf.h"
#include "utils.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"
#include "bpf_tracing.h"
#include "filter.h"

typedef struct net_ctx {
    int fd;
	sa_family_t sa_family;
    int addr;
} net_ctx_t;

BPF_LRU_HASH(connect_cache, u64, net_ctx_t, 4096);

__attribute__((always_inline)) int delete_connect_cache(u64 id)
{
    return bpf_map_delete_elem(&connect_cache, &id);
}

// The pointer should by avaliable through the whole process. Just save the pointer
SEC("tracepoint/syscalls/sys_enter_connect")
int sys_enter_connect(struct syscall_enter_args *ctx)
{
    net_ctx_t net_ctx = {};
    struct sockaddr* sa;
    bpf_probe_read(&sa, sizeof(struct sockaddr),&ctx->args[1]);
    if (sa == NULL)
        return 0;
    net_ctx.fd = ctx->args[0];
    net_ctx.addr = ctx->args[2];
    u16 family;
    bpf_probe_read(&family, sizeof(u16),&sa->sa_family);
    net_ctx.sa_family = family;
    if (family != AF_INET && family != AF_INET6)
        return 0;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    return bpf_map_update_elem(&connect_cache, &pid_tgid, &net_ctx, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_connect")
int sys_exit_connect(struct syscall_exit_args *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    net_ctx_t *net_ctx = bpf_map_lookup_elem(&connect_cache, &pid_tgid);
    if (net_ctx == NULL)
        return 0;
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        goto delete;
    if (context_filter(&data.context))
        goto delete;
    data.context.dt = SYSCONNECT;
    data.context.retval = ctx->ret;
    void *exe = get_exe_from_task(data.task);
    u16 family = net_ctx->sa_family;
    save_to_submit_buf(&data, &family, sizeof(u16), 0);
    int fd = net_ctx->fd;
    
    struct sock *sk = hades_sockfd_lookup(fd);
    if (sk == NULL)
        goto delete;
    
    if (family == AF_INET) {
        net_conn_v4_t net_details = {};
        get_network_details_from_sock_v4(sk, &net_details, 0);
        save_to_submit_buf(&data, &net_details, sizeof(struct network_connection_v4), 1);
    } else if (family == AF_INET6) {
        net_conn_v6_t net_details = {};
        get_network_details_from_sock_v6(sk, &net_details, 0);
        save_to_submit_buf(&data, &net_details, sizeof(struct network_connection_v6), 1);
    } else {
        goto delete;
    }
    
    save_str_to_buf(&data, exe, 2);
    bpf_map_delete_elem(&connect_cache, &pid_tgid);
    return events_perf_submit(&data);
    delete: delete_connect_cache(pid_tgid);
    return 0;
}

SEC("kprobe/security_socket_bind")
int BPF_KPROBE(kprobe_security_socket_bind)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;
    if (context_filter(&data.context))
        return 0;
    data.context.dt = SECURITY_SOCKET_BIND;

    // This is for getting protocol
    // In Elkeid, the protocol is not concerned, only sa_family, sip, sport, res
    // Maybe it's useful, so we need to work on this.
    struct socket *sock = (struct socket *)PT_REGS_PARM1(ctx);
    struct sock *sk = READ_KERN(sock->sk);
    __u16 protocol = get_sock_protocol(sk);

    struct sockaddr *address = (struct sockaddr *)PT_REGS_PARM2(ctx);
    sa_family_t sa_fam = READ_KERN(address->sa_family);
    if ((sa_fam != AF_INET) && (sa_fam != AF_INET6))
        return 0;

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
    save_str_to_buf(&data, exe, 1);
    save_to_submit_buf(&data, (void *)&protocol, sizeof(protocol), 2);

    return events_perf_submit(&data);
}

#define DNS_LIMIT_PERSEC 5000

typedef struct dns_context {
    struct msghdr *msg;
    net_conn_v4_t conn_v4;
} dns_context_t;

/* For DNS */
BPF_LRU_HASH(udpmsg, u64, dns_context_t, 4096);
// kprobe/kretprobe are used for get dns data. Proper way to get udp data,
// is to hook the kretprobe of the udp_recvmsg just like Elkeid does. But
// still, a uprobe of udp (like getaddrinfo and gethostbyname) to get this
// all.
// @Reference: https://www.nlnetlabs.nl/downloads/publications/DNS-augmentation-with-eBPF.pdf
SEC("kprobe/udp_recvmsg")
int BPF_KPROBE(kprobe_udp_recvmsg)
{
    if (hades_filter(UDP_RECVMSG, DNS_LIMIT_PERSEC, POLICY_PASS) == 0)
        return 0;
    // get the sock
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct inet_sock *inet = (struct inet_sock *)sk;
    // only port 53 and 5353 is considered useful here. Port 53 is well
    // known for dns while 5353 is the mDNS
    __u16 dport = READ_KERN(inet->inet_dport);
    // @ Notice:
    // In some situation, when we use command 'dig', 'nslookup' etc., it actually
    // comes from other ports(not 53 or 5353).
    // if all udp traffic is required, remove the dport thing.
    // By the way, I capture the Query part of dns structure and ignore TC flag,
    // which is somehow inaccurate though, but I'll do a uprobe hook for this all.
    if (dport == 13568 || dport == 59668 || dport == 0)
    {
        struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2(ctx);
        // in msghdr->iov_iter. There are different way to filter. What we need
        // is iovec. In Elkeid, they judge by the iov_len. In ehids-agent or
        // https://github.com/trichimtrich/dns-tcp-ebpf, they judge by the
        // (type != ITER_IOVEC). But just as I said, be careful about the name of
        // `type` or `iter_type`
        struct iovec *iov = NULL;
    #ifdef CORE
        if (bpf_core_field_exists(msg->msg_iter.__iov))
            iov = (struct iovec *)READ_KERN(msg->msg_iter.__iov);
        else if (bpf_core_field_exists(msg->msg_iter.iov))
            iov = (struct iovec *)READ_KERN(msg->msg_iter.iov);
    #else
        // TODO: need to add kernel version check here
        struct iovec *iov = (struct iovec *)READ_KERN(msg->msg_iter.iov);
    #endif
        if (iov == NULL)
            return 0;
        unsigned long iov_len = READ_KERN(iov->iov_len);
        if (iov_len == 0)
            return 0;
        // maybe bpf_get_prandom_u32() as a key...
        u64 pid_tgid = bpf_get_current_pid_tgid();
        dns_context_t data = {};
        data.msg = msg;
        net_conn_v4_t net_details = {};
        get_network_details_from_sock_v4(sk, &net_details, 0);
        data.conn_v4 = net_details;
        // 0 saadr
        bpf_map_update_elem(&udpmsg, &pid_tgid, &data, BPF_ANY);
    }
    return 0;
}

// in Elkeid, ip infomration is also collected, we'll add this later.
struct udpdata
{
    int opcode;
    int rcode;
    int qtype; // dns: question type. 1 - A; 5 - cname; 28 - AAAA...
    int atype; // dns: answer(rr) type. 1 - A; 5 - cname; 28 - AAAA... [just get first rr type]
};

// @Reference: https://en.wikipedia.org/wiki/Domain_Name_System
SEC("kretprobe/udp_recvmsg")
int BPF_KRETPROBE(kretprobe_udp_recvmsg, long retval)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    dns_context_t *dns_context = bpf_map_lookup_elem(&udpmsg, &pid_tgid);
    if (dns_context == 0)
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
    struct msghdr *msg = dns_context->msg;
    // Check the msghdr length
    // issue #39 BUG fix: due to wrong usage of READ_KERN
    int ret = 0;
    struct iov_iter msg_iter = {};
    struct iovec iov;

    msg_iter = READ_KERN(msg->msg_iter);

#ifdef CORE
    if (bpf_core_field_exists(msg_iter.__iov))
        ret = bpf_probe_read(&iov, sizeof(iov), msg_iter.__iov);
    else if (bpf_core_field_exists(msg_iter.iov))
        ret = bpf_probe_read(&iov, sizeof(iov), msg_iter.iov);
#else
    // TODO: need to add kernel version check here
    ret = bpf_probe_read(&iov, sizeof(iov), msg_iter.iov);
#endif

    if (ret != 0)
        goto delete;
    unsigned long iov_len = iov.iov_len;
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
    bpf_probe_read_user(&(string_p->buf[0]), iov_len & (512), iov.iov_base);
    // The data structure of dns is here...
    // |SessionID(2 bytes)|Flags(2 bytes)|Data(8 bytes)|Querys...|
    // The datas that we need are flags & querys
    int qr = (string_p->buf[2] & 0x80) ? 1 : 0;
    if (qr == 1)
    {
        event_data_t data = {};
        if (!init_event_data(&data, ctx))
            return 0;
        if (context_filter(&data.context))
            return 0;
        data.context.dt = UDP_RECVMSG;
        data.context.retval = retval;

        int opcode = (string_p->buf[2] >> 3) & 0x0f;
        int rcode = string_p->buf[3] & 0x0f;
        struct udpdata udata = {};
        udata.opcode = opcode;
        udata.rcode = rcode;
        
        int len;
        int templen;
        int end_flag = 0; // end_flag: question domain parse finished 
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
                    end_flag = 1;
                    break;
                }
                string_p->buf[(len + 1) & (MAX_PERCPU_BUFSIZE - 1)] = 46;
                len = len + templen + 1;
            }
        }

        // bad case: we hav't finished domain parse
        if (end_flag == 1) {
            udata.qtype =  string_p->buf[(len + 3) & (MAX_PERCPU_BUFSIZE - 1)] | \
                    string_p->buf[(len + 2) & (MAX_PERCPU_BUFSIZE - 1)]; 
            udata.atype =  string_p->buf[(len + 5 + 3) & (MAX_PERCPU_BUFSIZE - 1)] | \
                    string_p->buf[(len + 5 + 4) & (MAX_PERCPU_BUFSIZE - 1)];
        } else { // bad case: default val
            udata.qtype = 0;
            udata.atype = 0;
        }

        // commit: udata
        save_to_submit_buf(&data, &udata, sizeof(struct udpdata), 0);
        save_str_to_buf(&data, (void *)&string_p->buf[13], 1);
        // get exe from task
        void *exe = get_exe_from_task(data.task);
        save_str_to_buf(&data, exe, 1);
        u16 family = 2;
        save_to_submit_buf(&data, &family, sizeof(u16), 2);
        save_to_submit_buf(&data, &dns_context->conn_v4, sizeof(struct network_connection_v4), 3);
        events_perf_submit(&data);
    }
    delete : bpf_map_delete_elem(&udpmsg, &pid_tgid);
    return 0;
}
