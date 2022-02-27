#include "utils_buf.h"
#include "utils.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"
#include "bpf_tracing.h"

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

SEC("kprobe/security_socket_connect")
int kprobe_security_socket_connect(struct pt_regs *ctx)
{
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;
    data.context.type = 9;

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
    data.context.type = 10;

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
    void *exe = get_exe_from_task(data.task);
    int ret = save_str_to_buf(&data, exe, 1);
    if (ret == 0)
    {
        char nothing[] = "-1";
        save_str_to_buf(&data, nothing, 1);
    }

    return events_perf_submit(&data);
}