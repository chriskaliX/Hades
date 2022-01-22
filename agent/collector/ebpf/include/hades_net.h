#include "utils_buf.h"
#include "utils.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"
#include "bpf_tracing.h"

// SEC("kprobe/security_socket_create")
// int security_socket_create() {

// }

SEC("kprobe/security_socket_connect")
int kprobe_security_socket_connect(struct pt_regs *ctx) {
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;
    data.context.type = 9;

    struct sockaddr *address = (struct sockaddr *)PT_REGS_PARM2(ctx);
    uint addr_len = (uint)PT_REGS_PARM3(ctx);
    sa_family_t sa_fam = READ_KERN(address->sa_family);
    if ( (sa_fam != AF_INET) && (sa_fam != AF_INET6) && (sa_fam != AF_UNIX)) {
        return 0;
    }
    // TODO: maybe a filter to localhost
    switch (sa_fam)
    {
    case AF_INET:
        save_to_submit_buf(&data, (void *)address, sizeof(struct sockaddr_in), 0);
        break;
    case AF_INET6:
        save_to_submit_buf(&data, (void *)address, sizeof(struct sockaddr_in6), 0);
        break;
    // TODO: finish here
    case AF_UNIX:
        break;
    default:
        break;
    }
    return events_perf_submit(&data);
}

SEC("kprobe/security_socket_bind")
int kprobe_security_socket_bind(struct pt_regs *ctx) {
    event_data_t data = {};
    if (!init_event_data(&data, ctx))
        return 0;
    data.context.type = 10;
    struct socket *sock = (struct socket *)PT_REGS_PARM1(ctx);
    struct sock *sk = READ_KERN(sock->sk);

    struct sockaddr *address = (struct sockaddr *)PT_REGS_PARM2(ctx);
    uint addr_len = (uint)PT_REGS_PARM3(ctx);

    sa_family_t sa_fam = READ_KERN(address->sa_family);
    if ( (sa_fam != AF_INET) && (sa_fam != AF_INET6) && (sa_fam != AF_UNIX)) {
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
    // TODO: finish here
    case AF_UNIX:
        break;
    default:
        break;
    }
    return events_perf_submit(&data);
}