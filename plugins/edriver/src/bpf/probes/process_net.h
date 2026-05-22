// SPDX-License-Identifier: GPL-2.0-or-later

#ifndef __PROBES_PROCESS_NET_H__
#define __PROBES_PROCESS_NET_H__

#include <vmlinux.h>
#include <missing_definitions.h>
#include "runtime/constants.h"
#include "runtime/task_helpers.h"
#include "runtime/maps.h"
#include "bpf_core_read.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_endian.h"

struct connect_ctx {
    int fd;
    __u16 family;
};

struct udp_recv_ctx {
    __u16 family;
    struct hds_socket_info sinfo;
    struct hds_socket_info_v6 sinfo_v6;
};

BPF_LRU_HASH(connect_cache, __u64, struct connect_ctx, 4096);
BPF_LRU_HASH(udp_recv_cache, __u64, struct udp_recv_ctx, 4096);

SEC("tracepoint/syscalls/sys_enter_connect")
int tp__sys_enter_connect(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct connect_ctx cache = {};
    cache.fd = (int)ctx->args[0];

    void *uaddr = (void *)ctx->args[1];
    if (!uaddr)
        return 0;
    if (bpf_probe_read_user(&cache.family, sizeof(cache.family),
                            &((struct sockaddr *)uaddr)->sa_family) < 0)
        return 0;

    if (cache.family != AF_INET && cache.family != AF_INET6)
        return 0;

    bpf_map_update_elem(&connect_cache, &pid_tgid, &cache, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_connect")
int tp__sys_exit_connect(struct trace_event_raw_sys_exit *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct connect_ctx *cache = bpf_map_lookup_elem(&connect_cache, &pid_tgid);
    if (!cache)
        return 0;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task)
        goto out;

    struct file *f = fget_raw(task, cache->fd);
    if (!f)
        goto out;
    struct socket *sock = socket_from_file(f);
    if (!sock)
        goto out;
    struct sock *sk = BPF_CORE_READ(sock, sk);
    if (!sk)
        goto out;

    struct hds_socket_info sinfo = {};
    struct hds_socket_info_v6 sinfo_v6 = {};
    if (cache->family == AF_INET)
        get_sock_v4(sk, &sinfo);
    else
        get_sock_v6(sk, &sinfo_v6);

    struct path exe = BPF_CORE_READ(task, mm, exe_file, f_path);
    void *exe_path = get_path(__builtin_preserve_access_index(&exe));

    struct hds_context event_ctx = init_context(ctx, SYSCONNECT);
    EVT_SUBMIT(&event_ctx,
        &event_ctx.data_type,
        &cache->fd,
        &cache->family,
        &ctx->ret,
        &sinfo,
        &sinfo_v6,
        exe_path);
    report_event(&event_ctx);

out:
    bpf_map_delete_elem(&connect_cache, &pid_tgid);
    return 0;
}

SEC("kprobe/security_socket_bind")
int BPF_KPROBE(kprobe_security_socket_bind)
{
    struct socket *sock = (struct socket *)PT_REGS_PARM1(ctx);
    struct sockaddr *address = (struct sockaddr *)PT_REGS_PARM2(ctx);
    if (!sock || !address)
        return 0;

    __u16 family = BPF_CORE_READ(address, sa_family);
    if (family != AF_INET && family != AF_INET6)
        return 0;

    struct sock *sk = BPF_CORE_READ(sock, sk);
    __u16 protocol = 0;
    if (sk)
        protocol = (__u16)BPF_CORE_READ(sk, sk_protocol);

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task)
        return 0;
    struct path exe = BPF_CORE_READ(task, mm, exe_file, f_path);
    void *exe_path = get_path(__builtin_preserve_access_index(&exe));

    struct hds_context event_ctx = init_context(ctx, SECURITY_SOCKET_BIND);
    EVT_WRITE(&event_ctx, &event_ctx.data_type, sizeof(__u32));
    if (family == AF_INET)
        EVT_WRITE(&event_ctx, address, sizeof(struct sockaddr_in));
    else
        EVT_WRITE(&event_ctx, address, sizeof(struct sockaddr_in6));
    EVT_WRITE_AUTO(&event_ctx, exe_path);
    EVT_WRITE(&event_ctx, &protocol, sizeof(__u16));
    return report_event(&event_ctx);
}

SEC("kprobe/udp_recvmsg")
int BPF_KPROBE(kprobe_udp_recvmsg)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (!sk)
        return 0;

    __u16 family = BPF_CORE_READ(sk, sk_family);
    if (family != AF_INET && family != AF_INET6)
        return 0;

    struct udp_recv_ctx cache = {};
    cache.family = family;
    if (family == AF_INET)
        get_sock_v4(sk, &cache.sinfo);
    else
        get_sock_v6(sk, &cache.sinfo_v6);

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&udp_recv_cache, &pid_tgid, &cache, BPF_ANY);
    return 0;
}

SEC("kretprobe/udp_recvmsg")
int BPF_KRETPROBE(kretprobe_udp_recvmsg, long ret)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct udp_recv_ctx *cache = bpf_map_lookup_elem(&udp_recv_cache, &pid_tgid);
    if (!cache)
        return 0;

    struct hds_context event_ctx = init_context(ctx, UDP_RECVMSG);
    EVT_SUBMIT(&event_ctx,
        &event_ctx.data_type,
        &cache->family,
        &ret,
        &cache->sinfo,
        &cache->sinfo_v6);
    report_event(&event_ctx);

    bpf_map_delete_elem(&udp_recv_cache, &pid_tgid);
    return 0;
}

#endif