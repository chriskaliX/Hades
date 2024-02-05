#ifndef __TYPES_H__
#define __TYPES_H__

#include <vmlinux.h>
#include <missing_definitions.h>
#include "bpf_core_read.h"
#include "bpf_helpers.h"

/* global buf type */
typedef struct simple_buf {
    u8 buf[MAX_PERCPU_BUFSIZE];
} buf_t;

/* privilege slim */
struct hds_cred_slim {
    kuid_t uid;
	kgid_t gid;
	kuid_t suid;
	kgid_t sgid;
	kuid_t euid;
	kgid_t egid;
	kuid_t fsuid;
	kgid_t fsgid;
};

/* socket information */
struct hds_socket_info {
    __u16 family;
    __u32 local_address;
    __u16 local_port;
    __u32 remote_address;
    __u16 remote_port;
};

/* process information */
struct proc_info {
    __u64 timestamp;
    __u32 pid;
    __u32 tgid;
    __u32 pgid;
    __u32 ppid;
    __u32 sid;
    __u32 socket_pid;
    char  comm[TASK_COMM_LEN];
    char  node[MAX_NODENAME];
    char  args[MAX_STR];
    /* envs */
    char  ssh_conn[MAX_STR_ENV];
    char  ld_pre[MAX_STR_ENV];
    char  ld_lib[MAX_STR_ENV];
    /* user info */
    struct hds_cred_slim cred;
    struct hds_socket_info sinfo;
    __u64 retval;
};

/* context */
struct hds_context {
    buf_t *sbt;
    __u32 data_type;
    u16  offset;
    void *ctx;
};

struct proc_info _proc SEC(".rodata") = {};
struct hds_socket_info _sinfo SEC(".rodata") = {};

#endif