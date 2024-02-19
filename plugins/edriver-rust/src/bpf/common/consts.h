#ifndef __CONSTS_H__
#define __CONSTS_H__

/* consts: constrains */
#define TASK_COMM_LEN               (16)
#define MAX_STRING_SIZE             (256)
#define MAX_STRING_MASK             (MAX_STRING_SIZE - 1)
#define MAX_STR_ARR_ELEM            (32)
#define MAX_PATH_COMPONENTS         (16)
#define MAX_PATH_COMPONENTS_SIM     (10)
#define MAX_NODENAME                (64)
#define MAX_PID_TREE_TRACE          (12)
#define MAX_STR                     (4096)
#define MAX_STR_ENV                 (512)
#define MAX_STR_MASK                (MAX_STR - 1)
#define MAX_PERCPU_BUFSIZE          (1 << 15)
#define MAX_PERCPU_MASK             (MAX_PERCPU_BUFSIZE - 1)
#define MID_PERCPU_BUFSIZE          (MAX_PERCPU_BUFSIZE >> 1)
#define MID_PERCPU_MASK             (MID_PERCPU_BUFSIZE - 1)
#define ARR_ARGS_LEN                (32)
#define ARR_ENVS_LEN                (64)
#define SOCKET_TRACE_LIMIT          (4)
#define SOCKET_FD_NUM_LIMIT         (12)
#define PIDTREE_LEN                 (512)
#define PIDTREE_MASK                (PIDTREE_LEN - 1)

/* consts: fds */
#define STDIN                       (0)
#define STDOUT                      (1)
#define STDERR                      (2)

/* consts: magic */
#define PIPEFS_MAGIC                (0x50495045)
#define SOCKFS_MAGIC                (0x534f434b)

/* consts: event id */
#define SYS_ENTER_MEMFD_CREATE      (614)
#define SYS_ENTER_EXECVEAT          (698)
#define SYS_ENTER_EXECVE            (700)
#define COMMIT_CREDS                (1011)
#define SYS_ENTER_PRCTL             (1020)
#define SYS_ENTER_PTRACE            (1021)
#define SYSCONNECT                  (1022)
#define SECURITY_SOCKET_BIND        (1024)
#define UDP_RECVMSG                 (1025)
#define DO_INIT_MODULE              (1026)
#define SECURITY_KERNEL_READ_FILE   (1027)
#define SECURITY_INODE_CREATE       (1028)
#define SECURITY_SB_MOUNT           (1029)
#define CALL_USERMODEHELPER         (1030)
#define SECURITY_INODE_RENAME       (1031)
#define SECURITY_INODE_LINK         (1032)
#define ANTI_RKT_SCT                (1200)
#define ANTI_RKT_IDT                (1201)
#define ANTI_RKT_FOPS               (1202)
#define ANTI_RKT_MODULE             (1203)
#define SYS_BPF                     (1204)

/* consts: vmlinux contants fix */
#define PF_KTHREAD                  0x00200000

enum buf_index
{
    LOCAL_CACHE,
    PRINT_CACHE,
    MAX_BUFFERS
};

#endif
