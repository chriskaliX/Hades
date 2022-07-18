# Hades

[![CO-RE](https://github.com/chriskaliX/Hades/actions/workflows/co-re.yaml/badge.svg)](https://github.com/chriskaliX/Hades/actions/workflows/co-re.yaml)

English | [中文](README-zh_CN.md)

Hades is a Host-based Intrusion Detection System based on eBPF and Netlink/cn_proc. Now it's still under development. PRs and issues are welcome!

This project is based on [Tracee](https://github.com/aquasecurity/tracee) and [Elkeid](https://github.com/bytedance/Elkeid). Thanks for these awesome open-source projects.

## Architecture

> Agent part is mainly based on [Elkeid](https://github.com/bytedance/Elkeid) version 1.7. And I am going to make plugins(including the driver) compatible with Elkeid.

### Agent Part

![data](https://github.com/chriskaliX/Hades/blob/main/imgs/agent.png)

### Data Analysis

![data](https://github.com/chriskaliX/Hades/blob/main/imgs/data_analyze.png)

## Plugins

- [Driver-eBPF](https://github.com/chriskaliX/Hades/tree/main/plugin/driver/eBPF)
- [Collector](https://github.com/chriskaliX/Hades/tree/main/plugin/collector)
- HoneyPot
- Monitor
- Scanner
- Logger

## Capability

### Driver-eBPF

> Here are 15 hooks over `tracepoints`/`kprobes`/`uprobes`. The fields are extended just like Elkeid(basically).

For [details](https://github.com/chriskaliX/Hades/tree/main/plugin/driver) of these hooks.

Also, Rootkit detection(anti_rootkit) for `sys_call_table` hook is updated now.

| Hook                                       | Default Status(Description)           | ID   |
| :----------------------------------------- | :------------------------------------ | :--- |
| tracepoint/syscalls/sys_enter_execve       | ON                                    | 700  |
| tracepoint/syscalls/sys_enter_execveat     | ON                                    | 698  |
| tracepoint/syscalls/sys_enter_prctl        | ON(PR_SET_NAME & PR_SET_MM)           | 200  |
| tracepoint/syscalls/sys_enter_ptrace       | ON(PTRACE_PEEKTEXT & PTRACE_POKEDATA) | 164  |
| tracepoint/syscalls/sys_enter_memfd_create | ON                                    | 614  |
| kprobe/security_socket_connect             | ON                                    | 1022 |
| kprobe/security_socket_bind                | ON                                    | 1024 |
| kprobe/commit_creds                        | ON                                    | 1011 |
| k(ret)probe/udp_recvmsg                    | ON(53/5353 for dns data)              | 1025 |
| kprobe/do_init_module                      | ON                                    | 1026 |
| security_kernel_read_file                  | ON                                    | 1027 |
| security_inode_create                      | ON                                    | 1028 |
| security_sb_mount                          | ON                                    | 1029 |
| kprobe/call_usermodehelper                 | ON                                    | 1030 |
| kprobe/security_file_ioctl                 | ON(anti rootkit scan)                 | 1031 |

### Collector

> S stands for sync(real-time), P stands for periodicity.

|   Event   | Type |
| :-------: | :--: |
|  cn_proc  |  S   |
|  crontab  |  P   |
| processes |  P   |
|  socket   |  P   |
| sshconfig |  P   |
| ssh login |  S   |
|   user    |  P   |
|    yum    |  P   |

## Purpose

I maintain this project mainly for learning eBPF and HIDS

## Contact

Input `Hades` to get the QR code~

<img src="https://github.com/chriskaliX/Hades/blob/main/imgs/weixin.png" width="50%" style="float:left;"/>
