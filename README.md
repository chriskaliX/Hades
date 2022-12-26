<div align=center>
<img width="500" height="152.5" src="https://github.com/chriskaliX/Hades/blob/main/imgs/hades-low-resolution-logo-color-on-transparent-background.png"/>
</div>

<div align=center>
<img src="https://github.com/chriskaliX/Hades/actions/workflows/co-re.yaml/badge.svg"/>
</div>

# Hades - eBPF based HIDS

English | [中文](README-zh_CN.md)

Hades is a Host-based Intrusion Detection System based on eBPF and netlink(cn_proc). Now it's still under development. PRs and issues are welcome!

Declaration: This project is based on [Tracee](https://github.com/aquasecurity/tracee) and [Elkeid](https://github.com/bytedance/Elkeid). Thanks for these awesome open-source projects.

## Architecture

> Agent part is mainly based on [Elkeid](https://github.com/bytedance/Elkeid) version 1.7.

### Agent Part

![data](https://github.com/chriskaliX/Hades/blob/main/imgs/agent.png)

### Data Analysis

![data](https://github.com/chriskaliX/Hades/blob/main/imgs/data_analyze.png)

## Plugins

- [eBPF Driver](https://github.com/chriskaliX/Hades/tree/main/plugin/ebpfdriver)
- [Collector](https://github.com/chriskaliX/Hades/tree/main/plugin/collector)
- HoneyPot
- Monitor
- Scanner
- Logger

## Capability

### eBPF Driver

> Here are 21 hooks over `tracepoints`/`kprobes`/`uprobes`. The fields are extended just like Elkeid(basically).

For [details](https://github.com/chriskaliX/Hades/tree/main/plugin/ebpfdriver) of these hooks.


| Hook                                       | Status & Description                  | ID   |
| :----------------------------------------- | :------------------------------------ | :--- |
| tracepoint/syscalls/sys_enter_execve       | ON                                    | 700  |
| tracepoint/syscalls/sys_enter_execveat     | ON                                    | 698  |
| tracepoint/syscalls/sys_enter_memfd_create | ON                                    | 614  |
| tracepoint/syscalls/sys_enter_prctl        | ON(PR_SET_NAME & PR_SET_MM)           | 1020 |
| tracepoint/syscalls/sys_enter_ptrace       | ON(PTRACE_PEEKTEXT & PTRACE_POKEDATA) | 1021 |
| kprobe/security_socket_connect             | ON                                    | 1022 |
| kprobe/security_socket_bind                | ON                                    | 1024 |
| kprobe/commit_creds                        | ON                                    | 1011 |
| k(ret)probe/udp_recvmsg                    | ON(53/5353 for dns data)              | 1025 |
| kprobe/do_init_module                      | ON                                    | 1026 |
| kprobe/security_kernel_read_file           | ON                                    | 1027 |
| kprobe/security_inode_create               | ON                                    | 1028 |
| kprobe/security_sb_mount                   | ON                                    | 1029 |
| kprobe/call_usermodehelper                 | ON                                    | 1030 |
| kprobe/security_inode_rename               | ON                                    | 1031 |
| kprobe/security_inode_link                 | ON                                    | 1032 |
| uprobe/trigger_sct_scan                    | ON                                    | 1200 |
| uprobe/trigger_idt_scan                    | ON                                    | 1201 |
| kprobe/security_file_permission            | ON                                    | 1202 |
| uprobe/trigger_module_scan                 | ON                                    | 1203 |
| kprobe/security_bpf                        | ON                                    | 1204 |

### Collector

> S stands for sync(real-time), P stands for periodicity.

|   Event   | Type |
| :-------: | :--: |
|  crontab  |  P   |
| processes |  P   |
|  socket   |  P   |
| sshconfig |  P   |
| ssh login |  S   |
|   user    |  P   |
|    yum    |  P   |

### NCP

> Netlink CN_PROC

## Contact

Input `Hades` to get the QR code

<img src="https://github.com/chriskaliX/Hades/blob/main/imgs/weixin.png" width="50%" style="float:left;"/>

## 404Starlink

<img src="https://github.com/knownsec/404StarLink-Project/raw/master/logo.png" width="30%">

Hades has joined [404Starlink](https://github.com/knownsec/404StarLink)
