<div align=center>
<img width="500" height="152.5" src="https://github.com/chriskaliX/Hades/blob/main/imgs/hades-low-resolution-logo-color-on-transparent-background.png"/>
</div>

<div align=center>
<img src="https://github.com/chriskaliX/Hades/actions/workflows/co-re.yaml/badge.svg"/>
</div>

# Hades

Hades 是一个基于 eBPF 的主机入侵检测系统，同时兼容低版本下通过 netlink(cn_proc) 进行事件审计。

申明：本项目借鉴了 [Tracee](https://github.com/aquasecurity/tracee) 以及 [Elkeid](https://github.com/bytedance/Elkeid) 中的代码以及思路等

## 架构

> 注: Agent 部分基本参照 Elkeid 1.7 部分重构

### Agent

![data](https://github.com/chriskaliX/Hades/blob/main/imgs/agent.png)

### 数据处理流程

![data](https://github.com/chriskaliX/Hades/blob/main/imgs/data_analyze.png)

## 插件列表

- [Driver-eBPF](https://github.com/chriskaliX/Hades/tree/main/plugins/ebpfdriver)
- [Collector](https://github.com/chriskaliX/Hades/tree/main/plugins/collector)
- HoneyPot
- Monitor
- Scanner
- Logger

## 采集能力

### eBPF Driver

> 支持 `21` 种 Hook，涵盖大部分安全审计检测需求，采集字段基本和 Elkeid 相同

[Hook](https://github.com/chriskaliX/Hades/tree/main/plugins/ebpfdriver) 详情查看

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

> S 代表异步采集，P 代表周期采集

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

> Netlink CN_PROC 事件采集

## 联系 & 交流

输入 `Hades` 获取相关群二维码

<img src="https://github.com/chriskaliX/Hades/blob/main/imgs/weixin.png" width="50%" style="float:left;"/>

## 404 星链计划

<img src="https://github.com/knownsec/404StarLink-Project/raw/master/logo.png" width="30%">

Hades 现已加入 [404 星链计划](https://github.com/knownsec/404StarLink)
