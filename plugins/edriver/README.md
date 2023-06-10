# Hades eBPF-Driver

> Hades eBPF-Driver 是基于 eBPF 编写的 Hook 数据获取，是整个 Hades 最关键的部分。基于 tracee 做了大量的改造和修复，执行方式参考 Elkeid

> Hades eBPF-Driver is a eBPF-driven kernel hooker which is the most important part of Hades. Driver is based on tracee and I do a lot of modification. Draw on Elkeid.

## eBPF 快速启动 (eBPF quick start)

> 环境要求：内核版本高于 4.18, golang 版本 >= 1.17。非常建议使用 ubuntu 21.04 或者以上版本, 可以减少环境配置的时间成本

> kernel version over 4.18 and >= 1.17 is required. OS like ubuntu 21.04 is recommanded since it's easier for testing

1. 下载 Hades 项目 (Download Hades)

   ```bash
   git clone --recursive https://github.com/chriskaliX/Hades.git
   ```

2. 下载 Header，如果内核支持 BTF 可以跳过 (Download kernel header, skip if BTF is supported)

   ```bash
   # CentOS/RHEL 7
   yum install kernel-devel
   # Fedora
   dnf install kernel-devel
   # Ubuntu
   apt install linux-headers-$(uname -r)
   ```

3. 编译(Compile)

   进入 eBPF 文件夹 `cd /eBPF`

   - CORE 编译

     `make core`

   - 非 CO-RE 编译(从 kernel-header)

     `make`

4. 运行(Run)

   在 driver 目录下，会看见对应的 driver 文件，启动即可。

   默认情况下不会有输出，指定 **`--env debug`** 可以看到输出
   (driver file is generated in `Hades/plugins/edriver`, or you can run `./edriver`, `--debug` to get the output)

## 目前支持 Hook

> Hook 的作用和笔记记录在 `Hades/plugins/edriver/bpf/include` 下各个函数中, 持续学习并且更新。后续会讲笔记附在这个 Repo，或者新开一个 Repo 用于维护

内核态 Hook

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

用户态 Hook
| Hook 名称 | 状态/说明 | ID |
| :----------------------------------------- | :------------------------------------ | :--- |
| uretprobe/bash_readline | ON(字段同 execve) | 2000 |

uprobe 下 bash 执行结果大概率会和 execve 下相同，考虑后期是否移除

## 内核扫描(Kernel Scanner)

> 扫描方式: 通过内核态 eBPF 程序获取对应 table 的函数地址, 与用户态读取的 kallsyms 比对判断是否被 hook

目前支持:

|   Scan field   |
| :------------: |
| sys_call_table |
