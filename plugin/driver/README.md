# Hades Driver

## 为何独立出 Driver 模块

在一段时间的 eBPF 尝试之后, 发现了一些小问题：由于 BPF 的一些原因，我们无法像 LKM 一样任意操作锁等，导致其数据准确性会存在一定程度的偏差，同时在不同版本下的限制，让 BPF 在较低内核版本下会存在一定的兼容性问题。单独 driver 的原因，是希望 driver 这个模块的通用化，甚至可以作为插件直接下发到 Elkeid 中。

同样的，因为后续可能也会尝试去做 LKM 的方案，将 eBPF 从中剥离，而不是放在 Collector 模块中，我觉得会更加合理

## eBPF 快速启动 (eBPF quick start)

> 环境要求：内核版本高于 4.18, golang 版本 >= 1.17。非常建议使用 ubuntu 21.04 或者以上版本, 可以减少环境配置的时间成本

1. 下载 Hades 项目 (Download Hades)
   `git clone --recursive https://github.com/chriskaliX/Hades.git`

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

     `make core-debug`(结果输出至终端)

   - 非 CO-RE 编译(从 kernel-header)

     `make debug`(结果输出至终端)

4. 运行(Run)

   在 driver 目录下，会看见对应的 driver 文件，启动即可
   (driver file is generated in `Hades/plugin/driver`, or you can run `../driver`)

5. 过滤 id (Event filter)

   cmdline 支持 `-f` 选项，根据下面的 ID 可以指定 filter
   例如: `./driver -f 1031`， 只运行 `kprobe/security_file_ioctl` 即 anti_rootkit hook

## 目前支持 Hook

> Hook 的作用和笔记记录在 `Hades/plugin/driver/eBPF/kern/include` 下各个函数中, 持续学习并且更新。后续会讲笔记附在这个 Repo，或者新开一个 Repo 用于维护

内核态 Hook

| Hook 名称                                  | 状态/说明                             | ID   |
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

用户态 Hook
| Hook 名称 | 状态/说明 | ID |
| :----------------------------------------- | :------------------------------------ | :--- |
| uretprobe/bash_readline | ON(字段同 execve) | 2000 |

uprobe 下 bash 执行结果大概率会和 execve 下相同，考虑后期是否移除

## 内核扫描(Kernel Root scanner)

> 扫描方式: 通过内核态 eBPF 程序获取对应 table 的函数地址, 与用户态读取的 kallsyms 比对判断是否被 hook

目前支持:

|   Scan field   |
| :------------: |
| sys_call_table |
