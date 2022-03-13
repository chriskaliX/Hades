# eBPF

[nj师傅博客](https://www.njcx.bid/posts/S6.html)

## 类型

BPF_PROG_TYPE_SOCKET_FILTER：网络数据包过滤器
BPF_PROG_TYPE_KPROBE：确定是否应触发kprobe
BPF_PROG_TYPE_SCHED_CLS：网络流量控制分类器
BPF_PROG_TYPE_SCHED_ACT：网络流量控制操作
BPF_PROG_TYPE_TRACEPOINT：确定是否应触发跟踪点
BPF_PROG_TYPE_XDP：从设备驱动程序接收路径运行的网络数据包筛选器
BPF_PROG_TYPE_PERF_EVENT：确定是否应该触发性能事件处理程序
BPF_PROG_TYPE_CGROUP_SKB：用于控制组的网络数据包过滤器
BPF_PROG_TYPE_CGROUP_SOCK：用于控制组的网络数据包筛选器，允许修改套接字选项
BPF_PROG_TYPE_LWT_ *：用于轻型隧道的网络数据包过滤器
BPF_PROG_TYPE_SOCK_OPS：用于设置套接字参数的程序
BPF_PROG_TYPE_SK_SKB：网络数据包过滤器，用于在套接字之间转发数据包
BPF_PROG_CGROUP_DEVICE：确定是否应该允许设备操作

我们重点关注 BPF_PROG_TYPE_KPROBE

## Libbpf 使用

[libbpf地址](https://github.com/libbpf/libbpf)

1. `git clone https://github.com/libbpf/libbpf`
2. `cd src`
3. `make`
4. `make install`
5. `find / -name libbpf.so` 看一下安装的目录
6. `vim /etc/ld.so.conf` 把刚刚那个目录加进去
7. `ldconfig` 加载
8. `sudo ldconfig -v 2>/dev/null | grep libbpf` 如果有了代表加载成功

需要内核支持 BTF 格式, 这个内核版本要求非常高, 从官网 copy 一下

It does rely on kernel to be built with BTF type information, though. Some major Linux distributions come with kernel BTF already built in:

- Fedora 31+
- RHEL 8.2+
- OpenSUSE Tumbleweed (in the next release, as of 2020-06-04)
- Arch Linux (from kernel 5.7.1.arch1-1)
- Manjaro (from kernel 5.4 if compiled after 2021-06-18)
- Ubuntu 20.10
- Debian 11 (amd64/arm64)

确实, 和 issue 里说的一样, 如果内核版本比较固定, 不如还是 ELF 得了。看一下其他开源项目, Falco 和 Cilium 的实现

看到 osquery 支持 eBPF 的内核版本为 >= 4.18, 看了一下因为在 4.18 之后支持了 BTF... 加上 libbpf

## 学习参考

- [ ] https://github.com/cfc4n/ehids
