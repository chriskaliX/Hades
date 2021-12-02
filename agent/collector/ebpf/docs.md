# Hook 梳理

> 自己写的时候容易出现乱 Hook, 想到一出是一出, 先 PLAN 好

## Target

1. 进程信息
2. TCP/UDP 网络信息
3. Dns 信息
4. Java Rasp(没搞过, 看 cfc4n 师傅写的)

## 参考 & 拆解

1. 进程信息
 - [ ] kprobe/tracepoint execve/execveat/fork
2. DNS
 - [ ] uprobe/uretprobe getaddrinfo
3. socket
 - [ ] security_socket_connect/

## 注意点

1. 兼容性问题
 - eBPF CO-RE, https://nakryiko.com/posts/bpf-core-reference-guide/#handling-incompatible-field-and-type-changes
 - kernel version：很多 bpf 下的特性受限于 kernel version。导致需要花费比较多的精力去迎合 kernel 版本，由于前期想法是 docker 下的监控使用 eBPF, KVM 启的机器还是以原先 CN_PROC 的形式去获取(判断 kernel version, 可以主动 enable)
2. 数据获取
 - 跟兼容类似的 relocation
 - 获取当前 task 下的容器信息做区分, 在 task->nsproxy 下, 字段可以参考字节

## 思考

1. 在内核版本不多(仅覆盖 k8s), 是不是可以导出固定版本的 vmlinux.h 来跑呢, 不做 CO-RE
