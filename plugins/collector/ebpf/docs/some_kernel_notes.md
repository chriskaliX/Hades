# kernel 相关字段笔记

> 纯粹为了记录 & 学习

## Namespace 

> 读 task_struct 的时候,，nsproxy 下有多种 namespace，稍微理解一下，wiki [链接](https://en.wikipedia.org/wiki/Linux_namespaces)

```c
struct nsproxy {
	atomic_t count;
	struct uts_namespace *uts_ns;
	struct ipc_namespace *ipc_ns;
	struct mnt_namespace *mnt_ns;
	struct pid_namespace *pid_ns_for_children;
	struct net 	     *net_ns;
	struct cgroup_namespace *cgroup_ns;
};
```

UTS 即 unix time-sharing 缩写。用于 host name 和 domain name 的隔离
IPC 进程通讯隔离，隔离信号量，消息队列，共享内存
MNT 挂载隔离
PID 隔离，比如 docker 内和宿主机上 pid 的关系
NET 网络隔离

在 HIDS 中，我们比较关心容器安全 & 数据相关。关于容器安全其实还没有时间完全深入(明年的大计划是搞容器检测), 所以目前相对比较浅显。
