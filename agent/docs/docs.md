# 文档标记

## 事件标记

### HeartBeat 事件

- 1 心跳事件

### Error 类型

- 999  Error 事件

### 事件类型

- 1000 Process 事件
- 1001 Socket  事件
- 1002 User 事件
- 1003 SSH 事件
- 1004 Listening 事件

### 文件监听类型

- 2001 Crontab 事件

### 定期采集

- 3001 Crontab 信息
- 3002 SshConfig 信息
- 3003 yum 信息

## 压测

|target|cmdline|result|
|:-:|:-:|:-:|
|execve|./runltp -f syscalls -s execve -t 5m|占用一直低(阿里云乞丐版, CPU < 3% MEM < 6%), 我以为是写的特别棒, 看了一下基本都是被丢弃了...用户态取process信息的瞬时进程问题, 后续流程打通后我们会支持 `ebpf` 的, 这个有一点学习成本|

## 检测问题

### Rootkit

检测是否存在 Rookit 要怎么做呢? 或者一个地方是否被恶意内核态 Hook
想法点1. 检测内核态返回和用户态返回差异?(问了window下hades开发同学的回复)
想法点2. insmod
... 要参考一下别人的, 字节是怎么做 rootkit 级别的检测呢?

### execve 网络问题

目前我的这个是伪 ip, 只获取 envp 中的 SSH 部分。看了一下字节的代码, 在smith_hook.c 的 get_process_socket 函数里, 具体行为是: 从当前 task 开始, 不断进行向上溯源, 获取每个进程对应的 fd , 如果 fd 名称中包含 `socket:[` (socket fd), 则获取文件信息

这个 bpf 下应该也可以，开一个 LRU_MAP，然后循环一下。目前我的问题在于，C代码有点粗糙，用户态的代码也是。总有一种想要，重构的冲动

同理, pidtree, pwd 也应该尽可能全在内核态做。目前看来进度稍微落后了, 主要是因为几个数据获取的问题

## 代码风格 & 工程化反省

> 这属于基本功, 之前的代码风格基本不太好，决定以两个项目，一个是阿里的 ilogtail, 一个是 etcd 作为我的学习项目

1. 善用 interface 做代码层面抽象
2. 良好的代码注释
3. 目录结构分割明确

### 记录一些我少些的情况

> 有一些代码我会写, 但是一般会用更挫的写法... 对于代码风格和抽象的, 后续会在设计模式等等方面系统的补全

#### type func - 函数集合抽象

type MetricCreator func() MetricInput

var MetricInputs = map[string]MetricCreator{}

func AddMetricCreator(name string, creator MetricCreator) {
	MetricInputs[name] = creator
}

