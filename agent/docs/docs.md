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

## 代码风格 & 工程化反省

> 这属于基本功, 之前的代码风格基本不太好，决定以两个项目，一个是阿里的 ilogtail, 一个是 etcd 作为

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

