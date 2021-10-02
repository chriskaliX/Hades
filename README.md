# Hades

![language](https://shields.io/github/languages/top/chriskalix/HIDS-Linux)

Hades 是一款运行在 Linux 下的 HIDS，目前还在开发中。支持内核态(ebpf)以及用户态(cn_proc)的事件进程采集。目标为用纯 Golang 开发一款实际能用的，非玩具的 HIDS。其中借鉴了非常多的代码和思想(from meituan, Elkeid)

## 架构设计以及引擎

### Agent

> Agent自身接收命令，拆解Config指令，按照Osquery应该也要支持主动查询(其实就是Config中的一种)

![agent](https://github.com/chriskaliX/HIDS-Linux/blob/main/agent.png)

### 数据处理

> Agent字段连接公司对应的cmdb，做初步扩展。之后走入 Flink CEP 做初步的节点数据清洗。打入 HIVE 时根据情况，也可再做一次清洗减小性能消耗。清洗过后的数据走入第二个 Flink CEP 以及规则引擎，HIDS 的规则部分其实较为头疼，是一个 HIDS 能否用好的关键所在，后续会把自己的想法逐步开源

![data](https://github.com/chriskaliX/HIDS-Linux/blob/main/data_analyze.png)

## 目前阶段

2021-09-21: 今天压测并且运行了一段时间, 感觉可以~后续会开始研究 `ebpf` 了
2021-10-02: EBPF程序跑通，卡在环境和理解选型 CO-RE的问题消耗了比较多的时间

## 开发计划

> 按照先后顺序
> 2021-09-14 更新，觉得自己的思路有问题，太关注实现细节了。其实cn_proc，采集那一块不难的，重要是架构问题 & 设计。另外 ebpf 很好，后面跟 XDP 比较感兴趣，会再开一个仓库来学习。

- [ ] 参考 美团|字节 的 Agent 以及文章, 设计良好稳定的 Agent 架构
- [ ] 完成信息采集部分
  - [x] ncp 信息采集, 补齐进程树信息
  - [x] socket 采集 (LISTEN状态以及TCP_ESTABLISHED状态)
  - [x] process 采集 (启动阶段以及定期刷新)
  - [ ] yum 包采集
  - [ ] crontab 采集
  - [ ] 启动项采集
  - [ ] ssh 信息采集
  - [ ] pypi 采集 (恶意包, 如 request 包的检测)
  - [ ] ebpf hook kprobe 进程采集 (working)
- [ ] 完成日志部分
  - [ ] 日志设计
  - [ ] 日志存储 & 配置 & 分割
- [ ] 完成轮询交互
  - [ ] Agent 端 HTTPS 心跳 & 配置检测
  - [ ] Server 端开发 (暂时滞后, 支持集群部署)
- [ ] 自更新功能

## 框架设计

> 好的框架设计, 会让开发的时候不再迷茫, 总图

目前对 Agent 的架构设计上有点疑惑了, 我看了字节的模式, 进程之间 sock 通信，由agent统一控制plugins。暂时还不明白 Agent 自行升级，更新等如何操作。另外 unix domain 通信，没找到主动 kill 掉单个 plugin 的，可能是看的还不够多，我得找个比较合适的框架去实现
采集部分相对都是比较稳定了，还有一些文件监控，user监控，登录监控，应该都比较简单，优先度不高
分离的方式，在自更新的时候也会相对复杂，为了方便我们还是做成单个文件执行

### Agent端设计

> 自己尝试了一个初版之后, 发现自己的 Agent 存在耦合度太高, 灵活性低的问题, 遂重新学习。在阅读了字节的 Elkeid 部分代码后, 决定采用模块分离的方式。接口实现方面参考美团19年文章

统一接口

```txt
网络连接 INetRetry:
    指针回退, 尝试
配置文件 IConfig:
    配置合法性检测, 防止误操作
```

限流

```txt
网络IO:
    数据传输速度限制
磁盘IO:
    文件打开限制(因为每个进程进来后, 需要打开多个 fd, 可能会有 IO 瓶颈的问题)
    文件写入限制(同理, Log 写入后的问题)
```
