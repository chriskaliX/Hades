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

2021-10-18: 开始看 rpc 相关部分了, 抄着都费劲了, 先去学习一下 rpc 下的服务发现等代码了

2021-10-29: 目前看了运行数据，在空跑状态下 CPU 保持在 1-2%的占用，在大量数据的情况下会出现丢包，使CPU控制在12%下。

2021-11-14: tracepoint 下两个重要的 hook 进行中, 另外 perfbuf & ringbuf 文章也差不多了, ringbuf 缺少环境，要再看一下。后续会把 eBPF 下学习的都做成文章产出，之前学了一点别的文章也被我存着了，年底左右一并发出

## 开发计划

> 按照先后顺序
> 2021-09-14 更新，觉得自己的思路有问题，太关注实现细节了。其实cn_proc，采集那一块不难的，重要是架构问题 & 设计。另外 ebpf 很好，后面跟 XDP 比较感兴趣，会再开一个仓库来学习。

> 开发心得: 要注意以下大局观, 先在流程上打通, 再去钻研细节。另外经过一位大师傅点评，确实觉得自己工程化不够。在初期模块完毕（预计到年底）后，年后会开始看一些开源的项目，借鉴一下成熟的体系再进行大范围的重构

> 基本照搬的比较多, 很多东西看完了觉得没必要重写。但是所有搬来的代码都是人工看过的, 有些地方有问题的也反馈给社区, 我用不到的字段也被剔除, 部分优化的地方小范围重写。

- [x] 参考 美团|字节 的 Agent 以及文章, 设计良好稳定的 Agent 架构
- [ ] 完成信息采集部分
  - [x] ncp 信息采集, 补齐进程树信息
  - [x] socket 采集 (LISTEN状态以及TCP_ESTABLISHED状态)
  - [x] process 采集 (启动阶段以及定期刷新)
  - [x] yum 包采集
  - [x] crontab 采集
  - [ ] 启动项采集
  - [x] ssh 信息采集 - 配置信息
  - [ ] pypi 采集 (恶意包, 如 request 包的检测)
  - [ ] ebpf 先看 tracepoint 的
    - [x] tracepoint sys_enter_execve (进度 80% - 参考 osquery)
    - [x] tracepoint sys_enter_connect (完毕)
    - [ ] tracepoint hook 进 (connect bind accept accept4)
- [x] 完成日志部分 (搬字节的, 需要再仔细看一下)
  - [x] 日志设计
  - [x] 日志存储 & 配置 & 分割
- [ ] 完成轮询交互
  - [x] Agent 端 HTTPS 心跳 & 配置检测
  - [ ] Server 端开发 (暂时滞后, 支持集群部署)
- [ ] 自更新功能(调研)

## 框架设计

> 好的框架设计, 会让开发的时候不再迷茫, 总图

稍微看了一下 osquery 的, 应该不用做分离的 socket 通信, 独立线程就行, watchdog 守护。后续 systemd 守护

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

> 另外硬限制, cgroups 

### Server端设计

> 这个对于我来说有一点挑战, 重点在于负载均衡 & 服务发现, 高可用。关键词: service registration and discovery, load balancing and fault-tolerant processing

#### 调研

> [参考文章](https://programmer.group/grpc-service-discovery-amp-load-balancing.html)

## 性能优化

1. 很多地方替换成了 atomic
