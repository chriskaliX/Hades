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

2021-12-10: 搞了一天的 log4j2...今天不commit别的，早睡了...唯一水一次

## 开发计划

> 按照先后顺序
> 2021-09-14 更新，觉得自己的思路有问题，太关注实现细节了。其实cn_proc，采集那一块不难的，重要是架构问题 & 设计。另外 ebpf 很好，后面跟 XDP 比较感兴趣，会再开一个仓库来学习。

> 开发心得: 要注意以下大局观, 先在流程上打通, 再去钻研细节。另外经过一位大师傅点评，确实觉得自己工程化不够。在初期模块完毕（预计到年底）后，年后会开始看一些开源的项目，借鉴一下成熟的体系再进行大范围的重构

> 基本照搬的比较多, 很多东西看完了觉得没必要重写。但是所有搬来的代码都是人工看过的, 有些地方有问题的也反馈给社区, 我用不到的字段也被剔除, 部分优化的地方小范围重写。

- [x] 参考 美团|字节 的 Agent 以及文章, 设计良好稳定的 Agent 架构
  - [ ] 20211121 - 重构需要提上日程, 目前能体会到自己写的时候, 有些地方比较混乱。到时候新开一个 branch 更新吧
  - [ ] 腾讯云盾, 在 /usr/local/sa/agent 下, 能看到是 watchdog 守护。根据配置文件也能看出一些, 比如回连 ip 下发文件等, 到时候看一遍配置文件。这个很有意思, 包括一些 bash 脚本都有带注释, 能看出一些大致思路
- [ ] 完成信息采集部分
  - [x] ncp 信息采集, 补齐进程树信息
  - [x] socket 采集 (LISTEN状态以及TCP_ESTABLISHED状态)
  - [x] process 采集 (启动阶段以及定期刷新)
    - [x] process 包采集问题, ~~目前写法 getAll 有问题, 考虑自实现~~ 先用这个方式
    - [x] sha256sum 部分, 认为字节的实现不够完美, 参考 osquery 先 patch 了一版。已经提交给 Elkeid 开发, 等待回复
  - [x] yum 包采集
  - [x] crontab 采集
  - [ ] 启动项采集
  - [x] ssh 信息采集 - 配置信息
  - [ ] pypi 采集 (恶意包, 如 request 包的检测)
  - [ ] bash_history采集, 弥补 cn_proc 下丢失的问题
  - [ ] jar 包采集(对于这种文件名采集的, 应该参考一下 osquery? 做成通用的)
  - [x] **ebpf 采集进程和外连事件**
    - [x] tracepoint sys_enter_execve (LRU 解决了问题)
    - [x] tracepoint sys_enter_connect (完毕)
    - [x] tracepoint hook (done, 但是未测试)
    - [x] ~~ebpf 程序提高 channel 消费速度~~ channel 消费无上限, 过多会导致 ringbuffer full, 自带 drop
    - [ ] ebpf uprobe
    - [ ] ebpf 进程监控
    - [x] ~~编译|CORE~~  重要更新点: 能看到的程序大部分方式为: bpftool 导出 vmlinux.h, 但是在没有 vmlinux 的机器上, 需要 pahole 等等, 开启 BTF 重新编译, 比较麻烦。在看了 tracee 的方法后, 选择直接根据当前机器的 kernel header 去编译, 这样不能 CO-RE, 但是因为目的本身是跑在容器宿主机上, 其版本相对来讲比较固定, 可以先这么操作, 不过 kernel 版本还是要求 4.18+
    - [x] 解决三个问题
      - [x] ~~/bin/sh 采集问题~~ percpu fix
      - [x] ~~argv 部分情况重复~~ percpu fix
      - [x] ~~多 cpu 乱序, 导致消费程序需要做 reordering | 或者看一下如何直接发送一个完整的 argv( 不能 perf 有limit? )~~ percpu fix
  - [ ] ssh 日志采集 (journalctl)
- [x] 完成日志部分 (搬字节的, 需要再仔细看一下)
  - [x] 日志设计
  - [x] 日志存储 & 配置 & 分割
- [ ] 完成轮询交互
  - [x] Agent 端 HTTPS 心跳 & 配置检测
  - [ ] Server 端开发 (暂时滞后, 支持集群部署)
- [ ] 自更新功能(调研)
- [ ] yara 扫描模块
- [ ] **蜜罐模式** | 这个是我认为很有意思的模式，传统的蜜罐通常在内网下需要额外部署，部署数量或者网络配置等都会比较头疼。但是 agent 本身其实就是相当于一个 controller，我们可以随机的开放一个 port（这个功能一定要不占用正常端口），相当于大量的机器可以作为我们的蜜罐
  - [ ] 调研
  - [ ] 本身日志采集的好, 也是一个好蜜罐( SSH等日志 )

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

## 交流群

![agent](https://github.com/chriskaliX/Hades/blob/main/feishu1.png)
