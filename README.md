# Hades

![language](https://shields.io/github/languages/top/chriskalix/HIDS-Linux)

Hades 是一款运行在 Linux 下的 HIDS，目前还在开发中。支持内核态(ebpf)以及用户态(cn_proc)的事件进程采集。其中借鉴了非常多的代码和思想(from meituan, Elkeid, tracee)

## 架构设计以及引擎

### Agent

对 Agent 自身的架构设计，开始的时候比较混乱，没有设计好既定目标。在字节的 v1.7 版本 release 后，终于发现和美团之前文章的相似之处了。所有 plugins 抽象出统一的方法，包括新建 plugin，数据交互等。Agent 自身负责的是：
配置透传，Server 数据交互，插件启动停止，另外数据上传这个地方的实现待定（Agent 中自带上传，还是同样以 plugin 的形式去做）。

> 由于字节的 v1.7 版本已经 release 了，有大规模改动，但是之前读过，我会很快的过一遍

![data](https://github.com/chriskaliX/HIDS-Linux/blob/main/imgs/agentv1.png)

### 数据处理

> Agent 字段连接公司对应的 cmdb，做初步扩展。之后走入 Flink CEP 做初步的节点数据清洗。打入 HIVE 时根据情况，也可再做一次清洗减小性能消耗。清洗过后的数据走入第二个 Flink CEP 以及规则引擎，HIDS 的规则部分其实较为头疼，是一个 HIDS 能否用好的关键所在，后续会把自己的想法逐步开源

![data](https://github.com/chriskaliX/HIDS-Linux/blob/main/imgs/data_analyze.png)

## 目前阶段

用户态基本完成，eBPF 进行中, 目前 execve 字段全部采集完毕, 包括进程树, envp, cwd...

目前在重要的字段下先对齐 Elkeid, 还有一些纰漏, 慢慢的修复

![data](https://github.com/chriskaliX/HIDS-Linux/blob/main/imgs/examples.png)

## 开发计划

> 按照先后顺序。基本照搬的比较多, 很多东西看完了觉得没必要重写。但是所有搬来的代码都是人工看过的, 有些地方有问题的也反馈给社区, 我用不到的字段也被剔除, 部分优化的地方小范围重写。

我之前的 Agent 的设计耦合太重了，会参照字节的重新设计，预计过年前就开始。从一个 Agent 启动，相当于 Fork 插件的形式，之前逻辑想错了，还以为是独立的插件下发...顺便看了一下 Linux 进程间通信的[方式](https://www.linuxprobe.com/linux-process-method.html)，

翻开尘封已久的 UNIX 环境高级编程 15 章开始阅读...为了兼容性用半双工的，所以需要开启两个 pipe 作为双向读写。最早之间字节采用的方式应该是 socket 方式，找到了 performance 对比如下

https://stackoverflow.com/questions/1235958/ipc-performance-named-pipe-vs-socket

在读写效率上提高了 16%。由于创建 pipe 的时候默认会创建读写双方向的，为了兼容性还得 Close 掉各一遍的写和读，对于程序终止，用信号量的方式发送 `SIGKILL`

- [x] 参考字节重构在 v1.0.0 branch 下
  - [ ] (55%) 根据字节 Elkeid v1.7.1 通读源码, Agent 端采用 Plugin 形式 Pipe 通信。由于上传通道不走 server，考虑 agent 和 server 是否需要走 grpc? (OSQUERY心跳回连/ETCD)
    - [x] Agent 与 Plugin 侧与 Elkeid 相同  
    - [ ] Process 的 FDs 和 CPUPercentage 还没看明白, 进行中/nfpm 工程化部署
    - [ ] eBPF user端需要添加 size 大小判断, 另外 execveat 似乎有 bug，本周排查完毕
    - [ ] (20%)work with Elkeid deploy thing, very important and not familiar
    - [x] 刚刚看了 cgroups 设置, 问题1：为啥 Elkeid 需要 250M mem 而美团的文章里是 50M 左右, 问题2: cgroups 下碰到的 kernel panic 问题是啥.
  - [ ] 腾讯云盾: 在 /usr/local/sa/agent 下, 能看到是 watchdog 守护。根据配置文件也能看出一些, 比如回连 ip 下发文件等, 到时候看一遍配置文件。这个很有意思, 包括一些 bash 脚本都有带注释, 能看出一些大致思路
- [ ] 完成信息采集部分
  - [x] NCP 信息采集, 补齐进程树信息
  - [x] socket 采集 (LISTEN 状态以及 TCP_ESTABLISHED 状态)
  - [x] process 采集 (启动阶段以及定期刷新)
    - [x] process 包采集问题, ~~目前写法 getAll 有问题, 考虑自实现~~ 先用这个方式
    - [x] sha256sum 部分, 认为字节的实现不够完美, 参考 osquery 先 patch 了一版。已经提交给 Elkeid 开发, 等待回复
  - [x] yum 包采集
  - [x] crontab 采集
  - [ ] 启动项采集
  - [x] ssh 信息采集 - 配置信息
  - [ ] pypi 采集 (恶意包, 如 request 包的检测)
  - [ ] bash_history 采集, 弥补 cn_proc 下丢失的问题
  - [ ] jar 包采集(对于这种文件名采集的, 应该参考一下 osquery? 做成通用的)
  - [x] **eBPF 采集进程和外连事件**
    - [x] tracepoint sys_enter_execve (LRU 解决了问题)
    - [x] tracepoint sys_enter_connect (完毕)
    - [x] tracepoint hook (done, 但是未测试)
    - [x] channel 消费无上限, 过多会导致 ringbuffer full, 自带 drop
    - [ ] eBPF uprobe => openjdk
    - [x] eBPF 进程监控
    - [ ] 整理 ebpf 初版, 预备 release version
    - [x] 目前非 CO-RE, 后续支持
    - [ ] ehids 下有个 JVM Hook 的文章, 2022年3月份内 go through , 最好能实现 rmi 等 hook
  - [x] ssh 日志采集 - `/var/log/auth.log` | `/var/log/secure`
- [x] 完成日志部分 (搬字节的, 需要再仔细看一下)
  - [x] 日志设计
  - [x] 日志存储 & 配置 & 分割
- [ ] 完成轮询交互
  - [x] Agent 端 HTTPS 心跳 & 配置检测
  - [ ] Server 端开发 (暂时滞后, 支持集群部署)
- [ ] 自更新功能(调研)
- [ ] Yara 扫描模块
- [ ] **蜜罐模式** | 这个是我认为很有意思的模式，传统的蜜罐通常在内网下需要额外部署，部署数量或者网络配置等都会比较头疼。但是 agent 本身其实就是相当于一个 controller，我们可以随机的开放一个 port（这个功能一定要不占用正常端口），相当于大量的机器可以作为我们的蜜罐
  - [ ] 调研
  - [ ] 本身日志采集的好, 也是一个好蜜罐( SSH 等日志 )

## 调研

> [server 端 - 参考文章](https://programmer.group/grpc-service-discovery-amp-load-balancing.html)

## 交流群

<img src="https://github.com/chriskaliX/Hades/blob/main/imgs/feishu.png" width="50%" style="float:left;"/>

<img src="https://github.com/chriskaliX/Hades/blob/main/imgs/WechatIMG109.jpeg" width="50%" style="float:left;"/>
