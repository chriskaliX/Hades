# HIDS-Linux

> Linux HIDS based on Netlink Connector, cn_proc. Learn from [kinvolk](https://github.com/kinvolk/nswatch/blob/5ed779a0cbdfa80403ea42909ca157a89719f159/nswatch.go), [Elkeid](https://github.com/bytedance/Elkeid/blob/main/README-zh_CN.md)

## 开发目的

较为完整的学习用户态采集的方案, 能够开发出一款稳定的纯 golang ncp 采集的 HIDS。使得其能够稳定的运行在 Linux 主机上。
同时要对自己的开发水平有所认知, 在单人开发的情况下, 不尝试过大过多过难的功能...做出一个可用的即为我们的目标

## 目前阶段

目前还属于玩具状态, 图个乐...
各种借鉴(搬), 思考, 尝试

## 开发计划

> 按照先后顺序

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
- [ ] 完成日志部分
  - [ ] 日志设计
  - [ ] 日志存储 & 配置 & 分割
- [ ] 完成轮询交互
  - [ ] Agent 端 HTTPS 心跳 & 配置检测
  - [ ] Server 端开发 (暂时滞后, 支持集群部署)

## 框架设计

> 好的框架设计, 会让开发的时候不再迷茫, 总图

目前对 Agent 的架构设计上有点疑惑了, 我看了字节的模式, 进程之间 sock 通信，由agent统一控制plugins。暂时还不明白 Agent 自行升级，更新等如何操作。另外 unix domain 通信，没找到主动 kill 掉单个 plugin 的，可能是看的还不够多，我得找个比较合适的框架去实现
采集部分相对都是比较稳定了，还有一些文件监控，user监控，登录监控，应该都比较简单，优先度不高
分离的方式，在自更新的时候也会相对复杂，为了方便我们还是做成单个文件执行

### Agent端设计

> 自己尝试了一个初版之后, 发现自己的 Agent 存在耦合度太高, 灵活性低的问题, 遂重新学习。在阅读了字节的 Elkeid 部分代码后, 决定采用模块分离的方式。接口实现方面参考美团19年文章

进程通信

```txt
目前只计划实现 Collector 下的模块, 后期仅需扩容即可

------- Agent 进程(负责配置解析, 任务下发, Server 通信)
   |(unix域通信)
   --- Collector(负责进程事件采集, 循环配置采集)
```

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

## 运行图片

![image](https://blob/main/hids1.png)
