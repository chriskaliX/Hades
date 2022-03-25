# Hades

![language](https://shields.io/github/languages/top/chriskalix/HIDS-Linux)

Hades 是一个基于 eBPF 的主机入侵检测系统，同时兼容低版本下通过 Netlink 进行事件审计。

项目借鉴了 [Tracee](https://github.com/aquasecurity/tracee) 以及 [Elkeid](https://github.com/bytedance/Elkeid) 中的代码以及思想

## Hades 架构图

> 注: Agent 部分基本参照 Elkeid 1.7 部分重构。后续考虑插件全部能兼容至 `Elkeid` 项目下

### Agent 部分

![data](https://github.com/chriskaliX/HIDS-Linux/blob/main/imgs/agent.png)

### 数据处理流程

![data](https://github.com/chriskaliX/HIDS-Linux/blob/main/imgs/data_analyze.png)

## 插件列表

- [Driver-eBPF](https://github.com/chriskaliX/Hades/tree/main/plugin/driver/eBPF)
- [Collector](https://github.com/chriskaliX/Hades/tree/main/plugin/collector)
- HoneyPot
- Monitor
- Scanner
- Logger

## 目前进展

支持 `14` 种 Hook，涵盖大部分安全审计检测需求

## 开发计划

> 记录一些方案选择, 目前进度等，另外 golang 1.18 上线啦~ [官方 Tutorial](https://golang.google.cn/doc/tutorial/generics)，后续会开始多试试 Generics

### Agent-插件 交互

> Linux 进程间通信的[方式](https://www.linuxprobe.com/linux-process-method.html)

后续会全部 review 这里的方式，先挖一个坑

翻开尘封已久的 UNIX 环境高级编程 15 章开始阅读...为了兼容性用半双工的，所以需要开启两个 pipe 作为双向读写。最早之间字节采用的方式应该是 socket 方式，找到了 [performance 对比](https://stackoverflow.com/questions/1235958/ipc-performance-named-pipe-vs-socket)

在读写效率上提高了 16%。由于创建 pipe 的时候默认会创建读写双方向的，为了兼容性还得 Close 掉各一遍的写和读，对于程序终止，用信号量的方式发送 `SIGKILL`

### 开发进度

- [x] 参考字节 Elkeid 1.7 重构在 v1.0.0 branch 下
  - [ ] (80%) 根据字节 Elkeid v1.7.1 通读源码, Agent 端采用 Plugin 形式 Pipe 通信。由于上传通道不走 server，考虑 agent 和 server 是否需要走 grpc? (OSQUERY 心跳回连/ETCD)
    - [x] Agent 与 Plugin 侧与 Elkeid 相同
    - [x] Elkeid Deploy 部分基本照搬
    - [x] 出现在 runltp 下, 查询 cwd 为 NULL 会导致写入失败, 默认重写入 "-1"
    - [ ] iLog 插件编写, 先支持 Kafka
    - [ ] (20%)work with Elkeid deploy thing, very important and not familiar
- [ ] 1. 插件 Collector(半完成)
  - [x] NCP 信息采集, 补齐进程树信息
  - [x] socket 采集
  - [x] process 采集 (启动阶段以及定期刷新/TODO: 注意 Elkeid v1.7 对 exe_hash 的变更)
  - [x] yum 包采集
  - [x] crontab 采集
  - [ ] 启动项采集
  - [x] sshd/ssh config collection
  - [ ] pypi 采集 (恶意包, 如 request 包的检测)
  - [ ] bash_history 采集, 弥补 cn_proc 下丢失的问题
    - [ ] 除了定时采集, 使用 bpf uprobe hook readline 方式
  - [ ] jar 包采集(对于这种文件名采集的, 应该参考一下 osquery? 做成通用的)
    - [ ] jar 包采集和当前 java 进程引入的 jar 包需要思考一下, 扫描 /fd/ 下(字节的方式), 对 fatjar 可能无法采集。需要考虑别的方式?
  - [x] ssh 日志采集 - `/var/log/auth.log` | `/var/log/secure`
  - [ ] (10%)开始代码 review，全部代码看过标准化
- [ ] 2. 插件 Yara 扫描模块
- [ ] 3. 插件 **蜜罐模式**
     这个是我认为很有意思的模式，传统的蜜罐通常在内网下需要额外部署，部署数量或者网络配置等都会比较头疼。但是 agent 本身其实就是相当于一个 controller，我们可以随机的开放一个 port（这个功能一定要不占用正常端口），相当于大量的机器可以作为我们的蜜罐
- [ ] 4. 插件 Monitor 模块插件(系统信息采集, 最后支持)
- [ ] 5. Driver 模块 (和 Elkeid 一样, 把 driver 模块提取出来) -> 目前支持 8 个 hook 点, 稳定测试且 debug 过. 现在开始实现字节 Elkeid 下所有为 On 的 hook 点.
  - [x] tracepoint sys_enter_execve (LRU 解决了问题)
  - [x] tracepoint sys_enter_prctl 完毕, 添加了 PR_SET_MM
  - [x] tracepoint sys_enter_connect (完毕)
  - [x] tracepoint hook (done, 但是未测试)
  - [x] channel 消费无上限, 过多会导致 ringbuffer full, 自带 drop
  - [x] 过 Prctl 部分, 字节只 hook PR_SET_NAME，考虑添加 PR_SET_MM
  - [x] (100%)第一轮 review 修改进行中. 使用 ebpfmanager 重构了一下. memfd_create 添加, LSM bind 函数 ipv6 添加, 有个小的问题： json 效率和 inline
  - [x] eBPF uprobe(openjdk/readline)... (对于OpenJDK)的观测稍微延后, 需要作为一个可配置模块
  - [x] 面向对象, ebpfmanager review 使用
  - [x] eBPF 进程监控
  - [x] socket 下完全支持 ipv6, 字段丰富 EXE 完成(跟之前一样, 无 lock 操作, 可能有读错的问题)
  - [ ] 整理 ebpf 初版, 预备 release version
  - [ ] (20%)code review tracee 函数 get_path_str, 本周完成与 fsprobe 的方式对比以及原理, 更新在 private repo, 到时候写个小文章
  - [x] 目前非 CO-RE, 后续支持
  - [x] ehids 下有个 JVM Hook 的文章, 2022 年 3 月份内 go through , 最好能实现 rmi 等 hook
  - [x] [cd00r.c](https://github.com/ehids/rootkit-sample)这个 2000 的 backdoor 稍微看了一下，以及对应的 pdf。本质上新颖的地方在于不会暴露端口，libpcap 的模式来监听 knock, 看起来和 tcpdump 一样, 上述盘古文章里的后门里，这个应该是很小的一环。cd00r.c 是用户态的一个 demo，如果整合进来做成 rootkit 也挺好。
- [ ] 完成轮询交互
  - [x] Agent 端 HTTPS 心跳 & 配置检测
  - [ ] Server 端开发 (暂时滞后, 支持集群部署)

## 长远计划

> 另外, 目前不感觉 CO-RE 会是一个很大的问题, 看了下 LKM 下也都需要 linux-kernel-header, 后期 plan 是先按照大部分 kernel version 把 .o 文件编译出来. 放在这里提供下载

- [ ] LKM/Rootkit
- [ ] Linux Kernel 相关已经重开 Repo, 等记录的够多了再开吧

## Other

- [Linux RootKit初窥(一)IDT](https://chriskalix.github.io/2022/03/19/linux-rootkit%E5%88%9D%E7%AA%A5-%E4%B8%80-idt)
- [阿里云 Rootkit 检测产品 Simple Doc](https://help.aliyun.com/document_detail/194087.html?spm=5176.24320532.content1.3.7389ece6Exy34X)

## 交流群

<img src="https://github.com/chriskaliX/Hades/blob/main/imgs/WechatIMG120.jpeg" width="50%" style="float:left;"/>
