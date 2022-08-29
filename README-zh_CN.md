# Hades

[![CO-RE](https://github.com/chriskaliX/Hades/actions/workflows/co-re.yaml/badge.svg)](https://github.com/chriskaliX/Hades/actions/workflows/co-re.yaml)

Hades 是一个基于 eBPF 的主机入侵检测系统，同时兼容低版本下通过 Netlink 进行事件审计。

项目借鉴了 [Tracee](https://github.com/aquasecurity/tracee) 以及 [Elkeid](https://github.com/bytedance/Elkeid) 中的代码以及思想

## Hades 架构图

> 注: Agent 部分基本参照 Elkeid 1.7 部分重构。后续考虑插件全部能兼容至 `Elkeid` 项目下

### Agent 部分

![data](https://github.com/chriskaliX/Hades/blob/main/imgs/agent.png)

### 数据处理流程

![data](https://github.com/chriskaliX/Hades/blob/main/imgs/data_analyze.png)

## 插件列表

- [Driver-eBPF](https://github.com/chriskaliX/Hades/tree/main/plugin/ebpfdriver)
- [Collector](https://github.com/chriskaliX/Hades/tree/main/plugin/collector)
- HoneyPot
- Monitor
- Scanner
- Logger

## 目前进展

支持 `15` 种 Hook，涵盖大部分安全审计检测需求

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
    - [ ] iLog 插件编写, 先支持 Kafka
    - [ ] (20%)work with Elkeid deploy thing, important but not familiar
- [ ] 1. 插件 Collector(半完成)
  - [ ] 启动项采集
  - [ ] pypi 采集 (恶意包, 如 request 包的检测)
  - [ ] bash_history 采集, 弥补 cn_proc 下丢失的问题
    - [ ] 除了定时采集, 使用 bpf uprobe hook readline 方式
  - [ ] jar 包采集 (文件名采集通用化)
    - [ ] jar 包采集和当前 java 进程引入的 jar 包需要思考一下, 扫描 /fd/ 下(字节的方式)
    - [ ] Elkeid `fatjar`, 看一下如何支持 (jar 打开 lib 目录 maybe)
  - [ ] (10%)开始代码 review，全部代码看过标准化
- [ ] 2. 插件 Yara 扫描模块
- [ ] 3. 插件 **蜜罐模式**
     这个是我认为很有意思的模式，传统的蜜罐通常在内网下需要额外部署，部署数量或者网络配置等都会比较头疼。但是 agent 本身其实就是相当于一个 controller，我们可以随机的开放一个 port（这个功能一定要不占用正常端口），相当于大量的机器可以作为我们的蜜罐
- [ ] 4. 插件 Monitor 模块插件(系统信息采集, 最后支持)
- [ ] 5. Driver 模块 (和 Elkeid 一样, 把 driver 模块提取出来) -> 目前支持 8 个 hook 点, 稳定测试且 debug 过. 现在开始实现字节 Elkeid 下所有为 On 的 hook 点.
  - [ ] (20%)code review tracee 函数 get_path_str, 本周完成与 fsprobe 的方式对比以及原理, 更新在 private repo, 到时候写个小文章
  - [x] 支持 CO-RE 编译
  - [ ] 完善 CI/CD
  - [ ] 非 CO-RE 提供 `.o` file download
  - [x] Rootkit 检测(类 Elkied)/Bad eBPF 检测
  - [ ] BTFHub Backport 方式
  - [ ] Filter 方式
- [ ] 完成轮询交互
  - [x] Agent 端 HTTPS 心跳 & 配置检测
  - [ ] Server 端开发 (暂时滞后, 支持集群部署)

## 长远计划

> 另外, 目前不感觉 CO-RE 会是一个很大的问题, 看了下 LKM 下也都需要 linux-kernel-header, 后期 plan 是先按照大部分 kernel version 把 .o 文件编译出来. 放在这里提供下载

- [ ] LKM/Rootkit
- [ ] Linux Kernel 相关已经重开 Repo, 等记录的够多了再开吧

## Other

- [Linux RootKit 初窥(一)IDT](https://chriskalix.github.io/2022/03/19/linux-rootkit%E5%88%9D%E7%AA%A5-%E4%B8%80-idt)
- [阿里云 Rootkit 检测产品 Simple Doc](https://help.aliyun.com/document_detail/194087.html?spm=5176.24320532.content1.3.7389ece6Exy34X)

## 交流群

输入 `Hades` 获取相关群二维码

<img src="https://github.com/chriskaliX/Hades/blob/main/imgs/weixin.png" width="50%" style="float:left;"/>

## 404 星链计划

<img src="https://github.com/knownsec/404StarLink-Project/raw/master/logo.png" width="30%">

Hades 现已加入 [404 星链计划](https://github.com/knownsec/404StarLink)
