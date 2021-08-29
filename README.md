# HIDS-Linux

> Linux HIDS based on Netlink Connector, cn_proc. Learn from [kinvolk](https://github.com/kinvolk/nswatch/blob/5ed779a0cbdfa80403ea42909ca157a89719f159/nswatch.go), [Elkeid](https://github.com/bytedance/Elkeid/blob/main/README-zh_CN.md)

## 开发目的

较为完整的学习用户态采集的方案, 能够开发出一款稳定的纯 golang ncp 采集的 HIDS。使得其能够稳定的运行在 Linux 主机上

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

![image](https://github.com/chriskaliX/HIDS-Linux/blob/main/hids1.png)
