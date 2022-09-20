# 系统自启动进程服务管理

> 来自 Elkeid, Hades 基本一致, 学习摘抄笔记

## SYSVINIT

传统的方式

## SYSTEMD

较多的，包括我所在的环境基本用 systemd

## nfpm

https://www.cnblogs.com/rongfengliang/p/12638358.html
https://github.com/goreleaser/nfpm/releases
https://nfpm.goreleaser.com/

## 安装

将 agent 编译，命名为 hades-agent 放在该目录下
将 control 编译，命名为 hadesctl 放在改目录下

> 后续将变为简单的 Makefile

```bash
nfpm package -p rpm -t /tmp/hades-agent.rpm
yum localinstall hades-agent.rpm -y
```