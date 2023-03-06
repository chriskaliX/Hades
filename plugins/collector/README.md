# 信息采集插件

> 信息采集插件是 HIDS 当中的重要一环，提供了系统层最基本的数据采集和感知能力。目前改插件支持 20 种数据的采集，以及超过 30 种应用数据的识别。

## 快速启动

> 插件支持 debug 模式

1. `make` 编译 golang 代码
2. `./collector --debug` 运行插件, 看到输出数据

## 数据对照表

> S 代表异步采集，P 代表周期采集，C 代表触发采集

|   Event   | Type |  ID  |
| :-------: | :--: |  :-: |
| processes |  P   | 1001 |
|  crontab  |  P   | 2001 |
|sshdconfig |  P   | 3002 |
| ssh login |  S   | 3003 |
|   user    |  P   | 3004 |
| sshconfig |  P   | 3005 |
|    yum    |  P   | 3006 |
|host detect|  C   | 3007 |
|    apps   |  P   | 3008 |
|    kmod   |  P   | 3009 |
|    disk   |  P   | 3010 |
|  systemd  |  P   | 3011 |
| interface |  P   | 3012 |
|  iptable  |  P   | 3013 |
|bpf_program|  P   | 3014 |
|    jar    |  P   | 3015 |
|   dpkg    |  P   | 3016 |
|    rpm    |  P   | 3017 |
| container |  P   | 3018 |
|  socket   |  P   | 5001 |
