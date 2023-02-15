# 信息采集插件

## 快速启动

1. `make` 编译 golang 代码
2. `./collector --debug` 运行插件, 看到输出数据

## TODOList

- [ ] fd 获取 jar，以及对应 fatjar 问题

## Data Type对照表

> 未标识异步则代表定时查询

|名称|Data Type|
|:-|:-|
|cron|2001|
|cron - 异步|3001|
|process|1001|
|socket|5001|
|sshd_config|3002|
|ssh_log|3003|
|user|3004|
|ssh_config|3005|
|yum|3006|
|host_scan|3007|
|apps|3008|
|kmod|3009|
|disk|3010|
|systemd_unit|3011|
|net_interface|3012|
|iptables|3013|
|bpf_prog|3014|
