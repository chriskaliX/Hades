# 信息采集插件

## 快速启动

1. `make debug` 启动测试环境
2. ./collector 运行插件, 看到输出数据

## TODOList

- [ ] sshd 日志问题
- [ ] fd 获取 jar，以及对应 fatjar 问题

## Data Type对照表

> 未标识异步则代表定时查询

|名称|Data Type|
|:-|:-|
|cron|2001|
|cron - 异步|3001|
|process|1001|
|socket|5001|
|sshconfig|3005|
|ssh登陆日志|3003|
|sshd配置|3002|
|user|3004|
|yum|3003|
