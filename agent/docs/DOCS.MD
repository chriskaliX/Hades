# 文档标记

## 事件标记

- 999  Error 事件
- 1000 Process 事件
- 1001 Socket  事件
- 1002 Crontab 事件
- 1003 SSH 事件
- 1004 Listening 事件
- 1005 User 事件
- 1006 System 事件
- 1007 系统信息

## 压测

|target|cmdline|result|
|:-:|:-:|:-:|
|execve|./runltp -f syscalls -s execve -t 5m|占用一直低(阿里云乞丐版, CPU < 3% MEM < 6%), 我以为是写的特别棒, 看了一下基本都是被丢弃了...用户态取process信息的瞬时进程问题, 后续流程打通后我们会支持 `ebpf` 的, 这个有一点学习成本|
