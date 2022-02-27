package main

import (
	"collector/ebpf"
	// "collector/socket"
	"context"
	"runtime"
)

func init() {
	runtime.GOMAXPROCS(4)
}

// 这里采集的数据, 统一不带上主机基础信息
// 统一上传结构体然后Marshal上传
func main() {
	// 先获取User刷新, 临时代码, 先理清函数
	GetUser()

	// 上下文控制, 有点不统一, 待会更新
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 定期刷新进程树, 一小时一次
	go ProcessUpdateJob(ctx)

	// socket 定期采集
	// go socket.SocketJob(ctx)

	// crontab 信息采集
	go CronJob(ctx)

	// sshd 信息
	go SshdConfigJob(ctx)

	// sshconfig信息
	go SshConfigJob(ctx)

	// ssh 登录信息
	go GetSSH(ctx)

	// cn_proc_start()
	// go ebpf.Tracepoint_execve()
	// go ebpf.Tracer()
	go ebpf.Hades()

	// yum 信息
	GetYumJob(ctx)
}
