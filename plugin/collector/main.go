package main

import (
	"collector/ebpf"
	"collector/share"
	"context"
	"runtime"
	"sync"

	"go.uber.org/zap"
)

func init() {
	runtime.GOMAXPROCS(4)
}

// 总的方法, 为了调用清晰
var (
	Singleton *Collector
	once      sync.Once
)

type Collector struct{}

func GetCollectorSingleton() *Collector {
	once.Do(func() {
		Singleton = &Collector{}
	})
	return Singleton
}

// 定期执行, 进程采集
func (c *Collector) FlushProcessCache() {
	processes, err := GetProcess()
	if err != nil {
		zap.S().Error("get process failed")
	}
	for _, process := range processes {
		share.ProcessCache.Add(uint32(process.PID), uint32(process.PPID))
		share.ProcessCmdlineCache.Add(uint32(process.PID), process.Exe)
	}
}

// 这里采集的数据, 统一不带上主机基础信息
// 统一上传结构体然后Marshal上传
func main() {
	// 初始采集, 刷一批进内存, 能构建初步的进程树
	Singleton.FlushProcessCache()

	// 上下文控制, 有点不统一, 待会更新
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 定期刷新进程树, 一小时一次
	go ProcessUpdateJob(ctx)

	// socket 定期采集
	go SocketJob(ctx)

	// crontab 信息采集
	go CronJob(ctx)

	// sshd 信息
	go SshdConfigJob(ctx)

	// ssh 登录信息
	go GetSSH(ctx)

	// cn_proc_start()
	// go ebpf.Tracepoint_execve()
	// go ebpf.Tracer()
	go ebpf.Hades()

	// yum 信息
	GetYumJob(ctx)
}
