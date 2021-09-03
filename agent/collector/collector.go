package collector

import (
	"hids-agent/global"
	"hids-agent/network"
	"hids-agent/support"
	"runtime"
	"sync"
	"time"

	"go.uber.org/zap"
)

func init() {
	// 限制最大 PROC 数量
	runtime.GOMAXPROCS(4)
}

// 总的方法, 为了调用清晰
var (
	Singleton *Collector
	once      sync.Once
)

type Collector struct {
}

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
		global.ProcessCache.Add(uint32(process.PID), uint32(process.PPID))
		global.ProcessCmdlineCache.Add(uint32(process.PID), process.Cmdline)
	}
}

// 这里采集的数据, 统一不带上主机基础信息
// 统一上传结构体然后Marshal上传
func Run() {
	// socket 连接初始化
	clientContext := &network.Context{}
	client := &support.Client{
		Addr:    "/etc/ckhids/plugin.sock",
		Name:    "collector",
		Version: "0.0.1",
	}
	if err := clientContext.IRetry(client); err != nil {
		return
	}
	defer clientContext.IClose(client)

	Singleton.FlushProcessCache()
	// 定期


	// 开启生产进程
	go CN_PROC_START()

	// 开启消费进程, 传递至 socket 下, 限制一秒最多100条
	buf := make([]map[string]string, 0, 100)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case rd := <-global.UploadChannel:
			buf = append(buf, rd)
		case <-ticker.C:
			if len(buf) != 0 {
				err := client.Send(buf)
				buf = buf[:0]
				if err != nil {
					return
				}
			}
		}
	}
}
