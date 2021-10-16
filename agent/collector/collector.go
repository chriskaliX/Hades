package collector

import (
	"encoding/json"
	"math/rand"
	"runtime"
	"strconv"
	"sync"
	"time"

	"agent/config"
	"agent/global/structs"
	"agent/network"
	"agent/utils"

	"agent/global"

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
	// 初始采集, 刷一批进内存, 能构建初步的进程树
	Singleton.FlushProcessCache()

	// 开启生产进程
	// 必须 netlink 连接上, 否则没有进程采集功能了
	// 强制退出
	err := CN_PROC_START()
	if err != nil {
		zap.S().Error(err)
		return
	}

	// 定期刷新进程树, 一小时一次
	go func() {
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				Singleton.FlushProcessCache()
			case <-global.Context.Done():
				return
			}
		}
	}()

	// socket 定期采集
	// 在同一时间突然流量激增导致丢弃，给一个初始随机值，再reset掉
	go func() {
		init := true
		ticker := time.NewTicker(time.Second * time.Duration(rand.Intn(600)+1))
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if init {
					ticker.Reset(time.Hour)
					init = false
				}
				// 是否开启proc，统一关闭先
				socks, err := GetSockets(false, network.TCP_ESTABLISHED)
				if err == nil {
					data, err := json.Marshal(socks)
					if err == nil {
						rawdata := make(map[string]string)
						rawdata["time"] = strconv.Itoa(int(global.Time))
						rawdata["data"] = string(data)
						rawdata["data_type"] = "1001"
						global.UploadChannel <- rawdata
					}
				}
			}
		}
	}()

	// 系统信息24小时上传一次
	go func() {
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				global.Info()
			}
		}
	}()

	// 开启定期消费
	// 控制消费速率, 上限为一秒 1000 次, 多余的事件会被丢弃
	// 防止打开过多 fd 造成资源占用问题
	// go func() {
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			pid := <-global.PidChannel
			process, err := GetProcessInfo(pid)
			if err != nil {
				process.Reset()
				structs.ProcessPool.Put(process)
				continue
			}
			// 白名单校验
			if config.WhiteListCheck(process) {
				process.Reset()
				structs.ProcessPool.Put(process)
				continue
			}

			global.ProcessCmdlineCache.Add(pid, process.Cmdline)
			if ppid, ok := global.ProcessCache.Get(pid); ok {
				process.PPID = int(ppid.(uint32))
			}
			process.PidTree = global.GetPstree(uint32(process.PID))
			// json 对 html 字符会转义, 转用下面方法是否会对性能有影响? 需要再看一下
			// data, err := json.Marshal(process)
			data, err := utils.Marshal(process)
			if err == nil {
				rawdata := make(map[string]string)
				rawdata["data"] = string(data)
				rawdata["time"] = strconv.Itoa(int(global.Time))
				rawdata["data_type"] = "1000"
				global.UploadChannel <- rawdata
			}
			process.Reset()
			structs.ProcessPool.Put(process)
		case <-global.Context.Done():
			return
		}
	}
}
