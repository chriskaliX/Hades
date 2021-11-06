package basis

import (
	"strconv"
	"sync/atomic"

	sysinfo "github.com/elastic/go-sysinfo"
)

// 字节在 uuid 部分支持了云上的 ID 获取方式, 在 osquery 上看过, 不过厂商肯定不一样

// 存储基础信息, 分明一点, 不放在 global 下
// 换成 elastic 的, 看起来更官方一点?
// 写的时候觉得, HIDS 做好一点, 也能满足大部分的运维监控需求
var (
	// 直接操作 string 类型是非原子的, 非并发安全的

	// 将基础数据分为, 可能并发和非并发的
	// 涉及到并发的统一改为 atomic
	PrivateIPv4     []string
	PrivateIPv6     []string
	AgentID         string
	Platform        string
	PlatformFamily  string
	PlatformVersion string
	KernelVersion   string
	Arch            string
	Timezone        string

	// string
	Hostname atomic.Value
	Uptime   atomic.Value // 分钟精确度
)

// 基础信息
func getSystembasic() error {
	host, err := sysinfo.Host()
	if err != nil {
		return err
	}
	info := host.Info()

	Platform = info.OS.Platform
	PlatformFamily = info.OS.Family
	PlatformVersion = info.OS.Version
	KernelVersion = info.KernelVersion
	Arch = info.Architecture
	Timezone = info.Timezone

	Hostname.Store(info.Hostname)
	Uptime.Store(strconv.Itoa(int(info.Uptime().Minutes())))
	return nil
}

func getSystemPerformance() error {
	return nil
}

func init() {
	getSystembasic()
}
