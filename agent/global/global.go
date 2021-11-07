package global

import (
	"context"
	"os"
	"sync"
	"syscall"
	"time"

	"agent/global/structs"

	"github.com/shirou/gopsutil/v3/host"
)

var (
	pageSize = syscall.Getpagesize()

	// 全局上下文
	Context context.Context

	// 上传数据管道
	UploadChannel chan map[string]string

	// 进程管道
	ProcessChannel chan structs.Process

	// Grpc 上传数据
	GrpcChannel chan []*Record

	// 全局 byte 对象池
	BytePool *sync.Pool
)

func init() {
	// bytepool 要有初始长度, 因为扩容也有消耗
	BytePool = &sync.Pool{
		New: func() interface{} {
			return make([]byte, pageSize)
		},
	}

	Context = context.Context(context.Background())
	// 全局时间
	go func() {
		Time = uint(time.Now().Unix())
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				Time = uint(time.Now().Unix())
			case <-Context.Done():
				return
			}
		}
	}()

	// 初始化全局的上传管道
	UploadChannel = make(chan map[string]string, 1000)
	ProcessChannel = make(chan structs.Process, 1000)
	GrpcChannel = make(chan []*Record, 1000)
	// 开启的时候采集一次
	Info()
}

func Info() {
	// 初始信息
	Hostname, _ = os.Hostname()
	KernelVersion, _ = host.KernelVersion()
	Platform, PlatformFamily, PlatformVersion, _ = host.PlatformInformation()
	// 写入文件形式保存
	Getuuid()
	Getinterface()
}

func SystemInfoJob() {
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			Info()
		}
	}
}
