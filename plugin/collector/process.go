package main

import (
	"collector/cache"
	"collector/share"
	"context"
	"encoding/json"
	"math/rand"
	"time"

	"os"
	"strconv"

	"github.com/chriskaliX/plugin"
	"go.uber.org/zap"
)

// modify this according to Elkeid
const (
	MaxProcess             = 1500
	ProcessIntervalMillSec = 100
)

// Elkeid impletement still get problem when pid is too much, like 100,000+
func GetPids(limit int) (pids []int, err error) {
	// pre allocation
	pids = make([]int, 0, 100)
	d, err := os.Open("/proc")
	if err != nil {
		return
	}
	names, err := d.Readdirnames(limit + 50)
	if err != nil {
		return
	}
	for _, name := range names {
		if limit == 0 {
			return
		}
		pid, err := strconv.ParseInt(name, 10, 64)
		if err == nil {
			pids = append(pids, int(pid))
			limit -= 1
		}
	}
	return
}

func GetProcess() (procs []*cache.Process, err error) {
	var pids []int
	pids, err = GetPids(MaxProcess)
	if err != nil {
		return
	}
	for _, pid := range pids {
		proc, err := GetProcessInfo(pid)
		if err != nil {
			continue
		}
		procs = append(procs, proc)
		time.Sleep(time.Duration(ProcessIntervalMillSec) * time.Millisecond)
	}
	return
}

// 获取单个 process 信息
func GetProcessInfo(pid int) (proc *cache.Process, err error) {
	// 对象池获取
	proc = cache.DefaultProcessPool.Get()
	proc.PID = pid
	if err = proc.GetStatus(); err != nil {
		return
	}
	if err = proc.GetCwd(); err != nil {
		return
	}
	if err = proc.GetCmdline(); err != nil {
		return
	}
	if err = proc.GetExe(); err != nil {
		return
	}
	proc.Sha256, _ = share.GetFileHash(proc.Exe)
	if err = proc.GetStat(); err != nil {
		return
	}
	// 修改本地缓存加速
	proc.Username = share.GetUsername(proc.UID)
	// 修改本地缓存加速
	proc.Eusername = share.GetUsername(proc.EUID)
	// inodes 于 fd 关联, 获取 remote_ip
	// pprof 了一下, 这边占用比较大, 每个进程起来都带上 remote_addr 会导致 IO 高一点
	// 剔除了这部分对于 inodes 的关联, 默认不检测 socket 了
	return proc, nil
}

// realjob for processes
func GetProcessJob() error {
	processes, err := GetProcess()
	if err != nil {
		zap.S().Error("getprocess, err:", err)
		return err
	}
	for _, process := range processes {
		share.ProcessCache.Add(uint32(process.PID), uint32(process.PPID))
		share.ProcessCmdlineCache.Add(uint32(process.PID), process.Exe)
	}
	data, _ := json.Marshal(processes)
	rec := &plugin.Record{
		DataType:  1001,
		Timestamp: time.Now().Unix(),
		Data: &plugin.Payload{
			Fields: map[string]string{"data": string(data)},
		},
	}
	// TODO: proper implement?
	for _, process := range processes {
		cache.DefaultProcessPool.Put(process)
	}
	share.Client.SendRecord(rec)
	return nil
}

func ProcessUpdateJob(ctx context.Context) {
	rand.Seed(time.Now().UnixNano())
	time.Sleep(time.Second * time.Duration(rand.Intn(600)))
	GetProcessJob()
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			GetProcessJob()
		case <-ctx.Done():
			return
		}
	}
}
