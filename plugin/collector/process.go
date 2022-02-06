package main

import (
	"collector/model"
	"collector/share"
	"context"
	"errors"
	"sync"
	"time"

	"os"
	"strconv"
	"strings"

	"github.com/prometheus/procfs"
)

// modify this according to Elkeid
const (
	MaxProcess             = 1500
	ProcessIntervalMillSec = 100
)

var (
	processPool = &sync.Pool{
		New: func() interface{} {
			return procfs.Proc{}
		},
	}
	statPool = &sync.Pool{
		New: func() interface{} {
			return procfs.ProcStat{}
		},
	}
)

/*
	2021-11-26 更新
	本来想提一个 issue 或者自己 patch 一下 AllProcs, 感觉太麻烦了先这么写
*/
func GetProcess() (procs []model.Process, err error) {
	var (
		sys   procfs.Stat
		count int
	)

	d, err := os.Open("/proc")
	if err != nil {
		return procs, err
	}
	defer d.Close()
	// 这里数字上可能会有一些对不上
	// 因为 /proc 下可能包含别的文件夹, 如 sys tty 等, 所以我们加大一些, 然后计数
	names, err := d.Readdirnames(MaxProcess + 20)
	if err != nil {
		return
	}

	if sys, err = procfs.NewStat(); err != nil {
		return
	}

	for _, name := range names {
		if count > MaxProcess {
			return
		}
		count++
		pid, err := strconv.ParseInt(name, 10, 64)
		if err != nil {
			continue
		}
		p, err := procfs.NewProc(int(pid))
		if err != nil {
			continue
		}
		proc := model.Process{PID: p.PID}
		if proc.Exe, err = p.Executable(); err != nil {
			continue
		}
		if _, err = os.Stat(proc.Exe); err != nil {
			continue
		}
		if status, err := p.NewStatus(); err == nil {
			proc.UID = status.UIDs[0]
			proc.EUID = status.UIDs[1]
			proc.Name = status.Name
		} else {
			continue
		}

		if state, err := p.Stat(); err == nil {
			proc.PPID = state.PPID
			proc.Session = state.Session
			proc.TTY = state.TTY
			proc.StartTime = sys.BootTime + state.Starttime/100
		} else {
			continue
		}
		if proc.Cwd, err = p.Cwd(); err != nil {
			continue
		}
		if cmdline, err := p.CmdLine(); err != nil {
			continue
		} else {
			if len(cmdline) > 32 {
				cmdline = cmdline[:32]
			}
			proc.Cmdline = strings.Join(cmdline, " ")
			if len(proc.Cmdline) > 64 {
				proc.Cmdline = proc.Cmdline[:64]
			}
		}
		proc.Sha256, _ = share.GetFileHash("/proc/" + strconv.Itoa(proc.PID) + "/exe")
		proc.Username = share.GetUsername(proc.UID)
		proc.Eusername = share.GetUsername(proc.EUID)
		procs = append(procs, proc)
		time.Sleep(time.Duration(ProcessIntervalMillSec) * time.Millisecond)
	}
	return
}

// 获取单个 process 信息
// 改造一下, 用于补足单个进程的完整信息
// 这里其实会有一个问题, 频繁创建了, 需要用对象池
// 2021-11-06, 开始对这里进行优化
// 函数应该对已有值跳过 TODO 优化
func GetProcessInfo(pid uint32) (proc model.Process, err error) {
	// proc 对象池
	process := processPool.Get().(procfs.Proc)
	defer processPool.Put(process)

	if process, err = procfs.NewProc(int(pid)); err != nil {
		return proc, errors.New("no process found")
	}

	// 对象池获取
	proc = model.ProcessPool.Get().(model.Process)

	proc.PID = process.PID
	proc.NameUidEuid()

	// 改成对象池
	stat := statPool.Get().(procfs.ProcStat)
	defer statPool.Put(stat)

	if stat, err = process.Stat(); err == nil {
		proc.PPID = stat.PPID
		proc.Session = stat.Session
		proc.TTY = stat.TTY
		proc.StartTime = uint64(share.Time)
	}

	proc.Cwd, _ = process.Cwd()
	if cmdline, err := process.CmdLine(); err == nil {
		if len(cmdline) > 32 {
			cmdline = cmdline[:32]
		}
		proc.Cmdline = strings.Join(cmdline, " ")
		if len(proc.Cmdline) > 64 {
			proc.Cmdline = proc.Cmdline[:64]
		}
	}

	if proc.Exe, err = process.Executable(); err == nil {
		if _, err = os.Stat(proc.Exe); err == nil {
			proc.Sha256, _ = share.GetFileHash(proc.Exe)
		}
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

func ProcessUpdateJob(ctx context.Context) {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			Singleton.FlushProcessCache()
		case <-ctx.Done():
			return
		}
	}
}
