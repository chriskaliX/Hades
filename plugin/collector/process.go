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
			return &procfs.Proc{}
		},
	}
	statPool = &sync.Pool{
		New: func() interface{} {
			return &procfs.ProcStat{}
		},
	}
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

/*
	2021-11-26 更新
	本来想提一个 issue 或者自己 patch 一下 AllProcs, 感觉太麻烦了先这么写
*/
func GetProcess() (procs []model.Process, err error) {
	var (
		sys  procfs.Stat
		pids []int
	)

	pids, err = GetPids(MaxProcess)
	if err != nil {
		return
	}

	for _, pid := range pids {
		p, err := procfs.NewProc(pid)
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
func GetProcessInfo(pid uint32) (proc *model.Process, err error) {
	// proc 对象池
	process := processPool.Get().(*procfs.Proc)
	defer processPool.Put(process)

	if *process, err = procfs.NewProc(int(pid)); err != nil {
		return proc, errors.New("no process found")
	}

	// 对象池获取
	proc = model.DefaultProcessPool.Get()

	proc.PID = process.PID
	proc.GetStatus()

	// 改成对象池
	stat := statPool.Get().(*procfs.ProcStat)
	defer statPool.Put(stat)

	if *stat, err = process.Stat(); err == nil {
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
