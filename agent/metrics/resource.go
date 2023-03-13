package metrics

import (
	"os"
	"path/filepath"
	"time"

	"github.com/shirou/gopsutil/v3/process"
	"k8s.io/utils/lru"
)

var (
	ioCache   = lru.New(128)
	procCache = lru.New(100)
)

type ioState struct {
	Time       time.Time
	ReadBytes  uint64
	WriteBytes uint64
}

func getProcResource(pid int) (cpu float64, rss uint64, readSpeed, writeSpeed float64, fds int32, startAt int64, err error) {
	var p *process.Process
	// sync from Elkeid to fix the cpu error, since cpu need to be count from lasttime
	if iface, ok := procCache.Get(pid); ok {
		p = iface.(*process.Process)
	} else {
		p, err = process.NewProcess(int32(pid))
		if err != nil {
			return
		}
		procCache.Add(pid, p)
	}
	cpu, _ = p.Percent(0)
	cpu = cpu / 100.0
	startAt, _ = p.CreateTime()
	startAt = startAt / 1000
	fds, _ = p.NumFDs()

	if m, err := p.MemoryInfo(); err == nil {
		rss = m.RSS
	}

	if io, err := p.IOCounters(); err == nil {
		now := time.Now()
		var state ioState
		if stateI, ok := ioCache.Get(pid); ok {
			state = stateI.(ioState)
			readSpeed = float64(io.ReadBytes-state.ReadBytes) / now.Sub(state.Time).Seconds()
			writeSpeed = float64(io.WriteBytes-state.WriteBytes) / now.Sub(state.Time).Seconds()
		} else {
			state = ioState{}
			readSpeed = float64(io.ReadBytes-state.ReadBytes) / (float64(now.Unix() - startAt))
			writeSpeed = float64(io.WriteBytes-state.WriteBytes) / (float64(now.Unix() - startAt))
		}
		state.ReadBytes = io.ReadBytes
		state.WriteBytes = io.WriteBytes
		state.Time = now
	}
	return
}

func getDirSize(path string, except string) uint64 {
	var dirSize uint64 = 0
	readSize := func(_ string, file os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !file.IsDir() {
			dirSize += uint64(file.Size())
		} else {
			if file.Name() == except {
				return filepath.SkipDir
			}
		}
		return nil
	}
	filepath.Walk(path, readSize)
	return dirSize
}
