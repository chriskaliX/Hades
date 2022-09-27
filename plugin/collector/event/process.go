package event

import (
	"collector/cache"
	"strconv"
	"time"

	"go.uber.org/zap"
)

// modify this according to Elkeid
const (
	maxProcess             = 1500
	ProcessIntervalMillSec = 100
	PROCESS_DATATYPE       = 1001
)

var _ Event = (*Process)(nil)

type Process struct {
	BasicEvent
}

func (Process) DataType() int {
	return PROCESS_DATATYPE
}

func (Process) String() string {
	return "process"
}

// TODO: Log process
func (p Process) Run() (result map[string]interface{}, err error) {
	result = make(map[string]interface{})
	var processes []*cache.Process
	processes, err = p.getProcess()
	if err != nil {
		zap.S().Error("getprocess, err:", err)
		return
	}
	for _, process := range processes {
		cache.ProcessCache.Add(uint32(process.PID), uint32(process.PPID))
		cache.ProcessCmdlineCache.Add(uint32(process.PID), process.Exe)
	}
	for _, process := range processes {
		result[strconv.Itoa(process.PID)] = process
		if err != nil {
			continue
		}
	}
	return
}

func (Process) getProcess() (procs []*cache.Process, err error) {
	var pids []int
	pids, err = cache.GetPids(maxProcess)
	if err != nil {
		return
	}
	for _, pid := range pids {
		proc, err := cache.GetProcessInfo(pid, false)
		if err != nil {
			continue
		}
		procs = append(procs, proc)
		time.Sleep(time.Duration(ProcessIntervalMillSec) * time.Millisecond)
	}
	return
}

func init() {
	RegistEvent(&Process{})
}
