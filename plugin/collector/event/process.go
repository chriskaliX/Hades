package event

import (
	"collector/cache/process"
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

func (p Process) Run() (result map[string]interface{}, err error) {
	result = make(map[string]interface{})
	var processes []*process.Process
	processes, err = p.getProcess()
	if err != nil {
		zap.S().Error("getprocess, err:", err)
		return
	}
	for _, process := range processes {
		result[strconv.Itoa(process.PID)] = process
		if err != nil {
			continue
		}
	}
	return
}

func (Process) getProcess() (procs []*process.Process, err error) {
	var pids []int
	pids, err = process.GetPids(maxProcess)
	if err != nil {
		return
	}
	for _, pid := range pids {
		proc, err := process.GetProcessInfo(pid, false)
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
