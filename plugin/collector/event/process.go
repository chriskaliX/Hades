package event

import (
	"collector/cache/process"
	"collector/eventmanager"
	"time"

	"github.com/bytedance/sonic"
	"github.com/chriskaliX/SDK"
	"github.com/chriskaliX/SDK/transport/protocol"
	"go.uber.org/zap"
)

// modify this according to Elkeid
const (
	maxProcess             = 1500
	ProcessIntervalMillSec = 40
	PROCESS_DATATYPE       = 1001
)

var _ eventmanager.IEvent = (*Process)(nil)

type Process struct{}

func (Process) DataType() int {
	return PROCESS_DATATYPE
}

func (Process) Name() string {
	return "process"
}

func (n *Process) Flag() int {
	return eventmanager.Periodic
}

func (p Process) Run(s SDK.ISandbox, sig chan struct{}) error {
	processes, err := p.getProcess()
	if err != nil {
		zap.S().Error("getprocess, err:", err)
		return err
	}
	data, err := sonic.MarshalString(processes)
	if err != nil {
		return err
	}
	rec := &protocol.Record{
		DataType:  1001,
		Timestamp: time.Now().Unix(),
		Data: &protocol.Payload{
			Fields: map[string]string{
				"data": data,
			},
		},
	}
	s.SendRecord(rec)
	return nil
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
