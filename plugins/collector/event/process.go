package event

import (
	"collector/cache"
	"collector/cache/process"
	"collector/eventmanager"
	"collector/utils"
	"strconv"
	"time"

	"github.com/chriskaliX/SDK"
	"github.com/chriskaliX/SDK/transport/protocol"
	"go.uber.org/zap"
)

// modify this according to Elkeid
const (
	maxProcess             = 1500
	ProcessIntervalMillSec = 50
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

func (n *Process) Flag() eventmanager.EventMode {
	return eventmanager.Periodic
}

func (Process) Immediately() bool { return false }

func (p Process) Run(s SDK.ISandbox, sig chan struct{}) error {
	processes, err := p.getProcess()
	if err != nil {
		zap.S().Errorf("getprocess failed: %s", err.Error())
		return err
	}
	hash := utils.Hash()
	for _, process := range processes {
		rec := &protocol.Record{
			DataType:  1001,
			Timestamp: time.Now().Unix(),
			Data: &protocol.Payload{
				Fields: map[string]string{
					"pns":         strconv.FormatInt(int64(process.Pns), 10),
					"root_pns":    strconv.FormatInt(int64(cache.RootPns), 10),
					"pid":         strconv.FormatInt(int64(process.PID), 10),
					"gid":         strconv.FormatInt(int64(process.GID), 10),
					"pgid":        strconv.FormatInt(int64(process.PGID), 10),
					"pgid_argv":   process.PgidArgv,
					"tid":         strconv.FormatInt(int64(process.TID), 10),
					"session_id":  strconv.FormatInt(int64(process.Session), 10),
					"ppid":        strconv.FormatInt(int64(process.PPID), 10),
					"ppid_argv":   process.PpidArgv,
					"name":        process.Name,
					"argv":        process.Argv,
					"exe":         process.Exe,
					"exe_hash":    process.Hash,
					"uid":         strconv.FormatInt(int64(process.UID), 10),
					"username":    process.Username,
					"cwd":         process.Cwd,
					"stdin":       process.Stdin,
					"stdout":      process.Stdout,
					"pid_tree":    process.PidTree,
					"pod_name":    process.PodName,
					"nodename":    process.NodeName,
					"tty":         strconv.FormatInt(int64(process.TTY), 10),
					"ttyname":     process.TTYName,
					"start_time":  strconv.FormatUint(process.StartTime, 10),
					"remote_addr": process.RemoteAddr,
					"remote_port": process.RemotePort,
					"local_addr":  process.LocalAddr,
					"local_port":  process.LocalPort,
					"utime":       strconv.FormatUint(process.Utime, 10),
					"stime":       strconv.FormatUint(process.Stime, 10),
					"rss":         strconv.FormatUint(process.Rss, 10),
					"vsize":       strconv.FormatUint(process.Vsize, 10),
					"cpu":         strconv.FormatFloat(process.Cpu, 'f', 6, 64),
					"package_seq": hash,
				},
			},
		}
		s.SendRecord(rec)
		time.Sleep(20 * time.Millisecond)
	}
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
