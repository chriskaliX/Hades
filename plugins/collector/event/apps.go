package event

import (
	"collector/cache/container"
	"collector/cache/process"
	"collector/event/apps"
	"collector/eventmanager"
	"collector/utils"
	"strconv"
	"sync"
	"time"

	"github.com/chriskaliX/SDK"
	"github.com/chriskaliX/SDK/transport/protocol"
	"go.uber.org/zap"
	"golang.org/x/exp/maps"

	// force including the applications
	_ "collector/event/apps/bigdata"
	_ "collector/event/apps/container"
	_ "collector/event/apps/database"
	_ "collector/event/apps/service"
	_ "collector/event/apps/software"
	_ "collector/event/apps/web"
)

const appsMaxProcess = 3000

type Application struct {
	Apps []apps.IApplication
	once sync.Once
}

func (Application) DataType() int { return 3008 }

func (Application) Flag() eventmanager.EventMode { return eventmanager.Periodic }

func (Application) Name() string { return "application" }

func (Application) Immediately() bool { return false }

// Run over the application recognition plugins
func (a *Application) Run(s SDK.ISandbox, sig chan struct{}) (err error) {
	hash := utils.Hash()
	// inject mapping into application
	a.once.Do(func() { a.Apps = apps.Apps })
	var pids []int
	pids, err = process.GetPids(appsMaxProcess)
	if err != nil {
		return
	}
	for _, pid := range pids {
		proc, err := process.GetProcessInfo(pid, false)
		if err != nil {
			continue
		}
		time.Sleep(2 * ProcessIntervalMillSec * time.Millisecond)
		// Actual run function for applications, the applications package is differed by its name
		for _, v := range a.Apps {
			// Skip if did not match the application
			if matched := v.Match(proc); !matched {
				continue
			}
			// Run with the proc, and get information of what we need
			m, err := v.Run(proc)
			if err != nil {
				zap.S().Errorf("name: %s, datatype: %s, err: %s", v.Name(), v.Type(), err.Error())
				continue
			}
			if m == nil {
				m = make(map[string]string)
			}
			var container_id, container_name string
			if proc.Pns != 0 {
				if containerInfo, ok := container.ContainerInfo(uint32(proc.Pns)); ok {
					container_id = containerInfo[container.ContainerId]
					container_name = containerInfo[container.ContainerName]
				}
			}
			// If success, get the container-related fields, the IApplication will not
			// collect this in it's Run function
			// pay attention to the uts
			maps.Copy(m, map[string]string{
				"name":           v.Name(),
				"type":           v.Type(),
				"pid":            strconv.Itoa(proc.PID),
				"tid":            strconv.Itoa(proc.TID),
				"pgid":           strconv.Itoa(proc.PGID),
				"pns":            strconv.Itoa(proc.Pns),
				"root_pns":       strconv.Itoa(proc.RootPns),
				"exe":            proc.Exe,
				"cwd":            proc.Cwd,
				"version":        v.Version(),
				"cmdline":        proc.Argv,
				"pod_name":       proc.PodName,
				"container_id":   container_id,
				"container_name": container_name,
				"uid":            strconv.Itoa(int(proc.UID)),
				"gid":            strconv.Itoa(int(proc.GID)),
				"username":       proc.Username,
				"start_time":     strconv.FormatUint(proc.StartTime, 10),
				"listen_addrs":   apps.ProcListenAddrs(proc),
			})

			// software, only listen_addr not empty
			if v.Type() == "software" {
				if v, ok := m["listen_addrs"]; !ok || v == "" {
					goto Next
				}
			}

			rec := &protocol.Record{
				DataType:  int32(a.DataType()),
				Timestamp: time.Now().Unix(),
				Data: &protocol.Payload{
					Fields: m,
				},
			}
			rec.Data.Fields["package_seq"] = hash
			s.SendRecord(rec)
			goto Next
		}
	Next:
	}
	return nil
}
