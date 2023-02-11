// Applications collection which is cloud compatible, container specificated
package apps

import (
	"collector/cache/process"
	"collector/eventmanager"
	"strconv"
	"time"

	"github.com/chriskaliX/SDK"
	"github.com/chriskaliX/SDK/transport/protocol"
	"go.uber.org/zap"
)

const maxProcess = 3000

// Just for temporary
type IApplication interface {
	Name() string
	Run(*process.Process) (str string, err error)
	Match(*process.Process) (bool, error) // Whether the process matches
}

var DefaultApplication = &Application{
	Apps: make(map[string]IApplication),
}

type Application struct {
	Apps map[string]IApplication
}

func (Application) DataType() int { return 1002 }

func (Application) Flag() int { return eventmanager.Periodic }

func (Application) Name() string { return "application" }

// Run over the application recognition plugins
func (a *Application) Run(s SDK.ISandbox, sig chan struct{}) (err error) {
	// TODO: Inject the process list into apps to preventing go over the processes list everytime
	var pids []int
	pids, err = process.GetPids(maxProcess)
	if err != nil {
		return
	}
	for _, pid := range pids {
		proc, err := process.GetProcessInfo(pid, true)
		if err != nil {
			continue
		}

		// Actual run function for applications, the applications package is differed by its name
		for k, v := range a.Apps {
			// Skip if did not match the application
			if matched, err := v.Match(proc); err != nil || !matched {
				continue
			}
			// Run with the proc, and get information of what we need
			if data, err := v.Run(proc); err == nil {
				// If success, get the container-related fields, the IApplication will not
				// collect this in it's Run function
				// Send record
				s.SendRecord(&protocol.Record{
					DataType:  int32(a.DataType()),
					Timestamp: time.Now().Unix(),
					Data: &protocol.Payload{
						Fields: map[string]string{
							"data":           data,
							"type":           v.Name(),
							"pid":            strconv.Itoa(proc.PID),
							"cmdline":        proc.Argv,
							"pod_name":       proc.PodName,
							"container_id":   "",
							"container_name": "",
							"psm":            "",
						},
					},
				})
				zap.S().Infof("application collect %s is finished", k)
			}
		}
	}
	return nil
}

func registApp(app IApplication) {
	DefaultApplication.Apps[app.Name()] = app
}
