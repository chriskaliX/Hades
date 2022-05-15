package userspace

import (
	"hades-ebpf/userspace/event"
	"net/http"
	_ "net/http/pprof"

	"go.uber.org/zap"
)

// eBPF main function
func Hades() (err error) {
	if err = DefaultDriver.Init(); err != nil {
		zap.S().Error(err)
		return
	}
	if err = DefaultDriver.Start(); err != nil {
		zap.S().Error(err)
		return
	}
	if err = DefaultDriver.AfterRunInitialization(); err != nil {
		zap.S().Error(err)
		return
	}
	// TEST CODE
	if err = event.DefaultAntiRootkit.Scan(DefaultDriver.Manager); err != nil {
		zap.S().Error(err)
		return
	}
	// DefaultDriver.Manager.Stop(manager.CleanAll)
	// TODO: it's just debug code here, rebuild almost done
	http.ListenAndServe("0.0.0.0:6060", nil)
	return
}
