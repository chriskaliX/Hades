package userspace

import (
	"net/http"
	_ "net/http/pprof"

	"go.uber.org/zap"
)

// ebpf 主程序, 真正的 runner
func Hades() error {
	if err := DefaultDriver.Init(); err != nil {
		zap.S().Error(err)
	}
	if err := DefaultDriver.Manager.Start(); err != nil {
		zap.S().Error(err)
	}

	// DefaultDriver.Manager.Stop(manager.CleanAll)
	// TODO: it's just debug code here, rebuild almost done
	http.ListenAndServe("0.0.0.0:6060", nil)
	return nil
}
