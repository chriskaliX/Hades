package userspace

import (
	"fmt"
)

// ebpf 主程序, 真正的 runner
func Hades() error {
	if err := DefaultDriver.Init(); err != nil {
		fmt.Println(err.Error())
	}
	if err := DefaultDriver.Manager.Start(); err != nil {
		fmt.Println(err.Error())
	}

	// DefaultDriver.Manager.Stop(manager.CleanAll)
	// TODO: it's just debug code here, rebuild almost done
	// http.ListenAndServe("0.0.0.0:6060", nil)
	return nil
}
