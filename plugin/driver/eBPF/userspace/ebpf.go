package userspace

import (
	"fmt"
	"os"
	"time"
)

// ebpf 主程序, 真正的 runner
func Hades() error {
	if err := DefaultDriver.Init(); err != nil {
		os.Stderr.WriteString(err.Error() + "\n")
	}
	if err := DefaultDriver.Manager.Start(); err != nil {
		os.Stderr.WriteString(err.Error() + "\n")
	}
	// TODO: it's just debug code here, rebuild almost done
	fmt.Println("started")
	time.Sleep(60 * time.Second)
	fmt.Println("done")
	return nil
}
