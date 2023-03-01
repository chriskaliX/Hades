package utils

import (
	"github.com/shirou/gopsutil/host"
)

var KernelVersion string

func init() {
	KernelVersion, _ = host.KernelVersion()
}
