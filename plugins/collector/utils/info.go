package utils

import (
	"github.com/shirou/gopsutil/host"
)

var Platform string
var KernelVersion string

func init() {
	Platform, _, _, _ = host.PlatformInformation()
	KernelVersion, _ = host.KernelVersion()
}
