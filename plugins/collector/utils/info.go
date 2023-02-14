package utils

import "github.com/shirou/gopsutil/host"

var Platform string

func init() {
	Platform, _, _, _ = host.PlatformInformation()
}
