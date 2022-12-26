package cache

import (
	"os"
	"strconv"
)

var RootPns = 0

func init() {
	name, err := os.Readlink("/proc/1/ns/pid")
	if err != nil {
		return
	}
	if len(name) >= 6 {
		RootPns, _ = strconv.Atoi(name[5 : len(name)-1])
	}
}
