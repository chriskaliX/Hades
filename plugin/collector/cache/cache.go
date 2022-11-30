package cache

import (
	"os"
	"strconv"
	"sync/atomic"
	"time"
)

var GTicker = &TickerClock{}
var RootPns = 0

type TickerClock struct {
	cachetime atomic.Value
}

func (t *TickerClock) Now() time.Time {
	return t.cachetime.Load().(time.Time)
}

func init() {
	GTicker.cachetime.Store(time.Now())
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for range ticker.C {
			GTicker.cachetime.Store(time.Now())
		}
	}()

	name, err := os.Readlink("/proc/1/ns/pid")
	if err != nil {
		return
	}
	if len(name) >= 6 {
		RootPns, _ = strconv.Atoi(name[5 : len(name)-1])
	}
}
