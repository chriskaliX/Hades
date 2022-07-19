package share

import (
	"sync/atomic"
	"time"

	"github.com/chriskaliX/plugin"
)

var (
	Client = plugin.New()
	// global time
	Gtime atomic.Value
)

func init() {
	go func() {
		Gtime.Store(time.Now().Unix())
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				Gtime.Store(time.Now().Unix())
			}
		}
	}()
}
