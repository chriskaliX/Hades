package share

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/chriskaliX/plugin"
)

var (
	GContext, GCancel = context.WithCancel(context.Background())
	Client            = plugin.New(GCancel)
	// global time
	Gtime atomic.Value
)

func init() {
	// init global ticker
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
	// start the task receiving project, unfinished
	go func() {
		Client.ReceiveTask()
	}()
}
