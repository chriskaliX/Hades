package share

import (
	"context"
	"sync/atomic"
	"time"

	plugin "github.com/chriskaliX/SDK/transport"
	"go.uber.org/zap"
)

var (
	GContext, GCancel = context.WithCancel(context.Background())
	Client            = plugin.New(GCancel)
	// global time
	Gtime atomic.Value
	// task channel, for convenience, we receive the filter configuration
	// by the task passed by the agent, we only do the update action since
	// a change of filter is not happening every time
	TaskChan = make(chan *plugin.Task)
)

var (
	EventFilter string
	Env         string
)

func gtimeCron() {
	Gtime.Store(time.Now().Unix())
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			Gtime.Store(time.Now().Unix())
		}
	}
}

func taskCron() {
	if Env == "debug" {
		return
	}
	for {
		task, err := Client.ReceiveTask()
		if err != nil {
			zap.S().Error(err)
			time.Sleep(10 * time.Second)
			continue
		}
		TaskChan <- task
	}
}

func init() {
	// init global ticker
	go gtimeCron()
	// start the task receiving project, unfinished
	go taskCron()
}
