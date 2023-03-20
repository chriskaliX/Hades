package eventmanager

import (
	"fmt"
	"time"

	"github.com/chriskaliX/SDK"
	"github.com/robfig/cron/v3"
	"go.uber.org/zap"
)

type EventMode int

const (
	Realtime EventMode = iota // Real time events like inotify or netlink
	Periodic
	Trigger
)

var EmptyDuration = 0 * time.Second

type Event struct {
	event    IEvent
	interval time.Duration
	done     chan struct{}
	sig      chan struct{}
	id       cron.EntryID
}

func (e *Event) Start(s SDK.ISandbox) (err error) {
	select {
	case <-s.Done():
		return
	case <-e.done:
		err = e.event.Run(s, e.sig)
		if err != nil {
			return
		}
	default:
		<-e.done
	}
	e.done <- struct{}{}
	return
}

func (e *Event) Stop(c *cron.Cron) error {
	zap.S().Infof("stop %s is called", e.event.Name())
	switch e.event.Flag() {
	case Realtime:
		// send terminate sig to construct
		e.sig <- struct{}{}
		timer := time.NewTimer(5 * time.Second)
		defer timer.Stop()
		for {
			select {
			case <-e.done:
				goto Success
			case <-timer.C:
				return fmt.Errorf("%s stop timeout", e.event.Name())
			}
		}
	default:
		c.Remove(e.id)
	}
Success:
	zap.S().Infof("%s is stop", e.event.Name())
	return nil
}

type IEvent interface {
	Name() string
	DataType() int
	Run(SDK.ISandbox, chan struct{}) error
	Flag() EventMode
	Immediately() bool
}
