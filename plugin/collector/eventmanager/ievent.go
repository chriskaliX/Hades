package eventmanager

import (
	"errors"
	"time"

	"github.com/chriskaliX/SDK"
	"github.com/robfig/cron/v3"
	"go.uber.org/zap"
)

const (
	Snapshot = iota
	Differential
	None
)

const (
	Realtime = iota // Real time events like inotify or netlink
	Periodic
)

const (
	Stop  = 0
	Start = 1
)

type Mode int

type Event struct {
	event    IEvent
	interval time.Duration
	mode     int
	done     chan struct{}
	sig      chan struct{}
	id       cron.EntryID
}

func (e *Event) Start(s SDK.ISandbox) (err error) {
	// skip Stop status
	if e.interval == Stop {
		e.done <- struct{}{}
		return
	}
	select {
	case <-s.Context().Done():
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
	zap.S().Info(e.event.Name() + " calls stop")
	switch e.interval {
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
				return errors.New("stop timeout")
			}
		}
	default:
		c.Remove(e.id)
	}
Success:
	zap.S().Info(e.event.Name() + "is stop")
	e.interval = Stop
	return nil
}

type IEvent interface {
	Name() string
	DataType() int
	Run(SDK.ISandbox, chan struct{}) error
	Flag() int // return Realtime or Periodic
}
