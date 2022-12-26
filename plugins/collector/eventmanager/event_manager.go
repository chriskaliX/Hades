package eventmanager

import (
	"fmt"
	"math/rand"
	"strconv"
	"time"

	"github.com/chriskaliX/SDK"
	"github.com/chriskaliX/SDK/transport/protocol"
	"github.com/robfig/cron/v3"
	"go.uber.org/zap"
)

type EventManager struct {
	s    SDK.ISandbox
	m    map[int]*Event
	cron *cron.Cron
}

func New(s *SDK.Sandbox) *EventManager {
	return &EventManager{
		s: s,
		m: make(map[int]*Event),
		cron: cron.New(
			cron.WithChain(
				cron.SkipIfStillRunning(&logWrapper{
					logger: s.Logger,
				}),
			),
		),
	}
}

func (e *EventManager) AddEvent(event IEvent, t time.Duration, m int) {
	zap.S().Info(fmt.Sprintf("%s is added, %dm, %d", event.Name(), int(t.Minutes()), m))
	e.m[event.DataType()] = &Event{
		event:    event,
		interval: t,
		mode:     m,
		done:     make(chan struct{}, 1),
		sig:      make(chan struct{}, 1),
	}
	e.m[event.DataType()].done <- struct{}{}
}

func (e *EventManager) Run(s SDK.ISandbox) error {
	zap.S().Info("eventmanager running")
	for _, event := range e.m {
		switch event.event.Flag() {
		case Realtime:
			go event.Start(s)
		default:
			go func(ev *Event) {
				r := rand.Intn(600)
				time.Sleep(time.Duration(r) * time.Second)
				zap.S().Infof("%s first run", ev.event.Name())
				ev.Start(s)
				id, _ := e.cron.AddFunc(
					fmt.Sprintf("@every %dm", int(ev.interval.Minutes())),
					func() { ev.Start(s) },
				)
				ev.id = id
			}(event)
		}
	}
	go e.taskResolve()
	e.cron.Run()
	return nil
}

// collector task resolve
// only data_type and (an int interval)
func (e *EventManager) taskResolve() {
	for {
		task := e.s.RecvTask()
		// exit if task is nil, which should not happen
		if task == nil {
			return
		}
		// look up events by data type
		event, ok := e.m[int(task.DataType)]
		if !ok {
			zap.S().Error(fmt.Sprintf("%d is invalid", task.DataType))
			continue
		}
		// All trigger by interval
		interval, err := strconv.Atoi(task.Data)
		if err != nil {
			zap.S().Error(err)
			continue
		}

		var data = &protocol.Record{
			DataType:  5100,
			Timestamp: time.Now().Unix(),
			Data:      &protocol.Payload{},
		}

		if interval > 0 {
			if event.event.Flag() == Realtime {
				go event.Start(e.s)
			} else {
				event.interval = time.Duration(interval) * time.Minute
				e.cron.Remove(event.id)
				id, _ := e.cron.AddFunc(
					fmt.Sprintf("@every %dm", int(event.interval.Minutes())),
					func() { event.Start(e.s) },
				)
				event.id = id
			}
		} else {
			err := event.Stop(e.cron)
			if err == nil {
				data.Data.Fields = map[string]string{
					"status": "successed",
					"msg":    "",
					"token":  task.Token,
				}
			} else {
				zap.S().Error(fmt.Sprintf("%s stop fail", event.event.Name()))
				data.Data.Fields = map[string]string{
					"status": "failed",
					"msg":    "stop failed",
					"token":  task.Token,
				}
			}
		}
		e.s.SendRecord(data)
	}
}
