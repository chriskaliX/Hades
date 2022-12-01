package event

import (
	"collector/share"
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/bytedance/sonic"
	"github.com/chriskaliX/SDK/transport/protocol"
	"go.uber.org/zap"
)

// now it's only one event every time
var eventMap = sync.Map{}

func RegistEvent(event Event) {
	eventMap.LoadOrStore(event.String(), event)
}

func GetEvent(name string) (Event, bool) {
	var event Event
	_event, ok := eventMap.Load(name)
	if ok {
		event = _event.(Event)
	}
	return event, ok
}

type Event interface {
	// init for event
	Init(string) error
	// Name for the event
	String() string
	// Get the status
	Status() bool
	SetStatus(bool)
	// Get interval of event, seconds
	Interval() int
	SetInterval(int)
	// Get the mode
	Mode() int
	SetMode(int)
	// Get the data_type field
	DataType() int
	// Run the task and get the result
	// Key is the unique key as we used
	// in Differential mode.
	Run() (map[string]interface{}, error)
	// RunSync for cn-proc/sshd/cron
	// Now it's just a demo
	RunSync(context.Context) error
	// Filter, do the event filter with
	// Field/Value type. I found it's
	// more like osquery right now...
	Filter() bool
	// Check in diff here. Use this when we
	// use Differential mode here
	Diff(string) bool
	// Type of event
	Type() int
	SetType(int)
}

func RunEvent(event Event, immediately bool, ctx context.Context) {
	// init the event
	defer zap.S().Info(fmt.Sprintf("goroutine %s is exiting", event.String()))
	event.Init(event.String())
	zap.S().Info(fmt.Sprintf("goroutine %s is running", event.String()))
	switch event.Type() {
	case Periodicity:
		// set random time for the very first time.
		if immediately {
			eventTask(event)
		}
		ticker := time.NewTicker(time.Second * time.Duration(event.Interval()))
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				event.SetStatus(false)
				return
			case <-ticker.C:
				eventTask(event)
			}
		}
	case Realtime:
		event.RunSync(ctx)
	}
}

// run the real task
func eventTask(event Event) (err error) {
	var rawdata string
	var _data map[string]interface{}
	// run the event
	if _data, err = event.Run(); err != nil {
		zap.S().Error(event.String() + " " + err.Error())
		return err
	}
	data := make(map[string]string, 1)
	datalist := make([]interface{}, 0, 20)

	if !event.Status() {
		return nil
	}
	// switch by mode
	switch event.Mode() {
	case Snapshot:
		for _, value := range _data {
			datalist = append(datalist, value)
		}
	case Differential:
		for key, value := range _data {
			if event.Diff(key) {
				continue
			}
			datalist = append(datalist, value)
		}
	}
	rawdata, err = sonic.MarshalString(datalist)
	if err != nil {
		return err
	}
	data["data"] = rawdata
	rec := &protocol.Record{
		DataType: int32(event.DataType()),
		Data: &protocol.Payload{
			Fields: data,
		},
	}
	return share.Sandbox.SendRecord(rec)
}
