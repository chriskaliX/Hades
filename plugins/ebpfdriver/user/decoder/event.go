package decoder

import (
	"fmt"
	"reflect"

	"github.com/bytedance/sonic"
	manager "github.com/ehids/ebpfmanager"
	"k8s.io/utils/strings/slices"
)

var Events = map[uint32]Event{}

type EventCronFunc func(m *manager.Manager) error

// Event is the interface that all events should implement
type Event interface {
	// ID returns the unique id for event
	ID() uint32
	// Name returns the name of the event
	Name() string
	// GetExe returns the exe from the event, if it is not collected
	// return a empty string
	GetExe() string
	// DecodeEvent decodes buffer into event struct
	DecodeEvent(*EbpfDecoder) error
	// GetProbes returns the bpf probe used in the event
	GetProbes() []*manager.Probe
	// GetMaps returns the bpf map used in the event
	GetMaps() []*manager.Map
	// RegistCron registes the crontab functions into the driver
	// and the driver manages those jobs
	RegistCron() (string, EventCronFunc)
}

// SetAllowList
func SetAllowList(allows []string) {
	// skip if there is no allow list
	if len(allows) == 0 {
		return
	}
	for eventID := range Events {
		if !slices.Contains(allows, fmt.Sprint(eventID)) {
			delete(Events, eventID)
		}
	}
}

func RegistEvent(event Event) {
	Events[event.ID()] = event
}

func MarshalJson(event Event, ctx *Context) (result string, err error) {
	var eventByte, ctxByte, resultByte []byte
	if eventByte, err = sonic.Marshal(event); err != nil {
		return
	}
	if ctx != nil {
		if ctxByte, err = ctx.MarshalJson(); err != nil {
			return
		}
		resultByte = append(resultByte, ctxByte[:len(ctxByte)-2]...)
		resultByte = append(resultByte, byte('"'), byte(','))
		resultByte = append(resultByte, eventByte[1:]...)
	} else {
		resultByte = eventByte
	}
	result = string(resultByte)
	return
}

func init() {
	var ctx Context
	sonic.Pretouch(reflect.TypeOf(ctx))
}
