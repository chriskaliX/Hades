package decoder

import (
	"fmt"

	"github.com/bytedance/sonic"
	"github.com/cilium/ebpf"
	manager "github.com/ehids/ebpfmanager"
	"k8s.io/utils/strings/slices"
)

type Event interface {
	// ID returns the unique id for event
	ID() uint32
	// GetExe returns the exe from the event, if it is not collected
	// return a empty string
	GetExe() string
	// SetContext inject the context into the event(BasicEvent)
	SetContext(*Context)
	// Context return the context pointer
	Context() *Context
	// DecodeEvent decodes buffer into event struct
	DecodeEvent(*EbpfDecoder) error
	// Name returns the name of the event
	Name() string
	// GetProbes returns the bpf probe used in the event
	GetProbes() []*manager.Probe
	// GetMaps returns the bpf map used in the event
	GetMaps() []*manager.Map
	// FillCache caches some field, it runs after parse
	FillCache()
	// RegistCron registes the crontab functions into the driver
	// and the driver manages those jobs
	RegistCron() (string, EventCronFunc)
}

type EventCronFunc func(m *manager.Manager) error

var Events = map[uint32]Event{}

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

func MarshalJson(event Event) (result string, err error) {
	var (
		eventByte  []byte
		ctxByte    []byte
		resultByte []byte
	)
	if eventByte, err = sonic.Marshal(event); err != nil {
		return
	}
	if ctxByte, err = event.Context().MarshalJson(); err != nil {
		return
	}
	resultByte = append(resultByte, ctxByte[:len(ctxByte)-2]...)
	resultByte = append(resultByte, byte('"'), byte(','))
	resultByte = append(resultByte, eventByte[1:]...)
	result = string(resultByte)
	return
}

func GetMap(m *manager.Manager, name string) (*ebpf.Map, error) {
	analyzeCache, found, err := m.GetMap(name)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("%s not found", name)
	}
	return analyzeCache, nil
}
