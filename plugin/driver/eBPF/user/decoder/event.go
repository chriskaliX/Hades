package decoder

import (
	"fmt"

	"github.com/cilium/ebpf"
	manager "github.com/ehids/ebpfmanager"
)

type Event interface {
	ID() uint32
	Parse() error
	String() string
	GetExe() string
	GetProbe() []*manager.Probe
	GetMaps() []*manager.Map
	FillContext(uint32)
}

// use eventId as a key
var eventMap map[uint32]Event = make(map[uint32]Event)

func Regist(event Event) {
	eventMap[event.ID()] = event
}

func GetEvent(id uint32) Event {
	return eventMap[id]
}

func GetEvents() map[uint32]Event {
	return eventMap
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

// Set filter use this.
func SetFilter(i uint64) {
	if i == 0 {
		return
	}
	for k := range eventMap {
		if uint64(k) != i {
			delete(eventMap, k)
		}
	}
}
