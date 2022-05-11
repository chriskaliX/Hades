package decoder

import (
	manager "github.com/ehids/ebpfmanager"
)

type Event interface {
	ID() uint32
	Parse() error
	String() string
	GetExe() string
	GetProbe() []*manager.Probe
	GetMaps() []*manager.Map
}

// use eventId as a key
var eventMap map[uint32]Event = make(map[uint32]Event)

func Regist(event Event) {
	// TEST
	if event.ID() != 1031 {
		return
	}
	eventMap[event.ID()] = event
}

func GetEvent(id uint32) Event {
	return eventMap[id]
}

func GetEvents() map[uint32]Event {
	return eventMap
}
