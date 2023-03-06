package configs

import (
	"collector/eventmanager"
)

var Events = make(map[eventmanager.IEvent]struct{})

func addEvent(e eventmanager.IEvent) {
	Events[e] = struct{}{}
}
