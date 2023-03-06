package networks

import (
	"collector/eventmanager"
	"time"
)

var Events = make(map[eventmanager.IEvent]time.Duration)

func addEvent(e eventmanager.IEvent, d time.Duration) {
	Events[e] = d
}
