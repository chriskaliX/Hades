package event

import (
	"collector/event/systems"
	"collector/eventmanager"
)

func RegistSystem(em *eventmanager.EventManager) {
	for event, d := range systems.Events {
		em.AddEvent(event, d)
	}
}
