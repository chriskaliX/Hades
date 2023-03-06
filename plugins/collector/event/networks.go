package event

import (
	"collector/event/networks"
	"collector/eventmanager"
)

func RegistNetwork(em *eventmanager.EventManager) {
	for event, d := range networks.Events {
		em.AddEvent(event, d)
	}
}