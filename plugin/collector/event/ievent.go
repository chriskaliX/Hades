package event

import "sync"

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
	Init(string)
	// Name for the event
	String() string
	// Get the status
	Status() bool
	SetStatus(bool)
	// Get interval of event
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
	Run() (map[string]string, error)
	// Filter, do the event filter with
	// Field/Value type. I found it's
	// more like osquery right now...
	Filter() bool
	// Check in diff here. Use this when we
	// use Differential mode here
	Diff(string) bool
}
