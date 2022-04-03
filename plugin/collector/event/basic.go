package event

const (
	Snapshot = iota
	Differential
)

// BasicEvent for events
type BasicEvent struct {
	status bool
	// Field interval is for the event that
	// run periodicity, like cron.
	interval int
	// The mode of the event, snapshot or diff
	// Differential logs or Snapshot, just like osquery
	mode int
}

func (b BasicEvent) Status() bool {
	return b.status
}

func (b *BasicEvent) SetStatus(status bool) {
	b.status = status
}

func (b BasicEvent) Interval() int {
	return b.interval
}

func (b *BasicEvent) SetInterval(interval int) {
	b.interval = interval
}

func (b BasicEvent) Mode() int {
	return b.mode
}

func (b *BasicEvent) SetMode(mode int) {
	b.mode = mode
}
