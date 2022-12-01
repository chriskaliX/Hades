package event

import (
	"context"
	"errors"
	"sync"
)

const (
	Snapshot = iota
	Differential
)

const (
	Periodicity = iota
	Realtime
)

// cache for maps
var cacheMap = sync.Map{}

// BasicEvent for events
type BasicEvent struct {
	// the status of the event
	status bool
	// Field interval is for the event that
	// run periodicity, like cron.
	interval int
	// The mode of the event, snapshot or diff
	// Differential logs or Snapshot, just like osquery
	// and it's a default way
	mode int
	// event type. It's periodicity or realtime. As default
	// it's periodicity
	datatype int
	// The cache in here.
	// The key should be unique. It's just like the primary
	// key we used in SQL.
	cache *sync.Map
	// A filter is here. Key
	filter *sync.Map
}

func (b *BasicEvent) Init(name string) error {
	cache, _ := cacheMap.LoadOrStore(name, &sync.Map{})
	b.cache = cache.(*sync.Map)
	b.SetStatus(true)
	return nil
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

func (b BasicEvent) Type() int {
	return b.datatype
}

func (b *BasicEvent) SetType(datatype int) {
	b.datatype = datatype
}

// Check if the key in here, check in different
func (b *BasicEvent) Diff(key string) (loaded bool) {
	_, loaded = b.cache.LoadOrStore(key, true)
	return loaded
}

// TODO: finish this.
func (b *BasicEvent) Filter() (flag bool) {
	return
}

func (b BasicEvent) Run() (result map[string]interface{}, err error) {
	err = errors.New("nothing")
	return
}

func (b BasicEvent) RunSync(c context.Context) (err error) {
	err = errors.New("nothing")
	return
}
