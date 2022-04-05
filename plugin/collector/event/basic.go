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
var _cacheMap = sync.Map{}

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

	// // event type. It's periodicity or realtime. As default
	// // it's periodicity
	// _type int
	// // the speed of the realtime event, it's 100 as default
	// speed uint
	// // cache size for the realtime event channel
	// chansize uint
	// // channel for realtime event
	// _chan chan string

	// The cache in here.
	// The key should be unique. It's just like the primary
	// key we used in SQL.
	_cache *sync.Map
	// A filter is here. Key
	_filter *sync.Map
}

func (b *BasicEvent) Init(name string) {
	_cache, _ := _cacheMap.LoadOrStore(name, &sync.Map{})
	b._cache = _cache.(*sync.Map)
	b.SetStatus(true)
	b.mode = Differential
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

// func (b BasicEvent) Type() int {
// 	return b._type
// }

// func (b *BasicEvent) SetType(_type int) {
// 	b._type = _type
// }

// func (b *BasicEvent) SetChan(size uint) {
// 	b._chan = make(chan string, size)
// }

// func (b BasicEvent) Speed() uint {
// 	return b.speed
// }

// func (b *BasicEvent) SetSpeed(speed uint) {
// 	b.speed = speed
// }

// func (b *BasicEvent) ReadChan() string {
// 	return <-b._chan
// }

// Check if the key in here, check in different
func (b *BasicEvent) Diff(key string) (loaded bool) {
	_, loaded = b._cache.LoadOrStore(key, true)
	return loaded
}

// TODO: finish this.
func (b *BasicEvent) Filter() (flag bool) {
	return
}

func (b BasicEvent) Run() (result map[string]string, err error) {
	err = errors.New("nothing")
	return
}

func (b BasicEvent) RunSync(ctx context.Context) (err error) {
	err = errors.New("nothing")
	return
}
