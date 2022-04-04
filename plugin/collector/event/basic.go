package event

import "sync"

const (
	Snapshot = iota
	Differential
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
	// The cache in here.
	// The key should be unique. It's just like the primary
	// key we used in SQL.
	_cache *sync.Map
	// A filter is here. Key
	_filter sync.Map
}

func (b BasicEvent) Init(name string) {
	_cache, _ := _cacheMap.LoadOrStore(name, &sync.Map{})
	b._cache = _cache.(*sync.Map)
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

// Check if the key in here, check in different
func (b *BasicEvent) Diff(key string) (loaded bool) {
	_, loaded = b._cache.LoadOrStore(key, true)
	return !loaded
}

// TODO: finish this.
func (b *BasicEvent) Filter() (flag bool) {
	return
}
