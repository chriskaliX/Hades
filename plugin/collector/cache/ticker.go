package cache

import (
	"sync/atomic"
	"time"
)

var GTicker = &TickerClock{}

type TickerClock struct {
	cachetime atomic.Value
}

func (t *TickerClock) Now() time.Time {
	return t.cachetime.Load().(time.Time)
}

func init() {
	GTicker.cachetime.Store(time.Now())
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for range ticker.C {
			GTicker.cachetime.Store(time.Now())
		}
	}()
}
