package cache

import (
	"sync/atomic"
	"time"
)

// exception values
const (
	InVaild  = "-3"
	Error    = "-4"
	OverRate = "-5"
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
		for {
			select {
			case <-ticker.C:
				GTicker.cachetime.Store(time.Now())
			}
		}
	}()
}
