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

var cachetime atomic.Value

type TickerClock struct{}

func (t *TickerClock) Now() time.Time {
	return cachetime.Load().(time.Time)
}

func init() {
	cachetime.Store(time.Now())
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				cachetime.Store(time.Now())
			}
		}
	}()
}
