package clock

import (
	"sync"
	"time"
)

var _ IClock = (*Clock)(nil)

type IClock interface {
	Now() time.Time
	Reset(time.Duration)
	Sleep(time.Duration)
	Close()
}

type Clock struct {
	t      time.Time
	mu     sync.RWMutex
	ticker *time.Ticker
}

func New(interval time.Duration) *Clock {
	clock := &Clock{
		t:      time.Now(),
		ticker: time.NewTicker(interval),
	}
	go func() {
		for range clock.ticker.C {
			clock.update()
		}
	}()
	return clock
}

// A second interval as default
func NewWithTicker(ticker *time.Ticker) *Clock {
	if ticker == nil {
		ticker = time.NewTicker(1 * time.Second)
	}
	clock := &Clock{
		t:      time.Now(),
		ticker: ticker,
	}
	go func() {
		for range clock.ticker.C {
			clock.update()
		}
	}()
	return clock
}

func (c *Clock) Now() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.t
}

func (c *Clock) Reset(d time.Duration) {
	c.ticker.Reset(d)
}

func (c *Clock) Sleep(d time.Duration) { time.Sleep(d) }

func (c *Clock) Close() {
	if c.ticker == nil {
		return
	}
	c.ticker.Stop()
}

func (c *Clock) update() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = time.Now()
}
