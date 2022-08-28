package clock

import (
	"testing"
	"time"
)

func TestClose(t *testing.T) {
	clock := New(10 * time.Millisecond)
	for i := 0; i < 5; i++ {
		t.Log(clock.Now())
		time.Sleep(time.Second)
	}
}
