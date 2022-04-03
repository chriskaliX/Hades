package cache

import "time"

var Time uint

// test now
func init() {
	go func() {
		Time = uint(time.Now().Unix())
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				Time = uint(time.Now().Unix())
			}
		}
	}()
}
