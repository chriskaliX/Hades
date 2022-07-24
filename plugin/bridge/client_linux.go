package plugin

import (
	"bufio"
	"context"
	"os"
	"sync"
	"time"
)

func New(cancel context.CancelFunc) (c *Client) {
	c = &Client{
		rx: os.Stdin,
		tx: os.Stdout,
		// MAX_SIZE = 1 MB
		reader: bufio.NewReaderSize(os.NewFile(3, "pipe"), 1024*1024),
		writer: bufio.NewWriterSize(os.NewFile(4, "pipe"), 512*1024),
		rmu:    &sync.Mutex{},
		wmu:    &sync.Mutex{},
	}
	// this should be modified, a quit action is supposed to be notified
	// through channel between goroutines
	go func() {
		ticker := time.NewTicker(time.Millisecond * 200)
		defer ticker.Stop()
		for {
			<-ticker.C
			// write failed, more like agent is exited
			if err := c.Flush(); err != nil {
				cancel()
				break
			}
		}
	}()
	return
}
