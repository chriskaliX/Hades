//go:build windows

package client

import (
	"bufio"
	"os"
	"sync"
	"time"

	"github.com/chriskaliX/SDK/clock"
)

func New(clock clock.IClock) (c *Client) {
	c = &Client{
		rx: os.Stdin,
		tx: os.Stdout,
		// MAX_SIZE = 1 MB
		reader: bufio.NewReaderSize(os.Stdin, 1024*1024),
		writer: bufio.NewWriterSize(os.Stdout, 512*1024),
		rmu:    &sync.Mutex{},
		wmu:    &sync.Mutex{},
		clock:  clock,
	}
	go func() {
		ticker := time.NewTicker(time.Millisecond * 200)
		defer ticker.Stop()
		for {
			<-ticker.C
			if err := c.Flush(); err != nil {
				break
			}
		}
	}()
	return
}
