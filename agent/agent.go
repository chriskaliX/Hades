package main

import (
	"time"

	"github.com/chriskaliX/HIDS-Linux/agent/collector"
	"github.com/chriskaliX/HIDS-Linux/agent/global"
)

func main() {
	time.Sleep(1 * time.Second)
	collector.Run()

	buf := make([]map[string]string, 0, 100)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case rd := <-global.UploadChannel:
			buf = append(buf, rd)
		case <-ticker.C:
			if len(buf) != 0 {
				err := client.Send(buf)
				buf = buf[:0]
				if err != nil {
					return
				}
			}
		}
	}
}
