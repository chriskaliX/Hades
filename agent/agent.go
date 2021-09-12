package main

import (
	"time"

	"github.com/chriskaliX/HIDS-Linux/agent/collector"
	"github.com/chriskaliX/HIDS-Linux/agent/transport/domain"
)

func main() {
	go domain.ServerRun()
	time.Sleep(1 * time.Second)
	collector.Run()
}
