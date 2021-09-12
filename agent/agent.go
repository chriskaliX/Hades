package main

import (
	"agent/collector"
	"agent/transport/domain"
	"time"
)

func main() {
	go domain.ServerRun()
	time.Sleep(1 * time.Second)
	collector.Run()
}
