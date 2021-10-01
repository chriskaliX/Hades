package main

import (
	"encoding/json"
	"fmt"
	"time"

	"agent/collector"
	"agent/global"
)

// 默认 agent 仅仅保留和server段通信功能, 通信失败就不开启
func main() {
	defer func() {
		if err := recover(); err != nil {
			//log here
			panic(err)
		}
	}()

	collector.EbpfGather()

	// 默认collector也不开, 接收server指令后再开
	collector.Run()

	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			rd := <-global.UploadChannel
			rd["AgentID"] = global.AgentID
			rd["Hostname"] = global.Hostname
			_, err := json.Marshal(rd)
			if err != nil {
				continue
			}
			fmt.Println(rd)
			// fmt.Println(m)
			// network.KafkaSingleton.Send(string(m))
		}
	}

	// 指令回传在这里
}
