package collector

import (
	"encoding/json"
	"time"

	"agent/collector"
	"agent/global"
	"agent/network"
)

// 默认 agent 仅仅保留和server段通信功能, 通信失败就不开启
func main() {
	defer func() {
		if err := recover(); err != nil {
			//log here
			panic(err)
		}
	}()

	// 默认collector也不开, 接收server指令后再开
	collector.Run()

	go func() {
		ticker := time.NewTicker(time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				rd := <-global.UploadChannel
				rd["AgentID"] = global.AgentID
				rd["Hostname"] = global.Hostname
				m, err := json.Marshal(rd)
				if err != nil {
					continue
				}
				network.KafkaSingleton.Send(string(m))
			}
		}
	}()

	// 指令回传在这里
}
