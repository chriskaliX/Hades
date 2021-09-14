package collector

import (
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

	// 默认collector也不开, 接收server指令后再开
	collector.Run()

	go func() {
		buf := make([]map[string]string, 0, 100)
		ticker := time.NewTicker(time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case rd := <-global.UploadChannel:
				buf = append(buf, rd)
			case <-ticker.C:
				// if len(buf) != 0 {
				// 	err := client.Send(buf)
				// 	buf = buf[:0]
				// 	if err != nil {
				// 		return
				// 	}
				// }

				// 这里修改成kafka通道上传
				fmt.Println(buf)
			}
		}
	}()

	// 指令回传在这里
}
