package main

import (
	"flag"
	"time"

	"github.com/chriskaliX/SDK"
	"github.com/chriskaliX/SDK/logger"
	"github.com/chriskaliX/SDK/transport/protocol"
	"go.uber.org/zap/zapcore"
)

func test(sandbox SDK.ISandbox) error {
	go func() {
		for {
			time.Sleep(time.Second)
			sandbox.SendRecord(&protocol.Record{
				DataType:  1,
				Timestamp: time.Now().Unix(),
				Data: &protocol.Payload{
					Fields: map[string]string{
						"windows": "win",
					},
				},
			})
		}
	}()
	return nil
}

func main() {
	var debug bool
	flag.BoolVar(&debug, "debug", false, "set to run in debug mode")
	flag.Parse()
	sconfig := &SDK.SandboxConfig{
		Debug: debug,
		Hash:  true,
		Name:  "test",
		LogConfig: &logger.Config{
			Path:        "test.log",
			MaxSize:     10,
			MaxBackups:  10,
			Compress:    true,
			FileLevel:   zapcore.InfoLevel,
			RemoteLevel: zapcore.ErrorLevel,
		},
	}
	sandbox := SDK.NewSandbox()
	if err := sandbox.Init(sconfig); err != nil {
		return
	}
	sandbox.Run(test)
}
