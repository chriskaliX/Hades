package main

import (
	"flag"
	"ncp/event"
	"strconv"
	"time"

	"github.com/chriskaliX/SDK"
	"github.com/chriskaliX/SDK/logger"
	"github.com/chriskaliX/SDK/transport/protocol"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func main() {
	debug := flag.Bool("debug", false, "debug mode")
	flag.Parse()
	sconfig := &SDK.SandboxConfig{
		Debug: *debug,
		Name:  "ncp",
		LogConfig: &logger.Config{
			Path:        "ncp.log",
			MaxSize:     10,
			MaxBackups:  10,
			Compress:    true,
			FileLevel:   zapcore.InfoLevel,
			RemoteLevel: zapcore.ErrorLevel,
		},
	}
	// sandbox init
	sandbox := SDK.NewSandbox()
	if err := sandbox.Init(sconfig); err != nil {
		return
	}
	ncp := event.New()
	// task
	go func() {
		for {
			select {
			case <-sandbox.Context().Done():
			default:
				task := sandbox.RecvTask()
				switch task.DataType {
				case event.Stop:
					ncp.Stop()
				case event.Start:
					go ncp.Start(sandbox)
				}
				time.Sleep(time.Second)
			}
		}
	}()
	// state
	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			succTPS, failTPS := ncp.GetState()
			if failTPS > 2 {
				zap.S().Info(succTPS, failTPS)
			}
			data := make(map[string]string, 2)
			data["success_tps"] = strconv.FormatFloat(succTPS, 'f', 6, 64)
			data["failed_tps"] = strconv.FormatFloat(failTPS, 'f', 6, 64)
			rec := &protocol.Record{
				DataType: 1001,
				Data: &protocol.Payload{
					Fields: data,
				},
			}
			sandbox.SendRecord(rec)
		}
	}()

	sandbox.Run(ncp.Run)
}
