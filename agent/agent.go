package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"agent/collector"
	"agent/global"
	"agent/log"
	"agent/report"
	"agent/transport"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	_ "net/http/pprof"

	lumberjack "gopkg.in/natefinch/lumberjack.v2"
)

// 默认 agent 仅仅保留和server段通信功能, 通信失败就不开启
func main() {
	defer func() {
		if err := recover(); err != nil {
			panic(err)
		}
	}()

	config := zap.NewProductionEncoderConfig()
	config.CallerKey = "source"
	config.TimeKey = "timestamp"
	config.EncodeTime = func(t time.Time, z zapcore.PrimitiveArrayEncoder) {
		z.AppendString(strconv.FormatInt(t.Unix(), 10))
	}
	grpcEncoder := zapcore.NewJSONEncoder(config)
	grpcWriter := zapcore.AddSync(&log.LoggerWriter{})
	fileEncoder := zapcore.NewConsoleEncoder(zap.NewDevelopmentEncoderConfig())
	fileWriter := zapcore.AddSync(&lumberjack.Logger{
		Filename:   "log/hades.log",
		MaxSize:    1, // megabytes
		MaxBackups: 10,
		MaxAge:     10,   //days
		Compress:   true, // disabled by default
	})
	core := zapcore.NewTee(zapcore.NewCore(grpcEncoder, grpcWriter, zap.ErrorLevel), zapcore.NewCore(fileEncoder, fileWriter, zap.InfoLevel))
	logger := zap.New(core, zap.AddCaller())
	defer logger.Sync()
	undo := zap.ReplaceGlobals(logger)
	defer undo()

	// 默认collector也不开, 接收server指令后再开
	// go collector.EbpfGather()
	go collector.Run()
	go transport.Run()
	go report.Run()

	ticker := time.NewTicker(time.Millisecond)

	sshd, _ := collector.GetSshdConfig()
	fmt.Println(sshd)

	defer ticker.Stop()
	go func() {
		for {
			select {
			case <-ticker.C:
				rd := <-global.UploadChannel
				rd["AgentID"] = global.AgentID
				rd["Hostname"] = global.Hostname
				// 目前还在测试, 专门打印
				if rd["data_type"] == "1000" {
					if strings.Contains(rd["data"], ".vscode") {
						continue
					}
					if strings.Contains(rd["data"], "ssh") {
						fmt.Println(rd["data"])
					}
					// fmt.Println(rd["data"])
				}

				if rd["data_type"] != "2001" {
					continue
				}
				_, err := json.Marshal(rd)
				if err != nil {
					continue
				}
				fmt.Println(rd)
				// network.KafkaSingleton.Send(string(m))
			}
		}
	}()

	http.ListenAndServe("0.0.0.0:6060", nil)
	// 指令回传在这里
}
