package main

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"agent/collector"
	"agent/global"
	"agent/log"
	"agent/transport"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

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
		Filename:   "log/Hades.log",
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
			// network.KafkaSingleton.Send(string(m))
		}
	}

	// 指令回传在这里
}
