package main

import (
	"collector/event"
	"context"
	"time"

	// "collector/socket"

	"runtime"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	lumberjack "gopkg.in/natefinch/lumberjack.v2"
)

func init() {
	runtime.GOMAXPROCS(4)
}

// 这里采集的数据, 统一不带上主机基础信息
// 统一上传结构体然后Marshal上传
func main() {
	// logs
	fileEncoder := zapcore.NewConsoleEncoder(zap.NewDevelopmentEncoderConfig())
	fileWriter := zapcore.AddSync(&lumberjack.Logger{
		Filename:   "collector.log",
		MaxSize:    1, // megabytes
		MaxBackups: 10,
		MaxAge:     10,   //days
		Compress:   true, // disabled by default
	})
	core := zapcore.NewTee(
		zapcore.NewSamplerWithOptions(
			zapcore.NewCore(fileEncoder, fileWriter, zap.InfoLevel), time.Second, 4, 1),
	)

	logger := zap.New(core, zap.AddCaller())
	defer logger.Sync()
	zap.ReplaceGlobals(logger)

	// context for all jobs
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// user
	user, _ := event.GetEvent("user")
	user.SetMode(event.Differential)
	user.SetInterval(600)
	go event.RunEvent(user, true, ctx)

	// processes
	process, _ := event.GetEvent("process")
	process.SetMode(event.Differential)
	process.SetInterval(3600)
	go event.RunEvent(process, false, ctx)

	// yum
	yum, _ := event.GetEvent("yum")
	yum.SetMode(event.Differential)
	yum.SetInterval(3600)
	go event.RunEvent(yum, false, ctx)

	// sshdconfig
	sshdconfig, _ := event.GetEvent("sshdconfig")
	sshdconfig.SetMode(event.Differential)
	sshdconfig.SetInterval(3600)
	go event.RunEvent(sshdconfig, false, ctx)

	// socket 定期采集
	sshconfig, _ := event.GetEvent("sshconfig")
	sshconfig.SetMode(event.Differential)
	sshconfig.SetInterval(3600)
	go event.RunEvent(sshconfig, false, ctx)

	// crontab 信息采集
	// go CronJob(ctx)

	// ssh 登录信息
	// go GetSSH(ctx)

	socket, _ := event.GetEvent("socket")
	socket.SetMode(event.Differential)
	socket.SetInterval(300)
	event.RunEvent(socket, false, ctx)
}
