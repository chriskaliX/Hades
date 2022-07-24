package main

import (
	"collector/event"
	"collector/share"
	"context"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

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

	// For furthur information collection. All events come with a specific order.
	// User -> processes -> ncp should be strictly ordered to avoid lack of data.
	// Use sync.Cond maybe

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

	// sshdconfidg
	sshdconfig, _ := event.GetEvent("sshdconfig")
	sshdconfig.SetMode(event.Differential)
	sshdconfig.SetInterval(3600)
	go event.RunEvent(sshdconfig, false, ctx)

	// socket
	sshconfig, _ := event.GetEvent("sshconfig")
	sshconfig.SetMode(event.Differential)
	sshconfig.SetInterval(3600)
	go event.RunEvent(sshconfig, false, ctx)

	// for crontab and sshd and cn_proc and crontab . It's sync job
	// By the way a limit to pid tree should be strictly considered.
	cron, _ := event.GetEvent("cron")
	cron.SetType(event.Realtime)
	go event.RunEvent(cron, false, ctx)

	// ssh login events
	ssh, _ := event.GetEvent("ssh")
	ssh.SetType(event.Realtime)
	go event.RunEvent(ssh, false, ctx)

	// ncp = netlink/cn_proc
	ncp, _ := event.GetEvent("ncp")
	ncp.SetType(event.Realtime)
	go event.RunEvent(ncp, false, ctx)

	socket, _ := event.GetEvent("socket")
	socket.SetMode(event.Differential)
	socket.SetInterval(300)
	go event.RunEvent(socket, false, ctx)

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM)
	for {
		select {
		case sig := <-sigs:
			zap.S().Error("receive signal:", sig.String())
			zap.S().Info("wait for 5 secs to exit eBPF driver")
			<-time.After(time.Second * 5)
		case <-share.GContext.Done():
			zap.S().Error("client exit")
			zap.S().Info("wait for 5 secs to exit eBPF driver")
			<-time.After(time.Second * 5)
		}
	}
}
