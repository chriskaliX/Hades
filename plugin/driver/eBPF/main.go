package main

import (
	user "hades-ebpf/user"
	"hades-ebpf/user/decoder"
	"hades-ebpf/user/share"
	"os"
	"os/signal"
	"syscall"
	"time"

	flag "github.com/spf13/pflag"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	lumberjack "gopkg.in/natefinch/lumberjack.v2"
)

func main() {
	decoder.EventFilter = flag.String("filter", "0", "set filter to specific the event id")
	// parse the log
	flag.Parse()
	// zap configuration pre-set
	fileEncoder := zapcore.NewConsoleEncoder(zap.NewDevelopmentEncoderConfig())
	fileWriter := zapcore.AddSync(&lumberjack.Logger{
		Filename:   "hades-ebpf.log",
		MaxSize:    2, // megabytes
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
	zap.S().Info("Hades eBPF driver start")
	// allow init
	decoder.SetAllowList(*decoder.EventFilter)
	// generate the main driver and run
	driver, err := user.NewDriver()
	if err != nil {
		zap.S().Error(err)
		return
	}
	if err = driver.Start(); err != nil {
		zap.S().Error(err)
		return
	}
	if err = driver.Init(); err != nil {
		zap.S().Error(err)
		return
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM)
	zap.S().Info("eBPF driver run successfully")
	for {
		select {
		case sig := <-sigs:
			zap.S().Error("receive signal:", sig.String())
			zap.S().Info("wait for 5 secs to exit eBPF driver")
			<-time.After(time.Second * 5)
			return
		case <-share.GContext.Done():
			if user.Env == "debug" {
				// just for testing
				time.Sleep(5 * time.Second)
				continue
			}
			zap.S().Error("client context done received")
			zap.S().Info("wait for 5 secs to exit eBPF driver")
			<-time.After(time.Second * 5)
			return
		default:
			time.Sleep(time.Second)
		}
	}
}
