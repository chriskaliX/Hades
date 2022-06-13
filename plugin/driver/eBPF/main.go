package main

import (
	"flag"
	"hades-ebpf/userspace"
	"hades-ebpf/userspace/decoder"
	"hades-ebpf/userspace/event"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	lumberjack "gopkg.in/natefinch/lumberjack.v2"
)

func main() {
	fileEncoder := zapcore.NewConsoleEncoder(zap.NewDevelopmentEncoderConfig())
	fileWriter := zapcore.AddSync(&lumberjack.Logger{
		Filename:   "hades-ebpf.log",
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

	// filters for command line
	filter := flag.Uint64("f", 0, "filter")
	flag.Parse()
	decoder.SetFilter(*filter)
	// the real functions
	var err error
	if err = userspace.DefaultDriver.Init(); err != nil {
		zap.S().Error(err)
		return
	}
	if err = userspace.DefaultDriver.Start(); err != nil {
		zap.S().Error(err)
		return
	}
	if err = userspace.DefaultDriver.AfterRunInitialization(); err != nil {
		zap.S().Error(err)
		return
	}
	// scan job here
	go func() {
		init := true
		ticker := time.NewTicker(time.Second * 5)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if init {
					ticker.Reset(time.Minute * 15)
					init = false
				}
				if err = event.DefaultAntiRootkit.Scan(userspace.DefaultDriver.Manager); err != nil {
					zap.S().Error(err)
				}
			}
		}
	}()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM)
	sig := <-sigs
	zap.S().Error("receive signal:", sig.String())
	zap.S().Info("wait for 5 secs to exit")
	<-time.After(time.Second * 5)
}
