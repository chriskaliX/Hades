package main

import (
	"flag"
	user "hades-ebpf/user"
	"hades-ebpf/user/decoder"
	"hades-ebpf/user/event"
	"net/http"
	_ "net/http/pprof"
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
	// filters for command line
	filter := flag.Uint64("f", 0, "filter")
	flag.Parse()
	decoder.SetFilter(*filter)
	// the real functions
	var err error
	if err = user.DefaultDriver.Init(); err != nil {
		zap.S().Error(err)
		return
	}
	if err = user.DefaultDriver.Start(); err != nil {
		zap.S().Error(err)
		return
	}
	if err = user.DefaultDriver.AfterRunInitialization(); err != nil {
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
				if err = event.DefaultAntiRootkit.Scan(user.DefaultDriver.Manager); err != nil {
					zap.S().Error(err)
				}
			}
		}
	}()
	http.ListenAndServe("localhost:6060", nil)
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM)
	sig := <-sigs
	zap.S().Error("receive signal:", sig.String())
	zap.S().Info("wait for 5 secs to exit")
	<-time.After(time.Second * 5)
}
