package main

import (
	user "hades-ebpf/user"
	"hades-ebpf/user/decoder"
	"net/http"
	_ "net/http/pprof"
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
	// start to run Hades
	zap.S().Info("Hades eBPF driver start")
	// filters for command line
	filter := flag.String("filter", "1", "--filter to specific the event id")
	flag.Parse()
	decoder.DefaultEventCollection.SetAllowList(*filter)

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
	http.ListenAndServe("localhost:6060", nil)
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM)
	sig := <-sigs
	zap.S().Error("receive signal:", sig.String())
	zap.S().Info("wait for 5 secs to exit")
	<-time.After(time.Second * 5)
}
