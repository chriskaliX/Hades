package main

import (
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"sync"
	"syscall"
	"time"

	"agent/agent"
	"agent/heartbeat"
	"agent/log"
	"agent/plugin"
	"agent/proto"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	_ "net/http/pprof"

	lumberjack "gopkg.in/natefinch/lumberjack.v2"
)

func init() {
	// 在一些 KVM 下其实可能小于 8，例如 4 核的机器，设置成大于 CPU 的数量反而可能会造成线程频繁切换
	numcpu := runtime.NumCPU()
	if numcpu > 8 {
		numcpu = 8
	}
	runtime.GOMAXPROCS(numcpu)
}

// plugin的模式，我思考了一下还是有必要的，又因为偷看了 osquery 的, 功能开放
// 后期蜜罐之类的这种还是以 plugin 模式，年底之前的目标是跑起来
func main() {
	config := zap.NewProductionEncoderConfig()
	config.CallerKey = "source"
	config.TimeKey = "timestamp"
	config.EncodeTime = func(t time.Time, z zapcore.PrimitiveArrayEncoder) {
		z.AppendString(strconv.FormatInt(t.Unix(), 10))
	}
	grpcEncoder := zapcore.NewJSONEncoder(config)
	grpcWriter := zapcore.AddSync(&log.GrpcWriter{})
	fileEncoder := zapcore.NewConsoleEncoder(zap.NewDevelopmentEncoderConfig())
	fileWriter := zapcore.AddSync(&lumberjack.Logger{
		Filename:   "log/hades.log",
		MaxSize:    2, // megabytes - 1 default, 50 for test
		MaxBackups: 10,
		MaxAge:     10,   //days
		Compress:   true, // disabled by default
	})
	core := zapcore.NewTee(zapcore.NewCore(grpcEncoder, grpcWriter, zap.ErrorLevel), zapcore.NewCore(fileEncoder, fileWriter, zap.InfoLevel))
	logger := zap.New(core, zap.AddCaller())
	defer logger.Sync()
	zap.ReplaceGlobals(logger)
	wg := &sync.WaitGroup{}
	// transport to server not added
	wg.Add(2)
	go plugin.Startup(agent.Context, wg)
	go heartbeat.Startup(agent.Context, wg)
	// test
	cfg := make(map[string]*proto.Config)
	cfg["collector"] = &proto.Config{
		Name:    "collector",
		Version: "1.0.0",
		Sha256:  "4e47d55002c585985a60cc51fe0e62622c065276dfd3db310733b957569d1466",
	}
	plugin.DefaultManager.Sync(cfg)

	// https://colobu.com/2015/10/09/Linux-Signals/
	// SIGTERM 信号: 结束程序(可以被捕获、阻塞或忽略)
	go func() {
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGTERM)
		sig := <-sigs
		zap.S().Error("receive signal:", sig.String())
		zap.S().Info("wait for 5 secs to exit")
		<-time.After(time.Second * 5)
		agent.Cancel()
	}()
	wg.Wait()
}
