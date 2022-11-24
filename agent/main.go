package main

import (
	"flag"
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
	"agent/transport"
	"agent/transport/connection"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	_ "net/http/pprof"

	lumberjack "gopkg.in/natefinch/lumberjack.v2"
)

func init() {
	// 在一些 KVM 下其实可能小于 8，例如 4 核的机器，设置成大于 CPU 的数量反而可能会造成线程频繁切换
	// 考虑到容器环境下 NumCpu 取值问题
	numcpu := runtime.NumCPU()
	if numcpu > 8 {
		numcpu = 8
	}
	runtime.GOMAXPROCS(numcpu)
}

func main() {
	// Before deploying, change the GrpcAddr value if you need to, compare with the original one
	flag.StringVar(&connection.GrpcAddr, "url", "127.0.0.1:9001", "set grpc addr")
	flag.BoolVar(&connection.InsecureTransport, "insecure", false, "grpc with insecure")
	flag.BoolVar(&connection.InsecureTLS, "insecure-tls", true, "grpc tls insecure")
	flag.Parse()
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
	wg.Add(3)
	go plugin.Startup(agent.Instance.Context, wg)
	go heartbeat.Startup(agent.Instance.Context, wg)
	go func() {
		transport.Startup(agent.Instance.Context, wg)
		agent.Instance.Cancel()
	}()

	// https://colobu.com/2015/10/09/Linux-Signals/
	// SIGTERM 信号: 结束程序(可以被捕获、阻塞或忽略)
	// https://github.com/osquery/osquery/blob/master/osquery/process/posix/process.cpp
	// osquery 中也是用这个方式, 作为 gracefulExit 的方式, 应该对 plugin 也如此处理
	go func() {
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGTERM)
		sig := <-sigs
		zap.S().Error("receive signal:", sig.String())
		zap.S().Info("wait for 5 secs to exit")
		<-time.After(time.Second * 5)
		agent.Instance.Cancel()
	}()
	wg.Wait()
}
