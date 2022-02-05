package main

import (
	"fmt"
	"runtime"
	"strconv"
	"sync"
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
		Sha256:  "3899dec243d4f4db760d19224055c07a3037d6cbfa6ece9591a437e97831be3f",
	}
	manager := plugin.NewManager()
	manager.Sync(cfg)
	wg.Wait()
	fmt.Println("agent itself has started")
}
