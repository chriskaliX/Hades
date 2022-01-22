package main

import (
	"encoding/json"
	"fmt"
	"runtime"
	"strconv"
	"time"

	"agent/collector"
	"agent/global"
	"agent/log"
	"agent/report"
	"agent/transport"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"net/http"
	_ "net/http/pprof"

	lumberjack "gopkg.in/natefinch/lumberjack.v2"
)

func init() {
	// 跟进去看一下, 默认值为 100, 策略大致为每次更新会扩大内存
	// 应该是有必要的, 如果以默认的值, 会导致不断的变大, 最终触发外在的内存限制导致 panic 问题
	/*https://gocn.vip/topics/9822*/
	/*https://wudaijun.com/2019/09/go-performance-optimization/*/
	runtime.GOMAXPROCS(8)
	// debug.SetGCPercent(50)
}

// 默认 agent 仅仅保留和server段通信功能, 通信失败就不开启
/*
	字节更新后, 基本移除了所有 panic 的代码
	Agent 自身应该只保留与 server 通讯功能, 其余的功能由服务端控制开启
*/

// plugin的模式，我思考了一下还是有必要的，又因为偷看了 osquery 的, 功能开放
// 后期蜜罐之类的这种还是以 plugin 模式，年底之前的目标是跑起来
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

	// 默认collector也不开, 接收server指令后再开
	// go collector.EbpfGather()
	go collector.Run()
	go transport.Run()
	go report.Run()

	// 下面都是测试代码, 后面这里应该为走 kafka 渠道上传
	// 可以理解为什么字节要先走 grpc 到 server 端, 可以压缩, 统计, 更加灵活
	// 但是我还是以之前部署 osquery 的方式一样, 全部走 kafka, 控制好即可
	// TODO: 2021-11-06 这里考虑一下, kafka 批量上传, ticker 时间过段导致切换频繁
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	go func() {
		for {
			select {
			case <-ticker.C:
				rd := <-global.UploadChannel
				rd["AgentID"] = global.AgentID
				rd["Hostname"] = global.Hostname
				// 目前还在测试, 专门打印
				if rd["data_type"] == "3003" {
					fmt.Println(rd["data"])
				} else {
					continue
				}
				_, err := json.Marshal(rd)
				if err != nil {
					continue
				}
				// network.KafkaSingleton.Send(string(m))
			}
		}
	}()

	http.ListenAndServe("0.0.0.0:6060", nil)
	// time.Sleep(1000 * time.Second)
	// 指令回传在这里
}
