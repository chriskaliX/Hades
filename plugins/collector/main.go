package main

import (
	"collector/event"
	"collector/eventmanager"
	"flag"
	"runtime"
	"runtime/debug"
	"time"

	_ "net/http/pprof"

	"github.com/chriskaliX/SDK"
	"github.com/chriskaliX/SDK/logger"
	"go.uber.org/zap/zapcore"
)

func init() {
	n := runtime.NumCPU()
	if n > 4 {
		n = 4
	}
	// set memorylimit to 50M
	debug.SetMemoryLimit(50 * 1024 * 1024)
	runtime.GOMAXPROCS(n)
	SDK.RuntimeOpt()
}

func main() {
	var debug bool
	flag.BoolVar(&debug, "debug", false, "set to run in debug mode")
	flag.Parse()
	// start the sandbox
	sconfig := &SDK.SandboxConfig{
		Debug: debug,
		Name:  "collector",
		LogConfig: &logger.Config{
			Path:        "collector.log",
			MaxSize:     1,
			MaxBackups:  10,
			Compress:    true,
			FileLevel:   zapcore.InfoLevel,
			RemoteLevel: zapcore.ErrorLevel,
		},
	}
	// sandbox init
	sandbox := SDK.NewSandbox(sconfig)
	em := eventmanager.New(sandbox)
	em.AddEvent(&event.SSH{}, eventmanager.EmptyDuration)
	em.AddEvent(&event.CronWatcher{}, eventmanager.EmptyDuration)
	em.AddEvent(&event.Container{}, 5*time.Minute)
	em.AddEvent(&event.User{}, 10*time.Minute)
	em.AddEvent(&event.Process{}, 15*time.Minute)
	em.AddEvent(&event.Crontab{}, 24*time.Hour)
	// system configuration
	em.AddEvent(&event.Configs{}, 6*time.Hour)
	// system-related
	event.RegistSystem(em)
	// networks
	event.RegistNetwork(em)
	// applications
	em.AddEvent(&event.Application{}, 24*time.Hour)
	// libraries (jar / dpkg / rpm / yum)
	em.AddEvent(&event.Libraries{}, 24*time.Hour)
	sandbox.Run(em.Schedule)
}
