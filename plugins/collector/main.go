package main

import (
	"collector/event"
	"collector/eventmanager"
	"flag"
	_ "net/http/pprof"
	"runtime"
	"runtime/debug"
	"time"

	_ "net/http/pprof"

	"github.com/chriskaliX/SDK"
	"github.com/chriskaliX/SDK/logger"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func init() {
	n := runtime.NumCPU()
	if n > 4 {
		n = 4
	}
	runtime.GOMAXPROCS(n)
}

// setGCPercentForSlowStart sets GC percent with a small value at startup
// to avoid high RSS (caused by data catch-up) to trigger OOM-kill.
// alibaba ilogtail
func setGCPercentForSlowStart() {
	gcPercent := 20
	defaultGCPercent := debug.SetGCPercent(gcPercent)
	zap.S().Infof("set startup GC percent from %v to %v", defaultGCPercent, gcPercent)
	resumeSeconds := 5 * 60
	go func(pc int, sec int) {
		time.Sleep(time.Second * time.Duration(sec))
		last := debug.SetGCPercent(pc)
		zap.S().Infof("resume GC percent from %v to %v", last, pc)
	}(defaultGCPercent, resumeSeconds)
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

	em.AddEvent(&event.SSH{}, eventmanager.Start)
	em.AddEvent(&event.CronWatcher{}, eventmanager.Start)

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

	// go func() {
	// 	http.ListenAndServe("0.0.0.0:6060", nil)
	// }()

	sandbox.Run(em.Run)
}
