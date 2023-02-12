package main

import (
	"collector/event"
	"collector/eventmanager"
	"flag"
	_ "net/http/pprof"
	"runtime"
	"time"

	"github.com/chriskaliX/SDK"
	"github.com/chriskaliX/SDK/logger"
	"go.uber.org/zap/zapcore"
)

func init() {
	n := runtime.NumCPU()
	if n > 4 {
		n = 4
	}
	runtime.GOMAXPROCS(n)
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
			MaxSize:     10,
			MaxBackups:  10,
			Compress:    true,
			FileLevel:   zapcore.InfoLevel,
			RemoteLevel: zapcore.ErrorLevel,
		},
	}
	// sandbox init
	sandbox := SDK.NewSandbox(sconfig)
	em := eventmanager.New(sandbox)
	// TODO: sync.Cond
	// Add events
	em.AddEvent(&event.Container{}, 5*time.Minute, eventmanager.Snapshot)
	em.AddEvent(&event.Crontab{}, eventmanager.Start, eventmanager.None)
	em.AddEvent(&event.Process{}, 15*time.Minute, eventmanager.Snapshot)
	em.AddEvent(&event.Socket{}, 10*time.Minute, eventmanager.Snapshot)
	em.AddEvent(&event.SSH{}, eventmanager.Start, eventmanager.None)
	em.AddEvent(&event.SshConfig{}, 30*time.Minute, eventmanager.Snapshot)
	em.AddEvent(&event.Sshd{}, 30*time.Minute, eventmanager.Snapshot)
	em.AddEvent(&event.User{}, 10*time.Minute, eventmanager.Snapshot)
	em.AddEvent(&event.Yum{}, 10*time.Minute, eventmanager.Snapshot)

	sandbox.Run(em.Run)
}
