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
	// TODO: sync.Cond
	// Add events

	var sockAndAppInterval = 15 * time.Minute
	// socket and application must get the same interval since application needs the socket informations
	em.AddEvent(&event.Crontab{}, eventmanager.Start)
	em.AddEvent(&event.SSH{}, eventmanager.Start)

	em.AddEvent(&event.Socket{}, sockAndAppInterval)
	em.AddEvent(&event.Application{}, sockAndAppInterval)

	em.AddEvent(&event.Container{}, 5*time.Minute)
	em.AddEvent(&event.User{}, 10*time.Minute)
	em.AddEvent(&event.Yum{}, 10*time.Minute)
	em.AddEvent(&event.Process{}, 15*time.Minute)

	em.AddEvent(&event.Kmod{}, 6*time.Minute)
	em.AddEvent(&event.SshConfig{}, 6*time.Hour)
	em.AddEvent(&event.Sshd{}, 6*time.Hour)
	em.AddEvent(&event.Disk{}, 6*time.Hour)
	em.AddEvent(&event.NetInterface{}, 6*time.Hour)
	em.AddEvent(&event.SystemdUnit{}, 6*time.Hour)
	em.AddEvent(&event.BPFProg{}, 6*time.Hour)

	em.AddEvent(&event.Iptables{}, 24*time.Hour)
	em.AddEvent(&event.Libraries{}, 24*time.Hour)

	sandbox.Run(em.Run)
}
