package main

import (
	"collector/event"
	"collector/share"
	"flag"
	_ "net/http/pprof"
	"runtime"

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

func collector(sandbox SDK.ISandbox) error {
	// user
	user, _ := event.GetEvent("user")
	user.SetMode(event.Snapshot)
	user.SetType(event.Periodicity)
	user.SetInterval(600)
	go event.RunEvent(user, true, sandbox.Context())

	// processes
	process, _ := event.GetEvent("process")
	process.SetMode(event.Snapshot)
	process.SetType(event.Periodicity)
	process.SetInterval(3600)
	go event.RunEvent(process, false, sandbox.Context())

	// yum
	yum, _ := event.GetEvent("yum")
	yum.SetMode(event.Differential)
	yum.SetType(event.Periodicity)
	yum.SetInterval(3600)
	go event.RunEvent(yum, false, sandbox.Context())

	// sshdconfig
	sshdconfig, _ := event.GetEvent("sshdconfig")
	sshdconfig.SetMode(event.Snapshot)
	sshdconfig.SetInterval(3600)
	go event.RunEvent(sshdconfig, false, sandbox.Context())

	// ssh
	sshconfig, _ := event.GetEvent("sshconfig")
	sshconfig.SetMode(event.Snapshot)
	sshconfig.SetInterval(3600)
	go event.RunEvent(sshconfig, false, sandbox.Context())

	// for crontab and sshd and cn_proc and crontab . It's sync job
	// By the way a limit to pid tree should be strictly considered.
	// For collections, we need snapshot
	cron, _ := event.GetEvent("cron")
	cron.SetType(event.Realtime)
	go event.RunEvent(cron, false, sandbox.Context())

	// ssh login events
	ssh, _ := event.GetEvent("ssh")
	ssh.SetType(event.Realtime)
	go event.RunEvent(ssh, false, sandbox.Context())

	// ncp(netlink cn_proc)
	ncp, _ := event.GetEvent("ncp")
	ncp.SetType(event.Realtime)
	go event.RunEvent(ncp, false, sandbox.Context())

	// socket
	socket, _ := event.GetEvent("socket")
	socket.SetMode(event.Snapshot)
	socket.SetInterval(300)
	go event.RunEvent(socket, false, sandbox.Context())

	return nil
}

func main() {
	var debug bool
	flag.BoolVar(&debug, "debug", false, "set to run in debug mode")
	flag.Parse()
	// start the sandbox
	sconfig := &SDK.SandboxConfig{
		Debug: debug,
		Hash:  true,
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
	sandbox := SDK.NewSandbox()
	if err := sandbox.Init(sconfig); err != nil {
		return
	}
	share.Sandbox = sandbox
	// run
	sandbox.Run(collector)
}
