package main

import (
	"collector/event"
	"collector/share"
	"flag"
	"runtime"

	"github.com/chriskaliX/SDK"
	"github.com/chriskaliX/SDK/logger"
	"go.uber.org/zap/zapcore"
)

func init() {
	runtime.GOMAXPROCS(4)
}
func collector(sandbox SDK.ISandbox) error {
	// user
	user, _ := event.GetEvent("user")
	user.SetMode(event.Differential)
	user.SetInterval(600)
	go event.RunEvent(user, true, sandbox.Context())

	// processes
	process, _ := event.GetEvent("process")
	process.SetMode(event.Differential)
	process.SetInterval(3600)
	go event.RunEvent(process, false, sandbox.Context())

	// yum
	yum, _ := event.GetEvent("yum")
	yum.SetMode(event.Differential)
	yum.SetInterval(3600)
	go event.RunEvent(yum, false, sandbox.Context())

	// sshdconfidg
	sshdconfig, _ := event.GetEvent("sshdconfig")
	sshdconfig.SetMode(event.Differential)
	sshdconfig.SetInterval(3600)
	go event.RunEvent(sshdconfig, false, sandbox.Context())

	// socket
	sshconfig, _ := event.GetEvent("sshconfig")
	sshconfig.SetMode(event.Differential)
	sshconfig.SetInterval(3600)
	go event.RunEvent(sshconfig, false, sandbox.Context())

	// for crontab and sshd and cn_proc and crontab . It's sync job
	// By the way a limit to pid tree should be strictly considered.
	cron, _ := event.GetEvent("cron")
	cron.SetType(event.Realtime)
	go event.RunEvent(cron, false, sandbox.Context())

	// ssh login events
	ssh, _ := event.GetEvent("ssh")
	ssh.SetType(event.Realtime)
	go event.RunEvent(ssh, false, sandbox.Context())

	// ncp = netlink/cn_proc
	ncp, _ := event.GetEvent("ncp")
	ncp.SetType(event.Realtime)
	go event.RunEvent(ncp, false, sandbox.Context())

	socket, _ := event.GetEvent("socket")
	socket.SetMode(event.Differential)
	socket.SetInterval(300)
	event.RunEvent(socket, false, sandbox.Context())

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
	sandbox.Init(sconfig)
	share.Sandbox = sandbox
	// run
	sandbox.Run(collector)
}
