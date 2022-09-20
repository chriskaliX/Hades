package main

import (
	"flag"
	"hades-ebpf/user"
	"hades-ebpf/user/cache"
	"hades-ebpf/user/decoder"
	"hades-ebpf/user/share"

	"github.com/chriskaliX/SDK"
	"github.com/chriskaliX/SDK/logger"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"net/http"
	_ "net/http/pprof"
)

func driver(s SDK.ISandbox) error {
	decoder.SetAllowList(share.EventFilter)
	driver, err := user.NewDriver(s)
	if err != nil {
		zap.S().Error(err)
		return err
	}
	if err = driver.Start(); err != nil {
		zap.S().Error(err)
		return err
	}
	if err = driver.Init(); err != nil {
		zap.S().Error(err)
		return err
	}
	return nil
}

func main() {
	var debug bool
	flag.BoolVar(&debug, "debug", false, "set to run in debug mode")
	flag.StringVar(&share.EventFilter, "filter", "0", "set filter to specific the event id")
	flag.Parse()
	// start the sandbox
	sconfig := &SDK.SandboxConfig{
		Debug: debug,
		Hash:  true,
		Name:  "ebpfdriver",
		LogConfig: &logger.Config{
			Path:        "ebpfdriver.log",
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
	if debug {
		go http.ListenAndServe("0.0.0.0:50000", nil)
	}
	// TODO: Dirty init jusr for now
	cache.DefaultHashCache = sandbox.Hash
	// inject into sandbox
	sandbox.Run(driver)
}
