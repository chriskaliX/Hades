package main

import (
	"hades-ebpf/user"
	"hades-ebpf/user/cache"
	"hades-ebpf/user/decoder"
	"hades-ebpf/user/share"

	"hades-ebpf/cmd"

	"github.com/chriskaliX/SDK"
	"github.com/chriskaliX/SDK/logger"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

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
	if err = driver.PostRun(); err != nil {
		zap.S().Error(err)
		return err
	}
	return nil
}

func main() {
	// inject into sandbox
	cmd.RootCmd.Run = (func(c *cobra.Command, args []string) {
		sconfig := &SDK.SandboxConfig{
			Debug: share.Debug,
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
		// TODO: Dirty init jusr for now
		cache.DefaultHashCache = sandbox.Hash
		// Better UI for command line usage
		sandbox.Run(driver)
	})
	cmd.Execute()
}
