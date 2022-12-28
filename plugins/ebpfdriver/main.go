package main

import (
	"hades-ebpf/user"
	"hades-ebpf/user/decoder"
	_ "hades-ebpf/user/event"
	"hades-ebpf/user/share"

	"hades-ebpf/cmd"

	"github.com/chriskaliX/SDK"
	"github.com/chriskaliX/SDK/logger"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	_ "net/http/pprof"
)

var driver *user.Driver

func appRun(s SDK.ISandbox) (err error) {
	decoder.SetAllowList(share.EventFilter)
	driver, err = user.NewDriver(s)
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
	cmd.RootCmd.Run = (func(_ *cobra.Command, _ []string) {
		sconfig := &SDK.SandboxConfig{
			Debug: share.Debug,
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
		defer func() {
			if driver != nil {
				driver.Stop()
				return
			}
		}()
		// Better UI for command line usage
		sandbox.Run(appRun)
	})
	cmd.Execute()
}
