package main

import (
	"edriver/constants"
	user "edriver/pkg"
	"edriver/pkg/decoder"
	_ "edriver/pkg/events"

	"edriver/cmd"

	"github.com/chriskaliX/SDK"
	"github.com/chriskaliX/SDK/logger"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	_ "net/http/pprof"
)

var driver *user.Driver

func appRun(s SDK.ISandbox) (err error) {
	decoder.SetAllowList(constants.EventFilter)
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
		if !constants.Debug {
			SDK.RuntimeOpt()
		}
		sconstantsig := &SDK.SandboxConfig{
			Debug: constants.Debug,
			Name:  "edriver",
			LogConfig: &logger.Config{
				Path:        "edriver.log",
				MaxSize:     10,
				MaxBackups:  10,
				Compress:    true,
				FileLevel:   zapcore.InfoLevel,
				RemoteLevel: zapcore.ErrorLevel,
			},
		}
		// sandbox init
		sandbox := SDK.NewSandbox(sconstantsig)
		// Better UI for command line usage
		sandbox.Run(appRun)
	})
	cmd.Execute()
}
