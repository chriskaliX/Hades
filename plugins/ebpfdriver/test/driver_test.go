package test

import (
	"encoding/json"
	"hades-ebpf/user"
	"hades-ebpf/user/decoder"
	"hades-ebpf/user/share"
	"net"
	"testing"
	"time"

	"github.com/chriskaliX/SDK"
	"github.com/chriskaliX/SDK/logger"
	"github.com/chriskaliX/SDK/transport/protocol"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var driver *user.Driver

func appRun(s SDK.ISandbox) (err error) {
	go func() {
		time.Sleep(10 * time.Second)
		s.Shutdown()
	}()
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

func TestMain(t *testing.T) {
	share.Debug = true
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
	decoder.SetAllowList([]string{"1022"})
	// sandbox init
	sandbox := SDK.NewSandbox()
	if err := sandbox.Init(sconfig); err != nil {
		return
	}
	// flags
	var connect_flag bool
	// test by use the hook
	sandbox.SetSendHook(func(rec *protocol.Record) error {
		switch rec.DataType {
		case 1022:
			data := make(map[string]interface{}, 30)
			json.Unmarshal([]byte(rec.Data.Fields["data"]), &data)
			if data["dip"] == "8.8.8.8" && data["dport"] == float64(80) {
				connect_flag = true
			}
		}
		return nil
	})
	// test case
	go func() {
		time.Sleep(5 * time.Second)
		connect()
	}()

	// Better UI for command line usage
	sandbox.Run(appRun)

	assert.Equal(t, connect_flag, true, "connect testcase failed")
}

func connect() {
	net.DialTimeout("tcp", "8.8.8.8:80", 3*time.Second)
}
