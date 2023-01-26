package main

import (
	"bytes"
	"edr/pkg/conf"
	"io/ioutil"
	"math"

	"github.com/chriskaliX/SDK"
	"github.com/chriskaliX/SDK/logger"
	manager "github.com/ehids/ebpfmanager"
	"go.uber.org/zap/zapcore"
	"golang.org/x/sys/unix"
)

const Name = "edr"
const LogPath = Name + ".log"

func appRun(s SDK.ISandbox) error {
	m := manager.Manager{}
	_bytecode, err := ioutil.ReadFile(conf.NAME + ".bpf.o")
	if err != nil {
		return err
	}
	m.Probes = append(m.Probes, &manager.Probe{
		Section:          "kprobe/openat",
		EbpfFuncName:     "kprobe_openat",
		AttachToFuncName: "openat",
	})

	if err = m.InitWithOptions(
		bytes.NewReader(_bytecode),
		manager.Options{
			DefaultKProbeMaxActive: 512,
			RLimit: &unix.Rlimit{
				Cur: math.MaxUint64,
				Max: math.MaxUint64,
			},
		},
	); err != nil {
		return err
	}

	return m.Start()
}

func main() {
	sconfig := &SDK.SandboxConfig{
		Debug: true,
		Name:  Name,
		LogConfig: &logger.Config{
			Path:        LogPath,
			MaxSize:     10,
			MaxBackups:  10,
			Compress:    true,
			FileLevel:   zapcore.InfoLevel,
			RemoteLevel: zapcore.ErrorLevel,
		},
	}
	// sandbox init
	sandbox := SDK.NewSandbox(sconfig)
	// Better UI for command line usage
	sandbox.Run(appRun)
}
