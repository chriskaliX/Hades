package main

import (
	"encoding/json"
	"hades-ebpf/conf"
	"hades-ebpf/user"
	"hades-ebpf/user/decoder"
	"io/ioutil"
	"net"
	"os/exec"
	"strings"
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
		time.Sleep(30 * time.Second)
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
	conf.Debug = true
	sconfig := &SDK.SandboxConfig{
		Debug: conf.Debug,
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
	decoder.SetAllowList([]string{"700", "1022", "1028", "1031"})
	// sandbox init
	sandbox := SDK.NewSandbox(sconfig)
	// flags
	var connect_flag bool
	var execve_flag bool
	var inode_create_flag bool
	var inode_rename_flag bool
	// test by use the hook
	sandbox.SetSendHook(func(rec *protocol.Record) error {
		switch rec.DataType {
		case 1022:
			data := make(map[string]interface{}, 30)
			json.Unmarshal([]byte(rec.Data.Fields["data"]), &data)
			if data["dip"] == "172.16.17.1" && data["dport"] == float64(8090) {
				connect_flag = true
			}
		case 700:
			data := make(map[string]interface{}, 30)
			json.Unmarshal([]byte(rec.Data.Fields["data"]), &data)
			if data["comm"] == "ls" {
				execve_flag = true
			}
		case 1028:
			data := make(map[string]interface{}, 30)
			json.Unmarshal([]byte(rec.Data.Fields["data"]), &data)
			if strings.HasSuffix(data["filename"].(string), "1.txt") {
				inode_create_flag = true
			}
		case 1031:
			data := make(map[string]interface{}, 30)
			json.Unmarshal([]byte(rec.Data.Fields["data"]), &data)
			if strings.HasSuffix(data["old"].(string), "1.txt") && strings.HasSuffix(data["new"].(string), "2.txt") {
				inode_rename_flag = true
			}
		}
		return nil
	})
	// test case
	go func() {
		for {
			if (driver != nil) && driver.Status() {
				break
			}
			time.Sleep(1 * time.Second)
		}
		go connect()
		go execve()
		t.Log(inode_create())
		t.Log(inode_rename())
	}()
	// Better UI for command line usage
	sandbox.Run(appRun)
	time.Sleep(5 * time.Second)
	f, err := ioutil.ReadFile("edriver.log")
	if err == nil {
		t.Log(string(f))
	}

	// clean up
	exec.Command("rm", "-f", "test/dist/*.txt").Start() // clean up
	assert.Equal(t, connect_flag, true, "connect testcase failed")
	assert.Equal(t, execve_flag, true, "execve testcase failed")
	assert.Equal(t, inode_create_flag, true, "inode_create testcase failed")
	assert.Equal(t, inode_rename_flag, true, "inode_create testcase failed")
}

func connect() {
	net.DialTimeout("tcp", "172.16.17.1:8090", 3*time.Second)
}

func execve() error {
	return exec.Command("ls", "la").Start()
}

func inode_create() error {
	return exec.Command("touch", "dist/1.txt").Run()
}

func inode_rename() error {
	return exec.Command("mv", "dist/1.txt", "dist/2.txt").Run()
}
