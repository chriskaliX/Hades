//go:build windows

package plugin

import (
	"agent/agent"
	"agent/proto"
	"agent/utils"
	"bufio"
	"context"
	"os"
	"os/exec"
	"path"
	"sync"
	"time"

	"go.uber.org/zap"
)

func NewPlugin(ctx context.Context, config proto.Config) (p *Plugin, err error) {
	var (
		rx_r, rx_w, tx_r, tx_w *os.File
		errFile                *os.File
	)
	p = &Plugin{
		config:     config,
		updateTime: time.Now(),
		done:       make(chan struct{}),
		taskCh:     make(chan proto.Task),
		wg:         &sync.WaitGroup{},
		logger:     zap.S().With("plugin", config.Name, "pver", config.Version, "psign", config.Signature),
	}
	p.workdir = path.Join(agent.Instance.Workdir, "plugin", p.Name())
	// pipe init
	// In Elkeid, a note: 'for compatibility' is here. Since some systems only allow
	// half-duplex pipe.
	rx_r, rx_w, err = os.Pipe()
	if err != nil {
		p.logger.Error("rx pipe init")
		return
	}
	p.rx = rx_r
	defer rx_w.Close()
	tx_r, tx_w, err = os.Pipe()
	if err != nil {
		p.logger.Error("tx pipe init")
		return
	}
	p.tx = tx_w
	defer tx_r.Close()
	// reader init
	p.reader = bufio.NewReaderSize(rx_r, 1024*128)
	// purge the files
	os.Remove(path.Join(p.workdir, p.Name()+".stderr"))
	os.Remove(path.Join(p.workdir, p.Name()+".stdout"))
	// cmdline
	execPath := path.Join(p.workdir, p.Name())
	err = utils.CheckSignature(execPath, config.Signature)
	if err != nil {
		p.logger.Warn("check signature failed")
		p.logger.Info("start download")
		err = utils.Download(ctx, execPath, config.Sha256, config.DownloadUrls, config.Type)
		if err != nil {
			p.logger.Error("download failed:", err)
			return
		}
		p.logger.Info("download success")
	}
	cmd := exec.Command(execPath)
	// cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	// cmd.ExtraFiles = append(cmd.ExtraFiles, tx_r, rx_w)
	cmd.Stdin = tx_r
	cmd.Stdout = rx_w
	cmd.Dir = p.workdir
	if errFile, err = os.OpenFile(execPath+".stderr", os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o0600); err != nil {
		p.logger.Error("open stderr:", errFile)
		return
	}
	defer errFile.Close()
	cmd.Stderr = errFile
	// details. if it is needed
	if config.Detail != "" {
		cmd.Env = append(cmd.Env, "DETAIL="+config.Detail)
	}
	p.logger.Info("cmd start")
	err = cmd.Start()
	if err != nil {
		p.logger.Error("cmd start:", err)
	}
	p.cmd = cmd
	return
}

// Syscall is system related.
func (p *Plugin) Shutdown() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.IsExited() {
		return
	}
	p.logger.Info("shutdown called")
	p.tx.Close()
	p.rx.Close()
	select {
	case <-time.After(time.Second * 30):
		p.logger.Warn("close by killing start")
		process, err := os.FindProcess(p.pid)
		if err != nil {
			zap.S().Error(err)
			return
		}
		process.Kill()
		<-p.done
		p.logger.Info("close by killing done")
	case <-p.done:
		p.logger.Info("close by done channel")
	}
}
