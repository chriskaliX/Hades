//go:build linux

package server

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/chriskaliX/SDK/transport/protocol"
	"github.com/chriskaliX/SDK/utils"
	"go.uber.org/zap"
)

func NewServer(ctx context.Context, workdir string, conf protocol.Config) (s *Server, err error) {
	var rx_r, rx_w, tx_r, tx_w, errFile *os.File
	// internal config parser
	// Server init
	s = &Server{
		config:     conf,
		updateTime: time.Now(),
		done:       make(chan struct{}),
		taskCh:     make(chan protocol.Task),
		wg:         &sync.WaitGroup{},
		logger:     zap.S().With("plugin", conf.GetName(), "pver", conf.GetVersion(), "psign", conf.GetSignature()),
	}
	s.workdir = filepath.Join(workdir, "plugin", s.Name())
	// pipe init
	rx_r, rx_w, err = os.Pipe()
	if err != nil {
		s.logger.Error("rx pipe init")
		return
	}
	s.rx = rx_r
	defer rx_w.Close()
	tx_r, tx_w, err = os.Pipe()
	if err != nil {
		s.logger.Error("tx pipe init")
		return
	}
	s.tx = tx_w
	defer tx_r.Close()
	s.reader = bufio.NewReaderSize(rx_r, 1024*128)
	os.Remove(filepath.Join(s.workdir, s.Name()+".stderr"))
	os.Remove(filepath.Join(s.workdir, s.Name()+".stdout"))
	// cmdline
	execPath := filepath.Join(s.workdir, s.Name())
	// For now, downloading and check are in the NewPlugin. Maybe remove
	// this later since is non-related behavior for new action.
	err = util.CheckSignature(execPath, conf.GetSignature())
	if err != nil {
		s.logger.Warn("check signature failed")
		s.logger.Info("start download")
		err = util.Download(ctx, execPath, conf.GetSha256(), conf.GetDownloadUrls(), conf.GetType())
		if err != nil {
			s.logger.Error("download failed:", err)
			return
		}
		s.logger.Info("download success")
	}
	// cmdline init
	cmd := exec.CommandContext(ctx, execPath)
	cmd.ExtraFiles = append(cmd.ExtraFiles, tx_r, rx_w)
	cmd.Dir = s.workdir
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if errFile, err = os.OpenFile(execPath+".stderr", os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o0600); err != nil {
		s.logger.Error("open stderr:", errFile)
		return
	}
	defer errFile.Close()
	cmd.Stderr = errFile
	// details. if it is needed
	if conf.GetDetail() != "" {
		cmd.Env = append(cmd.Env, "DETAIL="+conf.GetDetail())
	}
	s.logger.Info("cmd start")
	err = cmd.Start()
	if err != nil {
		s.logger.Error("cmd start:", err)
		return
	}
	s.cmd = cmd
	return
}

func (s *Server) Shutdown() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.IsExited() {
		return
	}
	s.logger.Info("shutdown called")
	s.tx.Close()
	s.rx.Close()
	select {
	case <-time.After(time.Second * 30):
		s.logger.Warn("close by killing start")
		syscall.Kill(-s.cmd.Process.Pid, syscall.SIGKILL)
		<-s.done
		s.logger.Info("close by killing done")
	case <-s.done:
		s.logger.Info("close by done channel")
	}
}
