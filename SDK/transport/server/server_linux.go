//go:build linux

package server

import (
	"syscall"
	"time"
)

func (s *Server) cmdInit() {
	s.cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
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
