//go:build windows

package server

import (
	"time"
)

func (s *Server) cmdInit() {
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
		// In windows, some plugin needs to shutdown with driver uninstall
		// in this case, DO NOT send kill imediately
		process, err := os.FindProcess(p.cmd.Process.Pid)
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
