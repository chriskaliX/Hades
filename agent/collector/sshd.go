package collector

import (
	"context"
	"os"

	"github.com/fsnotify/fsnotify"
	"go.uber.org/zap"
)

// Get and parse SSH log
func GetSSH(ctx context.Context) {
	// Redhat or Fedora Core: /var/log/secure
	// Mandrake, FreeBSD, OpenBSD or Debian: /var/log/auth.log
	// Format: Month Day Time Hostname ProcessName[ActionID] Message
	var (
		err     error
		watcher *fsnotify.Watcher
		path    string
		// record the last size
		lastSize int64
	)

	path = "/var/log/secure"

	// init the size
	fs, err := os.Stat(path)
	if err != nil {
		zap.S().Error(err)
		return
	}
	lastSize = fs.Size()

	// start a watcher
	// TODO: make this to a interface
	if watcher, err = fsnotify.NewWatcher(); err != nil {
		zap.S().Error(err)
		return
	}
	defer watcher.Close()

	watcher.Add(path)

	// only for write now, evaluate
	for {
		select {
		case event := <-watcher.Events:
			switch event.Op {
			case fsnotify.Write:
				fs, err := os.Stat(event.Name)
				if err != nil {
					zap.S().Error(err)
				}
				// the first time, read
				
			}
		case err := <-watcher.Errors:
			zap.S().Error(err)
			return
		case <-ctx.Done():
			return
		}
	}
}
