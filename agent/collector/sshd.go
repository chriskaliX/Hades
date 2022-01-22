package collector

import (
	"agent/global"
	"agent/utils"
	"bufio"
	"context"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

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
		secure  string
		// record the last size
		lastSize int64
		fs       os.FileInfo
	)

	path = "/var/log/auth.log"
	secure = "/var/log/secure"

	// init the size
	fs, err = os.Stat(path)
	if err != nil {
		zap.S().Error(err)
		fs, err = os.Stat(secure)
		if err != nil {
			zap.S().Error(err)
			return
		} else {
			path = secure
		}
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
					return
				}
				// nothing to read
				if fs.Size() == lastSize {
					continue
					// truncate maybe, need to look into that
				} else if fs.Size() < lastSize {
					lastSize = fs.Size()
					if lastSize > 1024*1024 {
						lastSize = lastSize - 1024*1024
					}
				}
				// start to read
				file, err := os.Open(path)
				if err != nil {
					zap.S().Error(err)
					return
				}
				// 0 = Beginning of file
				// 1 = Current position
				// 2 = End of file
				file.Seek(lastSize, 0)
				s := bufio.NewScanner(io.LimitReader(file, 1024*1024))
				for s.Scan() {
					// some situations that we need to audit
					// 1. Session opened - Success Login
					// 2. Received disconnect from - Port Scanner
					// 3. Invalid user - Failed Login
					fields := strings.Fields(s.Text())
					if len(fields) < 6 {
						continue
					}
					timeNow, err := time.Parse(time.Stamp, strings.Join(fields[:3], " "))
					if err != nil {
						continue
					}

					sshlog := make(map[string]string)
					rawdata := make(map[string]string)
					rawdata["time"] = strconv.FormatInt(timeNow.Unix(), 10)
					rawdata["data_type"] = "3003"

					// failed password
					if len(fields) == 14 && fields[6] == "password" {
						switch fields[5] {
						case "Failed", "Accepted":
							sshlog["reason"] = fields[5]
						}
						sshlog["username"] = fields[8]
						sshlog["ip"] = fields[10]
						sshlog["port"] = fields[12]
						if data, err := utils.Marshal(sshlog); err == nil {
							rawdata["data"] = string(data)
							global.UploadChannel <- rawdata
						}

					}
				}
				// before we exit
				lastSize = fs.Size()
			}
		case err := <-watcher.Errors:
			zap.S().Error(err)
			return
		case <-ctx.Done():
			return
		}
	}
}
