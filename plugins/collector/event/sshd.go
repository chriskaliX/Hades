package event

import (
	"bufio"
	"collector/eventmanager"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/chriskaliX/SDK"
	"github.com/chriskaliX/SDK/transport/protocol"
	"github.com/fsnotify/fsnotify"
	"github.com/shirou/gopsutil/host"
	"go.uber.org/zap"
)

var _, _platformfamily, _, _ = host.PlatformInformation()

const (
	SSH_DATATYPE = 3003
)

var _ eventmanager.IEvent = (*SSH)(nil)

type SSH struct{}

func (SSH) DataType() int {
	return SSH_DATATYPE
}

func (SSH) Name() string {
	return "ssh"
}

func (n *SSH) Flag() eventmanager.EventMode {
	return eventmanager.Realtime
}

func (SSH) Immediately() bool { return false }

// Get and parse SSH log
// 2022-03-22: for now, performance is under improved.
func (SSH) Run(sandbox SDK.ISandbox, sig chan struct{}) (err error) {
	// Redhat or Fedora Core: /var/log/secure
	// Mandrake, FreeBSD, OpenBSD or Debian: /var/log/auth.log
	// Format: Month Day Time Hostname ProcessName[ActionID] Message
	var (
		watcher *fsnotify.Watcher
		path    string
		// record the last size
		lastSize int64
		fs       os.FileInfo
	)
	// choose file by platformfamily
	// BUG: centos exit
	// In centos, it's in /var/log/messages
	switch _platformfamily {
	case "fedora", "redhat", "rhel":
		path = "/var/log/secure"
	default:
		path = "/var/log/auth.log"
	}
	// init the size
	if fs, err = os.Stat(path); err != nil {
		zap.S().Error(err)
		return
	}
	lastSize = fs.Size()
	// start a watcher
	if watcher, err = fsnotify.NewWatcher(); err != nil {
		zap.S().Error(err)
		return
	}
	defer watcher.Close()
	watcher.Add(path)
	// start to read
	file, err := os.Open(path)
	if err != nil {
		zap.S().Error(err)
		return
	}
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()
	// only for write now, evaluate
	for {
		select {
		case event := <-watcher.Events:
			switch event.Op {
			case fsnotify.Write:
				fs, err = os.Stat(event.Name)
				if err != nil {
					zap.S().Errorf("stat file %s failed: %s", event.Name, err.Error())
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
				// 0 = Beginning of file
				// 1 = Current position
				// 2 = End of file
				file.Seek(lastSize, 0)
				s := bufio.NewScanner(io.LimitReader(file, 1024*1024))
				// parse here
				for s.Scan() {
					// some situations that we need to audit
					// 1. Session opened - Success Login
					// 2. Received disconnect from - Port Scanner
					// 3. Invalid user - Failed Login
					// enhanced with the port scanner
					fields := strings.Fields(s.Text())
					if len(fields) <= 6 {
						continue
					}
					timeNow, err := time.Parse(time.Stamp, strings.Join(fields[:3], " "))
					if err != nil {
						continue
					}
					timeNow = timeNow.AddDate(time.Now().Year(), 0, 0)
					sshlog := make(map[string]string, 5)
					// failed password
					// Mar 22 00:21:51 localhost sshd[3246569]: Accepted password for root from xx.xx.xx.xx port 49186 ssh2
					// Mar 22 00:21:29 localhost sshd[3246477]: Failed password for invalid user Craft from xx.xx.xx.xx port 44983 ssh2
					if fields[6] != "password" {
						continue
					}
					switch len(fields) {
					case 14:
						switch fields[5] {
						case "Failed", "Accepted":
							sshlog["reason"] = strings.ToLower(fields[5])
						}
						sshlog["timestamp"] = strconv.FormatInt(timeNow.Unix(), 10)
						sshlog["username"] = fields[8]
						sshlog["ip"] = fields[10]
						sshlog["port"] = fields[12]
						rec := &protocol.Record{
							DataType:  3003,
							Timestamp: time.Now().Unix(),
							Data: &protocol.Payload{
								Fields: sshlog,
							},
						}
						sandbox.SendRecord(rec)
					// This is for the invalid user
					case 16:
						sshlog["reason"] = "failed"
						sshlog["timestamp"] = strconv.FormatInt(timeNow.Unix(), 10)
						sshlog["username"] = fields[10]
						sshlog["ip"] = fields[12]
						sshlog["port"] = fields[14]
						rec := &protocol.Record{
							DataType:  3003,
							Timestamp: time.Now().Unix(),
							Data: &protocol.Payload{
								Fields: sshlog,
							},
						}
						sandbox.SendRecord(rec)
					}
				}
				// before we exit
				lastSize = fs.Size()
			}
		case err = <-watcher.Errors:
			zap.S().Errorf("ssh watcher failed: %s", err.Error())
			return
		case <-sandbox.Done():
			return
		case <-sig:
			return
		case <-timer.C:
			timer.Reset(10 * time.Second)
		}
	}
}
