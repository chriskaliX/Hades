package event

import (
	"collector/eventmanager"
	"collector/utils"
	"crypto/md5"
	"os"
	"strings"
	"time"

	"github.com/chriskaliX/SDK"
	"github.com/chriskaliX/SDK/transport/protocol"
	"github.com/fsnotify/fsnotify"
	lru "github.com/hashicorp/golang-lru"
	"github.com/mitchellh/mapstructure"
	"go.uber.org/zap"
)

type CronWatcher struct {
	cron Crontab
}

func (CronWatcher) DataType() int { return 3001 }

func (CronWatcher) Flag() eventmanager.EventMode { return eventmanager.Realtime }

func (CronWatcher) Name() string { return "cron_watcher" }

func (CronWatcher) Immediately() bool { return false }

func (c *CronWatcher) Run(s SDK.ISandbox, sig chan struct{}) (err error) {
	hash := utils.Hash()
	if c.cron.cronCache == nil {
		c.cron.cronCache, _ = lru.New(240)
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		zap.S().Error(err)
		return
	}
	defer watcher.Close()
	for _, path := range CronSearchDirs {
		if err = watcher.Add(path); err != nil {
			continue
		}
	}
	watcher.Add("/etc/crontab")
	timer := time.NewTicker(3 * time.Second)
	defer timer.Stop()

	for {
		timer.Reset(3 * time.Second)
		select {
		case <-s.Done():
			return
		case <-sig:
			return
		case <-timer.C:
			continue
		case event := <-watcher.Events:
			if event.Op != fsnotify.Create && event.Op != fsnotify.Write && event.Op != fsnotify.Chmod {
				continue
			}
			fs, err := os.Stat(event.Name)
			if err != nil {
				zap.S().Errorf("stat file %s failed: %s", event.Name, err.Error())
			}
			if !fs.Mode().IsRegular() {
				continue
			}
			f, err := os.Open(event.Name)
			flag := strings.HasPrefix(event.Name, "/var/spool/cron")
			if crons := c.cron.parse(flag, event.Name, f); err == nil {
				tmp := crons[:0]
				for _, cron := range crons {
					sum := md5.Sum([]byte(cron.Command))
					flag, _ := c.cron.cronCache.ContainsOrAdd(sum, true)
					if !flag {
						tmp = append(tmp, cron)
					}
				}
				if len(tmp) > 0 {
					for _, cron := range tmp {
						rec := &protocol.Record{
							DataType:  int32(c.DataType()),
							Timestamp: time.Now().Unix(),
							Data: &protocol.Payload{
								Fields: make(map[string]string, 9),
							},
						}
						mapstructure.Decode(&cron, &rec.Data.Fields)
						rec.Data.Fields["package_seq"] = hash
						s.SendRecord(rec)
					}
				}
			}
			f.Close()
		}
	}
}
