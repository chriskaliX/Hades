package event

import (
	"bufio"
	"collector/share"
	"context"
	"crypto/md5"
	"errors"
	"io"
	"io/fs"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bytedance/sonic"
	"github.com/chriskaliX/SDK/transport/protocol"
	"github.com/fsnotify/fsnotify"
	lru "github.com/hashicorp/golang-lru"
	"go.uber.org/zap"
)

var (
	CronSearchDirs = []string{
		"/etc/cron.d",
		"/var/spool/cron/",
		"/var/spool/cron/crontabs",
	}
)

const CRON_DATATYPE = 2001

var _ Event = (*Crontab)(nil)

type Cron struct {
	Minute     string `json:"minute"`
	Hour       string `json:"hour"`
	DayOfMonth string `json:"day_of_month"`
	Month      string `json:"month"`
	DayOfWeek  string `json:"day_of_week"`
	User       string `json:"user"`
	Command    string `json:"command"`
	Path       string `json:"path"`
}

type Crontab struct {
	cronCache *lru.Cache
	BasicEvent
}

func (c *Crontab) Init(name string) (err error) {
	c.cronCache, _ = lru.New(240)
	c.BasicEvent.Init(name)
	return
}

func (Crontab) DataType() int {
	return CRON_DATATYPE
}

func (Crontab) String() string {
	return "cron"
}

// https://github.com/osquery/osquery/blob/d2be385d71f401c85872f00d479df8f499164c5a/tests/integration/tables/crontab.cpp
/*
	const std::string kSystemCron = "/etc/crontab";

	const std::vector<std::string> kCronSearchDirs = {
		"/etc/cron.d/", // system all
		"/var/at/tabs/", // user mac:lion
		"/var/spool/cron/", // user linux:centos
		"/var/spool/cron/crontabs/", // user linux:debian
	};
	https://github.com/osquery/osquery/blob/2c2b85cbd25a381eb0973017427928e5691c4431/osquery/tables/system/posix/crontab.cpp
*/
func Parse(withUser bool, path string, file *os.File) (crons []Cron) {
	r := bufio.NewScanner(io.LimitReader(file, 1024*1024))
	for r.Scan() {
		line := r.Text()
		// skip empty and null line
		if line != "" && strings.TrimSpace(line)[0] == '#' {
			continue
		} else if strings.Contains(line, "@reboot") {
			fields := strings.Fields(line)
			cron := Cron{
				Minute:     "@reboot",
				Hour:       "@reboot",
				DayOfMonth: "@reboot",
				Month:      "@reboot",
				DayOfWeek:  "@reboot",
				Path:       path,
			}
			if len(fields) >= 2 {
				if withUser {
					cron.User = file.Name()
					cron.Command = strings.Join(fields[1:], " ")
				} else if len(fields) >= 3 {
					cron.User = fields[1]
					cron.Command = strings.Join(fields[2:], " ")
				}
			}
			crons = append(crons, cron)
		} else {
			fields := strings.Fields(line)
			if len(fields) >= 6 {
				cron := Cron{
					Minute:     fields[0],
					Hour:       fields[1],
					DayOfMonth: fields[2],
					Month:      fields[3],
					DayOfWeek:  fields[4],
					Path:       path,
				}
				if withUser {
					cron.User = filepath.Base(file.Name())
					cron.Command = strings.Join(fields[5:], " ")
				} else if len(fields) >= 7 {
					cron.User = fields[5]
					cron.Command = strings.Join(fields[6:], " ")
				}
				crons = append(crons, cron)
				// flag, _ := cronCache.ContainsOrAdd(md5.Sum([]byte(cron.Command)), true)
			}
		}
	}
	return
}

func GetCron() (crons []Cron, err error) {
	for _, dir := range CronSearchDirs {
		err := filepath.Walk(dir, func(path string, info fs.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.Mode().IsRegular() {
				f, err := os.Open(path)
				if err != nil {
					return nil
				}
				flag := strings.HasPrefix(path, "/var/spool/cron")
				crons = append(crons, Parse(flag, path, f)...)
				f.Close()
			}
			return nil
		})
		if err != nil {
			continue
		}
	}

	if f, e := os.Open("/etc/crontab"); e == nil {
		crons = append(crons, Parse(false, "/etc/crontab", f)...)
		f.Close()
	}

	if len(crons) == 0 {
		err = errors.New("crontab is empty")
	}
	return
}

func (c Crontab) RunSync(ctx context.Context) (err error) {
	init := true
	ticker := time.NewTicker(time.Second * time.Duration(rand.Intn(6)+1))

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

	for {
		select {
		case <-ticker.C:
			// skip if not SnapShot
			if !init && c.Type() != Snapshot {
				continue
			}
			// only first time
			if init {
				ticker.Reset(time.Hour)
				init = false
			}
			if crons, err := GetCron(); err == nil {
				for _, cron := range crons {
					c.cronCache.Add(md5.Sum([]byte(cron.Command)), true)
				}
				if data, err := sonic.MarshalString(crons); err == nil {
					rawdata := make(map[string]string)
					rawdata["data"] = data
				}
			}
		case event := <-watcher.Events:
			if event.Op != fsnotify.Create && event.Op != fsnotify.Write && event.Op != fsnotify.Chmod {
				continue
			}
			fs, err := os.Stat(event.Name)
			if err != nil {
				zap.S().Error(err)
			}
			if !fs.Mode().IsRegular() {
				continue
			}
			f, err := os.Open(event.Name)
			flag := strings.HasPrefix(event.Name, "/var/spool/cron")
			if crons := Parse(flag, event.Name, f); err == nil {
				tmp := crons[:0]
				for _, cron := range crons {
					sum := md5.Sum([]byte(cron.Command))
					flag, _ := c.cronCache.ContainsOrAdd(sum, true)
					if !flag {
						tmp = append(tmp, cron)
					}
				}
				if len(tmp) > 0 {
					if data, err := sonic.Marshal(tmp); err == nil {
						rawdata := make(map[string]string)
						rawdata["data"] = string(data)
						rec := &protocol.Record{
							DataType:  2001,
							Timestamp: time.Now().Unix(),
							Data: &protocol.Payload{
								Fields: rawdata,
							},
						}
						share.Sandbox.SendRecord(rec)
					}
				}
			}
			f.Close()
		case <-ctx.Done():
			return
		}
	}
}

func init() {
	RegistEvent(&Crontab{})
}
