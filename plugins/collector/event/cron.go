package event

import (
	"bufio"
	"collector/eventmanager"
	"collector/utils"
	"crypto/md5"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/chriskaliX/SDK"
	"github.com/chriskaliX/SDK/transport/protocol"
	lru "github.com/hashicorp/golang-lru"
	"github.com/mitchellh/mapstructure"
)

var (
	CronSearchDirs = []string{
		"/etc/cron.d",
		"/var/spool/cron/",
		"/var/spool/cron/crontabs",
	}
)

const CRON_DATATYPE = 2001

var _ eventmanager.IEvent = (*Crontab)(nil)

type Cron struct {
	Minute     string `mapstructure:"minute"`
	Hour       string `mapstructure:"hour"`
	DayOfMonth string `mapstructure:"day_of_month"`
	Month      string `mapstructure:"month"`
	DayOfWeek  string `mapstructure:"day_of_week"`
	User       string `mapstructure:"user"`
	Command    string `mapstructure:"command"`
	Path       string `mapstructure:"path"`
}

type Crontab struct {
	cronCache *lru.Cache
}

func (Crontab) DataType() int { return CRON_DATATYPE }

func (Crontab) DataTypeSync() int { return 3001 }

func (n *Crontab) Flag() eventmanager.EventMode { return eventmanager.Periodic }

func (Crontab) Name() string { return "cron" }

func (Crontab) Immediately() bool { return false }

// https://github.com/osquery/osquery/blob/d2be385d71f401c85872f00d479df8f499164c5a/tests/integration/tables/crontab.cpp
// const std::string kSystemCron = "/etc/crontab";

// const std::vector<std::string> kCronSearchDirs = {
// 	"/etc/cron.d/", // system all
// 	"/var/at/tabs/", // user mac:lion
// 	"/var/spool/cron/", // user linux:centos
// 	"/var/spool/cron/crontabs/", // user linux:debian
// };
// https://github.com/osquery/osquery/blob/2c2b85cbd25a381eb0973017427928e5691c4431/osquery/tables/system/posix/crontab.cpp
func (c *Crontab) parse(withUser bool, path string, file *os.File) (crons []Cron) {
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
			}
		}
	}
	return
}

func (c *Crontab) GetCron() (crons []Cron, err error) {
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
				crons = append(crons, c.parse(flag, path, f)...)
				f.Close()
			}
			return nil
		})
		if err != nil {
			continue
		}
	}

	if f, e := os.Open("/etc/crontab"); e == nil {
		crons = append(crons, c.parse(false, "/etc/crontab", f)...)
		f.Close()
	}

	if len(crons) == 0 {
		err = errors.New("crontab is empty")
	}
	return
}

func (c *Crontab) Run(s SDK.ISandbox, sig chan struct{}) (err error) {
	if c.cronCache == nil {
		c.cronCache, _ = lru.New(240)
	}
	hash := utils.Hash()
	// get crons if it start
	if crons, err := c.GetCron(); err == nil {
		for _, cron := range crons {
			c.cronCache.Add(md5.Sum([]byte(cron.Command)), true)
		}
		for _, cron := range crons {
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
	return nil
}
