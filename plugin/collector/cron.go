package main

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

	"github.com/chriskaliX/plugin"
	"github.com/fsnotify/fsnotify"
	lru "github.com/hashicorp/golang-lru"
	"go.uber.org/zap"
)

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

// 时间不是我们关注的, 执行了什么才是比较关键的, 所以我们取cmd的hash作为关键值来去重
var CronCache *lru.Cache

func init() {
	CronCache, _ = lru.New(240)
}

var CronSearchDirs = []string{
	"/etc/cron.d",
	"/var/spool/cron/",
	"/var/spool/cron/crontabs",
}

// https://github.com/osquery/osquery/blob/d2be385d71f401c85872f00d479df8f499164c5a/tests/integration/tables/crontab.cpp
// osquery 做了一个对于 Cron 的校验, 可能有个好处? 防止乱写 cron 然后上传
/*
	另外从代码里抠出来
	const std::string kSystemCron = "/etc/crontab";

	const std::vector<std::string> kCronSearchDirs = {
		"/etc/cron.d/", // system all
		"/var/at/tabs/", // user mac:lion
		"/var/spool/cron/", // user linux:centos
		"/var/spool/cron/crontabs/", // user linux:debian
	};
	具体源码在 https://github.com/osquery/osquery/blob/2c2b85cbd25a381eb0973017427928e5691c4431/osquery/tables/system/posix/crontab.cpp
*/
func Parse(withUser bool, path string, file *os.File) (crons []Cron) {
	r := bufio.NewScanner(io.LimitReader(file, 1024*1024))
	for r.Scan() {
		line := r.Text()
		// 过滤掉注释
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
				// flag, _ := CronCache.ContainsOrAdd(md5.Sum([]byte(cron.Command)), true)
			}
		}
	}
	return
}

// 看这里的时候发现了一个问题, 原先为 /etc/corn.d 改为 /etc/cron.d
// 另外字节这个写法, 有一点点疑惑。如果在 crontab 量大且经常变更的情况下, 一直调用这个
// 是否会产生很多日志? 学习一下osquery下如何diff的
// 看起来无法在客户端维护新增的 crontab, 只能在消费的时候做 diff 嘛? 感觉不合适

/*
	这个地方在 osquery 里是没有做递归的
	具体代码：
	QueryData genCronTabImpl(QueryContext& context, Logger& logger) {
		QueryData results;
		std::vector<std::string> file_list;

		file_list.push_back(kSystemCron);

		for (const auto& cron_dir : kCronSearchDirs) {
			osquery::listFilesInDirectory(cron_dir, file_list);
		}

		for (const auto& file_path : file_list) {
			auto lines = cronFromFile(file_path, logger);
			for (const auto& line : lines) {
			genCronLine(file_path, line, results);
			}
		}

		return results;
	}
	其中 listFilesInDirectory:
	Status listFilesInDirectory(const boost::filesystem::path& path,
                            std::vector<std::string>& results,
                            bool recursive = false);
	默认 false 了, 所以我们改用 fsnotify 吧, 反正 fsnotify 也是不支持递归的
*/

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
			zap.S().Error(err)
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

func CronJob(ctx context.Context) {
	init := true
	ticker := time.NewTicker(time.Second * time.Duration(rand.Intn(6)+1))

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		zap.S().Error(err)
	}
	defer watcher.Close()

	// 这个不会递归监听, 是否需要递归监听呢? - 看了 osquery 的, 看起来是不需要
	for _, path := range CronSearchDirs {
		if err = watcher.Add(path); err != nil {
			zap.S().Error(err)
		}
	}
	watcher.Add("/etc/crontab")

	for {
		select {
		case <-ticker.C:
			// 只有第一次的时候, 会刷进去 Cache, 其他时候都不会
			if init {
				ticker.Reset(time.Hour)
				init = false
			}
			if crons, err := GetCron(); err == nil {
				for _, cron := range crons {
					CronCache.Add(md5.Sum([]byte(cron.Command)), true)
				}
				if data, err := share.Marshal(crons); err == nil {
					rawdata := make(map[string]string)
					rawdata["data_type"] = "3001"
					rawdata["data"] = string(data)
					// rawdata["time"] = strconv.Itoa(int(global.Time))
					// global.UploadChannel <- rawdata
				}
			}
		case event := <-watcher.Events:
			if event.Op == fsnotify.Create || event.Op == fsnotify.Write || event.Op == fsnotify.Chmod {
				fs, err := os.Stat(event.Name)
				if err != nil {
					zap.S().Error(err)
				}
				if fs.Mode().IsRegular() {
					f, err := os.Open(event.Name)
					flag := strings.HasPrefix(event.Name, "/var/spool/cron")
					if crons := Parse(flag, event.Name, f); err == nil {
						tmp := crons[:0]
						for _, cron := range crons {
							sum := md5.Sum([]byte(cron.Command))
							flag, _ := CronCache.ContainsOrAdd(sum, true)
							if !flag {
								tmp = append(tmp, cron)
							}
						}
						if len(tmp) > 0 {
							if data, err := share.Marshal(tmp); err == nil {
								rawdata := make(map[string]string)
								rawdata["data"] = string(data)
								rec := &plugin.Record{
									DataType:  2001,
									Timestamp: time.Now().Unix(),
									Data: &plugin.Payload{
										Fields: rawdata,
									},
								}
								share.Client.SendRecord(rec)
							}
						}
					}
					f.Close()
				}
			}
		case <-ctx.Done():
			return
		}
	}
}
