package main

import (
	"bufio"
	"collector/share"
	"context"
	"errors"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/chriskaliX/plugin"
)

// 参考字节的, 以 osquery 的为标准开发

const (
	yumConfig              = "/etc/yum.conf"
	yumReposDir            = "/etc/yum.repos.d"
	yumConfigFileExtension = ".repo"
)

// map 过大?, scanner 已经有一个 Limit, 需要从数量上限制一下
func yum() (config map[string]string, err error) {
	config = make(map[string]string)

	sourcesList := []string{}
	files := getfiles(yumReposDir)
	files = append(files, yumConfig)
	// 只取 100 个, 防止过大, 有些 resp 机器?
	// 这里需要看一下, 有影响的会是内存, 速度
	// if len(files) >= 100 {
	// 	files = files[:99]
	// }

	for _, file := range files {
		if f, err := os.Open(file); err == nil {
			s := bufio.NewScanner(io.LimitReader(f, 1024*1024))
			for s.Scan() {
				fields := strings.Split(s.Text(), "=")
				if len(fields) == 2 && strings.TrimSpace(fields[0]) == "baseurl" {
					sourcesList = append(sourcesList, strings.TrimSpace(fields[1]))
				}
			}
			f.Close()
		}
	}

	if len(sourcesList) > 0 {
		if encodedsource, err := share.Marshal(sourcesList); err == nil {
			config["sources"] = string(encodedsource)
		}
	} else {
		err = errors.New("yum config is empty")
	}
	return
}

// 可能的性能问题? 在下面创建无数个, 导致内存占用
// 另外 walk 看一下 \ / 问题
func getfiles(pth string) (files []string) {
	files = []string{}
	filepath.Walk(pth, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Mode().IsRegular() && strings.HasPrefix(info.Name(), yumConfigFileExtension) {
			files = append(files, path)
		}
		return nil
	})
	return files
}

func GetYumJob(ctx context.Context) {
	init := true
	ticker := time.NewTicker(time.Until(time.Date(time.Now().Year(), time.Now().Month(), time.Now().Day()+1, rand.Intn(6), rand.Intn(60), rand.Intn(60), 0, time.Now().Location())))
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if init {
				ticker.Reset(time.Hour * 24)
				init = false
			}
			yum, err := yum()
			if err == nil {
				yum["data_type"] = "3003"
				rec := &plugin.Record{
					DataType:  3003,
					Timestamp: time.Now().Unix(),
					Data: &plugin.Payload{
						Fields: yum,
					},
				}
				share.Client.SendRecord(rec)
			}
		case <-ctx.Done():
			return
		}
	}
}
