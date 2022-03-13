// done
package main

import (
	"bufio"
	"collector/cache"
	"collector/share"
	"context"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/chriskaliX/plugin"
	"github.com/jinzhu/copier"
)

const (
	userSshConfig   = ".ssh/config"
	systemSshConfig = "/etc/ssh/ssh_config"
)

type SshConfig struct {
	Uid      string
	Block    string
	Option   map[string]string
	Filepath string
}

// Depend on usercache, execute after GetUser
func getSshConfigPath() (configs map[uint32]string) {
	users := cache.DefaultUserCache.GetUsers()
	for _, user := range users {
		configs[user.UID] = filepath.Join(user.HomeDir, userSshConfig)
	}
	return
}

// Reference: https://github.com/osquery/osquery/blob/d2be385d71f401c85872f00d479df8f499164c5a/osquery/tables/system/ssh_configs.cpp
func getSshConfig(uid string, path string) (configs []SshConfig, err error) {
	var (
		file   *os.File
		scan   *bufio.Scanner
		config = SshConfig{
			Option: make(map[string]string),
		}
		first = true
	)
	if file, err = os.Open(path); err != nil {
		return
	}
	defer file.Close()
	scan = bufio.NewScanner(io.LimitReader(file, 16834))
	for scan.Scan() {
		text := strings.TrimSpace(scan.Text())
		text = strings.ToLower(text)
		if len(text) == 0 || text[0] == '#' {
			continue
		}
		if strings.HasPrefix(text, "host ") || strings.HasPrefix(text, "match ") {
			if !first {
				// DeepCopy
				tmpConfig := SshConfig{}
				if err := copier.Copy(&config, &tmpConfig); err == nil {
					configs = append(configs, tmpConfig)
				}
				// init
				config = SshConfig{
					Option: make(map[string]string),
				}
			} else {
				first = false
			}
			config.Block = text
			config.Filepath = path
			config.Uid = uid
		} else {
			// don't know it's ` ` or `=`, try everytime
			spaceIndex := strings.Index(text, " ")
			equalIndex := strings.Index(text, "=")
			if spaceIndex == -1 && equalIndex == -1 {
				config.Option[text] = ""
			} else if spaceIndex == -1 {
				config.Option[text[:equalIndex]] = text[equalIndex+1:]
			} else {
				config.Option[text[:spaceIndex]] = text[spaceIndex+1:]
			}
		}
	}
	configs = append(configs, config)
	return
}

func SshConfigJob(ctx context.Context) {
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
			// get user configuration
			configPath := getSshConfigPath()
			configs := make([]SshConfig, 0)
			for uid, path := range configPath {
				if config, err := getSshConfig(string(rune(uid)), path); err == nil {
					configs = append(configs, config...)
				}
			}
			// get system configuration
			if config, err := getSshConfig("0", systemSshConfig); err == nil {
				configs = append(configs, config...)
			}
			// upload
			if len(configs) > 0 {
				if data, err := share.Marshal(configs); err == nil {
					rawdata := make(map[string]string, 1)
					rawdata["data"] = string(data)
					rec := &plugin.Record{
						DataType:  3005,
						Timestamp: time.Now().Unix(),
						Data: &plugin.Payload{
							Fields: rawdata,
						},
					}
					share.Client.SendRecord(rec)
				}
			}
		case <-ctx.Done():
			return
		}
	}
}
