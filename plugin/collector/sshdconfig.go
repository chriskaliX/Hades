package main

import (
	"bufio"
	"collector/cache"
	"collector/share"
	"context"
	"fmt"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/chriskaliX/plugin"
)

const (
	userSshConfig   = ".ssh/config"
	systemSshConfig = "/etc/ssh/sshd_config"
)

// 参考 https://github.com/osquery/osquery/blob/d2be385d71f401c85872f00d479df8f499164c5a/osquery/tables/system/ssh_configs.cpp
// 在我的机器上还有一个 Include /etc/ssh/sshd_config.d/*.conf
func GetSshdConfig() (config map[string]string, err error) {
	var (
		file *os.File
		scan *bufio.Scanner
	)
	if file, err = os.Open(systemSshConfig); err != nil {
		return
	}
	defer file.Close()
	config = make(map[string]string, 2)
	config["pubkey_authentication"] = "yes"
	config["passwd_authentication"] = "yes"

	scan = bufio.NewScanner(io.LimitReader(file, 1024*1024))
	for scan.Scan() {
		fields := strings.Fields(scan.Text())
		if len(fields) != 2 {
			continue
		}
		switch strings.TrimSpace(fields[0]) {
		case "PasswordAuthentication":
			config["passwd_authentication"] = strings.TrimSpace(fields[1])
		case "PubkeyAuthentication":
			config["pubkey_authentication"] = strings.TrimSpace(fields[1])
		}
	}
	return
}

type SshConfig struct {
	UID      uint32
	Username string
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

// unfinished
func analyzeConfig(fpath string) (config map[string]string, err error) {
	var (
		file  *os.File
		scan  *bufio.Scanner
		block string
	)
	if file, err = os.Open(systemSshConfig); err != nil {
		return
	}
	defer file.Close()
	config = make(map[string]string, 2)
	// Default
	config["pubkey_authentication"] = "yes"
	config["passwd_authentication"] = "yes"
	scan = bufio.NewScanner(io.LimitReader(file, 1024*1024))
	for scan.Scan() {
		text := strings.TrimSpace(scan.Text())
		text = strings.ToLower(text)
		if len(text) == 0 || text[:1] == "#" {
			continue
		}
		// In Elkeid, only PasswordAuthentication & PubkeyAuthentication is added. But in osquery,
		// all the configurations are added, I think it's better for future usage.
		// Also, according to https://www.cyberciti.biz/faq/create-ssh-config-file-on-linux-unix/
		// "=" is also supported, which is ignored in Elkeid. Just a tidy problem, which can be used
		// in avoiding detection of ssh_config.
		// Data structure of osquery: https://osquery.io/schema/5.1.0/#ssh_configs
		if strings.HasPrefix(text, "host ") || strings.HasPrefix(text, "match ") {
			block = text
		}
		fmt.Println(block)
		// get PasswordAuthentication & PubkeyAuthentication Only
		// fields := strings.Fields(text)
		// if len(fields) == 2 {
		// 	switch strings.TrimSpace(fields[0]) {
		// 	case "PasswordAuthentication":
		// 		config["passwd_authentication"] = strings.TrimSpace(fields[1])
		// 	case "PubkeyAuthentication":
		// 		config["pubkey_authentication"] = strings.TrimSpace(fields[1])
		// 	}
		// }
	}
	return
}

func SshdConfigJob(ctx context.Context) {
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
			if sshd, err := GetSshdConfig(); err == nil {
				if data, err := share.Marshal(sshd); err == nil {
					rawdata := make(map[string]string, 1)
					rawdata["data"] = string(data)
					rec := &plugin.Record{
						DataType:  3002,
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
