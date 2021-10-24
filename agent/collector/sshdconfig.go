package collector

import (
	"agent/global"
	"bufio"
	"context"
	"io"
	"math/rand"
	"os"
	"strconv"
	"strings"
	"time"
)

// Elkeid 只有 system 级别的 Config, User 级别没有获取...不对, 我看错了
// 参考 https://github.com/osquery/osquery/blob/d2be385d71f401c85872f00d479df8f499164c5a/osquery/tables/system/ssh_configs.cpp
// 在我的机器上还有一个 Include /etc/ssh/sshd_config.d/*.conf

func GetSshdConfig() (config map[string]string, err error) {
	var f *os.File
	f, err = os.Open("/etc/ssh/sshd_config")
	if err != nil {
		return
	}

	defer f.Close()
	config = make(map[string]string)
	config["pubkey_authentication"] = "yes"
	config["passwd_authentication"] = "yes"
	s := bufio.NewScanner(io.LimitReader(f, 1024*1024))
	for s.Scan() {
		fields := strings.Fields(s.Text())
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
			sshd, err := GetSshdConfig()
			if err == nil {
				sshd["time"] = strconv.FormatInt(time.Now().Unix(), 10)
				sshd["data_type"] = "3002"
				global.UploadChannel <- sshd
			}
		case <-ctx.Done():
			return
		}
	}
}
