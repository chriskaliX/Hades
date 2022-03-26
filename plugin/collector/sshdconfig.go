// done
package main

import (
	"bufio"
	"collector/share"
	"context"
	"io"
	"math/rand"
	"os"
	"strings"
	"time"
	"unicode"

	"github.com/chriskaliX/plugin"
)

const (
	sshdConfig = "/etc/ssh/sshd_config"
)

func GetSshdConfig() (config map[string]string, err error) {
	var (
		file *os.File
		scan *bufio.Scanner
	)
	if file, err = os.Open(sshdConfig); err != nil {
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
		// skip
		if len(text) == 0 || text[:1] == "#" {
			continue
		}
		// Also, according to https://www.cyberciti.biz/faq/create-ssh-config-file-on-linux-unix/
		// "=" is also supported, which is ignored in Elkeid. Just a tidy problem, which can be used
		// in avoiding detection of ssh_config.
		// get PasswordAuthentication & PubkeyAuthentication Only
		fields := strings.FieldsFunc(text, func(c rune) bool {
			return unicode.IsSpace(c) || c == '='
		})
		if len(fields) == 2 {
			switch strings.TrimSpace(fields[0]) {
			case "PasswordAuthentication":
				config["passwd_authentication"] = strings.TrimSpace(fields[1])
			case "PubkeyAuthentication":
				config["pubkey_authentication"] = strings.TrimSpace(fields[1])
			}
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
