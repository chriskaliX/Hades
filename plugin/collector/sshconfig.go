package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

const (
	userSshConfig   = ".ssh/config"
	systemSshConfig = "/etc/ssh/sshd_config"
)

type SshConfig struct {
	Uid      string
	Block    string
	option   map[string]string
	Filepath string
}

// unfinished
// Reference: https://github.com/osquery/osquery/blob/d2be385d71f401c85872f00d479df8f499164c5a/osquery/tables/system/ssh_configs.cpp
func getSshConfig(path string) (config map[string]string, err error) {
	var (
		file  *os.File
		scan  *bufio.Scanner
		block string
	)
	if file, err = os.Open(path); err != nil {
		return
	}
	defer file.Close()

	for scan.Scan() {
		text := strings.TrimSpace(scan.Text())
		text = strings.ToLower(text)
		if len(text) == 0 || text[0] == '#' {
			continue
		}
		if strings.HasPrefix(text, "host ") || strings.HasPrefix(text, "match ") {
			block = text
			fmt.Println(block)
		} else {

		}
	}
	return
}
