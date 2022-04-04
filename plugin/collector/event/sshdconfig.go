package event

import (
	"bufio"
	"collector/share"
	"io"
	"os"
	"strings"
	"unicode"
)

const (
	sshdConfig    = "/etc/ssh/sshd_config"
	SSHD_DATATYPE = 3002
)

var _ Event = (*Sshd)(nil)

type Sshd struct {
	BasicEvent
}

func (Sshd) DataType() int {
	return SSHD_DATATYPE
}

func (Sshd) String() string {
	return "sshdconfig"
}

func (Sshd) Run() (result map[string]string, err error) {
	var (
		file *os.File
		scan *bufio.Scanner
	)
	if file, err = os.Open(sshdConfig); err != nil {
		return
	}
	defer file.Close()
	config := make(map[string]string, 2)
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
	// set key+value as a primary key
	for key, value := range config {
		result[key+value], err = share.MarshalString(map[string]string{
			key: value,
		})
		// TODO: process here
		if err != nil {
		}
	}
	return
}
