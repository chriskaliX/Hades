package event

import (
	"bufio"
	"collector/cache/user"
	"collector/eventmanager"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/bytedance/sonic"
	"github.com/chriskaliX/SDK"
	"github.com/chriskaliX/SDK/transport/protocol"
)

const (
	userSshConfig      = ".ssh/config"
	systemSshConfig    = "/etc/ssh/ssh_config"
	SSHCONFIG_DATATYPE = 3005
)

var _ eventmanager.IEvent = (*SshConfig)(nil)

type SshConfig struct {
	// check if first time, pay attention to set true
	firstTime bool
}

func (SshConfig) DataType() int {
	return SSHCONFIG_DATATYPE
}

func (SshConfig) Name() string {
	return "sshconfig"
}

func (n *SshConfig) Flag() int { return eventmanager.Periodic }

func (SshConfig) Immediately() bool { return false }

func (s *SshConfig) Run(sandbox SDK.ISandbox, sig chan struct{}) error {
	// get user configuration
	configPath := s.sshConfigPath()
	s.firstTime = true
	configs := make([]sshConfig, 0, 20)
	for uid, path := range configPath {
		if config, err := s.getSshConfig(strconv.Itoa(int(uid)), path); err == nil {
			configs = append(configs, config...)
		}
	}
	// get system configuration
	if config, err := s.getSshConfig("0", systemSshConfig); err == nil {
		configs = append(configs, config...)
	}
	data, err := sonic.MarshalString(configs)
	if err != nil {
		return err
	}
	rec := &protocol.Record{
		DataType: SSHCONFIG_DATATYPE,
		Data: &protocol.Payload{
			Fields: map[string]string{
				"data": data,
			},
		},
	}
	sandbox.SendRecord(rec)
	return nil
}

// Depend on usercache, execute after GetUser
func (SshConfig) sshConfigPath() (configs map[uint32]string) {
	configs = make(map[uint32]string)
	users := user.Cache.GetUsers()
	for _, user := range users {
		configs[user.UID] = filepath.Join(user.HomeDir, userSshConfig)
	}
	return
}

type sshConfig struct {
	Uid      string            `json:"uid"`
	Block    string            `json:"block"`
	Option   map[string]string `json:"option"`
	Filepath string            `json:"filepath"`
}

// Reference:
// https://github.com/osquery/osquery/blob/d2be385d71f401c85872f00d479df8f499164c5a/osquery/tables/system/ssh_configs.cpp
func (s *SshConfig) getSshConfig(uid string, path string) (configs []sshConfig, err error) {
	var (
		file   *os.File
		scan   *bufio.Scanner
		config = sshConfig{
			Option: make(map[string]string),
		}
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
		// if matches the host or match fields, start record configuration
		if strings.HasPrefix(text, "host ") || strings.HasPrefix(text, "match ") {
			if s.firstTime {
				s.firstTime = false
			} else {
				configs = append(configs, config)
			}
			config = sshConfig{
				Option: make(map[string]string),
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
