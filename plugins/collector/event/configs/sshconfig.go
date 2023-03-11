package configs

import (
	"bufio"
	"collector/cache/user"
	"collector/eventmanager"
	"collector/utils"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/bytedance/sonic"
	"github.com/chriskaliX/SDK"
	"github.com/chriskaliX/SDK/transport/protocol"
	"github.com/mitchellh/mapstructure"
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

func (SshConfig) DataType() int { return SSHCONFIG_DATATYPE }

func (SshConfig) Name() string { return "sshconfig" }

func (n *SshConfig) Flag() eventmanager.EventMode { return eventmanager.Periodic }

func (SshConfig) Immediately() bool { return false }

func (s *SshConfig) Run(sandbox SDK.ISandbox, sig chan struct{}) error {
	hash := utils.Hash()
	// get user configuration
	configPath := s.sshConfigPath()
	s.firstTime = true
	configs := make([]sshConfig, 0, 20)
	for uid, path := range configPath {
		if config, err := s.getSshConfig(uid, path); err == nil {
			configs = append(configs, config...)
		}
	}
	// get system configuration
	if config, err := s.getSshConfig("0", systemSshConfig); err == nil {
		configs = append(configs, config...)
	}

	for _, config := range configs {
		rec := &protocol.Record{
			DataType: int32(s.DataType()),
			Data: &protocol.Payload{
				Fields: make(map[string]string, 5),
			},
		}
		mapstructure.Decode(&config, &rec.Data.Fields)
		rec.Data.Fields["package_seq"] = hash
		sandbox.SendRecord(rec)
	}
	return nil
}

// Depend on usercache, execute after GetUser
func (SshConfig) sshConfigPath() (configs map[string]string) {
	configs = make(map[string]string)
	users := user.Cache.GetUsers()
	for _, user := range users {
		configs[user.UID] = filepath.Join(user.HomeDir, userSshConfig)
	}
	return
}

type sshConfig struct {
	Uid      string `json:"uid" mapstructure:"uid"`
	Block    string `json:"block" mapstructure:"block"`
	Option   string `mapstructure:"option"`
	Filepath string `json:"filepath" mapstructure:"filepath"`
	option   map[string]string
}

// Reference:
// https://github.com/osquery/osquery/blob/d2be385d71f401c85872f00d479df8f499164c5a/osquery/tables/system/ssh_configs.cpp
func (s *SshConfig) getSshConfig(uid string, path string) (configs []sshConfig, err error) {
	var (
		file   *os.File
		scan   *bufio.Scanner
		config = sshConfig{
			option: make(map[string]string),
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
				option: make(map[string]string),
			}
			config.Block = text
			config.Filepath = path
			config.Uid = uid
		} else {
			// don't know it's ` ` or `=`, try everytime
			spaceIndex := strings.Index(text, " ")
			equalIndex := strings.Index(text, "=")
			if spaceIndex == -1 && equalIndex == -1 {
				config.option[text] = ""
			} else if spaceIndex == -1 {
				config.option[text[:equalIndex]] = text[equalIndex+1:]
			} else {
				config.option[text[:spaceIndex]] = text[spaceIndex+1:]
			}
		}
	}
	config.Option, _ = sonic.MarshalString(config.option)
	configs = append(configs, config)
	return
}

func init() { addEvent(&SshConfig{}) }
