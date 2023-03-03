package bigdata

import (
	"collector/cache/process"
	"collector/event/apps"
	"path/filepath"
	"regexp"
	"strings"
)

type Kafka struct {
	version    string
	reg        *regexp.Regexp
	regVersion *regexp.Regexp
}

func (Kafka) Name() string { return "kafka" }

func (Kafka) Type() string { return "bigdata" }

func (k Kafka) Version() string { return k.version }

func (k *Kafka) Match(p *process.Process) bool {
	if p.Name != "java" {
		return false
	}
	if k.reg == nil {
		k.reg = regexp.MustCompile(` kafka.Kafka( )`)
	}
	if s := k.reg.FindString(p.Argv); s == "" {
		return false
	}
	return true
}

// Check the version by the jar name, is there any better way to do this?
func (k *Kafka) Run(p *process.Process) (m map[string]string, err error) {
	k.version = ""
	if k.regVersion == nil {
		k.regVersion = regexp.MustCompile(`kafka_(\d+\.)+(\d+)-(\d+\.)+(\d+)\.jar`)
	}
	if fds, err := p.Fds(); err == nil {
		for _, fd := range fds {
			if filepath.Ext(fd) != ".jar" {
				continue
			}
			if s := k.regVersion.FindString(filepath.Base(fd)); s != "" {
				k.version = strings.Split(strings.TrimPrefix(s, "kafka_"), "-")[0]
			}
		}
	}
	return
}

func init() { apps.Regist(&Kafka{}) }
