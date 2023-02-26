package bigdata

import (
	"collector/cache/process"
	"collector/event/apps"
	"regexp"
)

type Kafka struct {
	version string
	reg     *regexp.Regexp
	regDir  *regexp.Regexp
}

func (Kafka) Name() string { return "kafka" }

func (Kafka) Type() string { return "bigdata" }

func (k Kafka) Version() string { return k.version }

func (k *Kafka) Match(p *process.Process) bool {
	if p.Name != "java" {
		return false
	}
	if k.reg == nil {
		k.reg = regexp.MustCompile(` kafka.Kafka`)
	}
	if s := k.reg.FindString(p.Argv); s == "" {
		return false
	}
	return true
}

// may not accurate
func (k *Kafka) Run(p *process.Process) (m map[string]string, err error) {
	return
}

func init() { apps.Regist(&Kafka{}) }
