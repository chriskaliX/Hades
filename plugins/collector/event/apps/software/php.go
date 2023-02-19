package software

import (
	"collector/cache/process"
	"collector/event/apps"
	"errors"
	"regexp"
	"strings"
)

type PHP struct {
	version string
	r       *regexp.Regexp
}

func (PHP) Name() string { return "php" }

func (PHP) Type() string { return "software" }

func (p PHP) Version() string { return p.version }

// only fpm
func (PHP) Match(p *process.Process) bool { return p.Name == "php-fpm" }

func (p *PHP) Run(proc *process.Process) (m map[string]string, err error) {
	if p.r == nil {
		p.r = regexp.MustCompile(`PHP\s(\d+\.)+\d+`)
	}
	result, err := apps.Execute(proc, "-v")
	if err != nil {
		return nil, err
	}
	str := p.r.FindString(result)
	if str == "" {
		err = errors.New("version not found")
		return
	}
	p.version = strings.TrimPrefix(str, "PHP ")
	return
}

func init() {
	apps.Regist(&PHP{})
}
