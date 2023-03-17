package web

import (
	"collector/cache/process"
	"collector/event/apps"
	"regexp"
	"strings"
)

type Tengine struct {
	version  string
	reg      *regexp.Regexp
	regNginx *regexp.Regexp
}

func (Tengine) Name() string { return "tengine" }

func (Tengine) Type() string { return "web" }

func (t Tengine) Version() string { return t.version }

// pay attention to the name, maybe nginx
func (Tengine) Match(p *process.Process) bool { return p.Name == "tegine" }

func (t *Tengine) Run(p *process.Process) (m map[string]string, err error) {
	m = make(map[string]string)
	m["nginx_version"] = ""
	if t.reg == nil {
		t.reg = regexp.MustCompile(`Tengine\/(\d+\.)+\d+`)
		t.regNginx = regexp.MustCompile(`nginx\/(\d+\.)+\d+`)
	}
	result, err := apps.Execute(p, "-v")
	str := t.reg.FindString(result)
	if str == "" {
		err = apps.ErrVersionNotFound
		return
	}
	if s := t.regNginx.FindString(result); s != "" {
		m["nginx_version"] = strings.TrimPrefix(str, "nginx/")
	}
	t.version = strings.TrimPrefix(str, "Tengine/")
	return
}

func init() {
	apps.Regist(&Tengine{})
}
