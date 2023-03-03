package database

import (
	"collector/cache/process"
	"collector/event/apps"
	"path/filepath"
	"regexp"
	"strings"
)

type ElasticSearch struct {
	version    string
	reg        *regexp.Regexp
	regVersion *regexp.Regexp
}

func (ElasticSearch) Name() string { return "elasticsearch" }

func (ElasticSearch) Type() string { return "database" }

func (e ElasticSearch) Version() string { return e.version }

func (e *ElasticSearch) Match(p *process.Process) bool {
	if p.Name != "java" {
		return false
	}
	if e.reg == nil {
		e.reg = regexp.MustCompile(` org\.elasticsearch\.bootstrap\.Elasticsearch( )`)
	}
	if s := e.reg.FindString(p.Argv); s == "" {
		return false
	}
	return true
}

func (e *ElasticSearch) Run(p *process.Process) (mapping map[string]string, err error) {
	e.version = ""
	if e.regVersion == nil {
		e.regVersion = regexp.MustCompile(`elasticsearch-(\d+\.)+(\d+)\.jar`)
	}
	if fds, err := p.Fds(); err == nil {
		for _, fd := range fds {
			if filepath.Ext(fd) != ".jar" {
				continue
			}
			if s := e.regVersion.FindString(filepath.Base(fd)); s != "" {
				e.version = strings.TrimRight(strings.TrimPrefix(s, "elasticsearch-"), ".jar")
			}
		}
	}
	return
}

func init() { apps.Regist(&ElasticSearch{}) }
