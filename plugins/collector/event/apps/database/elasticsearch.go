package database

import (
	"collector/cache/process"
	"regexp"
)

type ElasticSearch struct {
	version string
	reg     *regexp.Regexp
}

func (ElasticSearch) Name() string { return "elasticsearch" }

func (ElasticSearch) Type() string { return "database" }

func (e ElasticSearch) Version() string { return e.version }

func (ElasticSearch) Match(p *process.Process) bool {
	return false
	// return p.Name == "java"
}

func (e *ElasticSearch) Run(p *process.Process) (mapping map[string]string, err error) {
	// if e.reg == nil {
	// }
	return
}
