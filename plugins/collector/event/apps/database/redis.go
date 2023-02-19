package database

import (
	"collector/cache/process"
	"collector/event/apps"
	"path/filepath"
	"strings"
)

type Redis struct {
	version string
}

func (Redis) Name() string { return "redis" }

func (Redis) Type() string { return "database" }

func (r Redis) Version() string { return r.version }

func (r *Redis) Match(p *process.Process) bool { return p.Name == "redis-server" }

func (r *Redis) Run(p *process.Process) (m map[string]string, err error) {
	// Same problem in Elkeid, since the name is redis-server & the exe is redis-check-rdb
	// /usr/bin/redis-server symbol link to redis-check-rdb
	result, err := apps.ExecuteWithName(p, filepath.Join(filepath.Dir(p.Exe), "redis-server"), "-v")
	if err != nil {
		return nil, err
	}
	for _, v := range strings.Split(result, " ") {
		if strings.HasPrefix(v, "v=") {
			r.version = strings.TrimPrefix(v, "v=")
			return m, nil
		}
	}
	return nil, apps.ErrVersionNotFound
}

func init() {
	apps.Regist(&Redis{})
}
