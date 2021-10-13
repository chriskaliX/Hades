package config

import (
	"agent/global"
	"errors"
	"os"
)

type IConfig interface {
	Check() error //检测配置合法性
}

func Load(a global.Command) error {
	if a.AgentCtrl < 1 || a.AgentCtrl > 3 {
		return errors.New("AgentCtrl flag not valid")
	}
	switch a.AgentCtrl {
	case 1:
		os.Exit(0)
	case 2:

	case 3:
		w := &WhiteListConfig{}
		return w.Load(a.Message)
	}

	return nil
}
