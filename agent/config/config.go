package config

import (
	"agent/global"
	"errors"
)

type IConfig interface {
	Check() error //检测配置合法性
}

type AgentConfig global.Command

func (a *AgentConfig) Check() error {
	if a.AgentCtrl < 1 || a.AgentCtrl > 3 {
		return errors.New("AgentCtrl flag not valid")
	}
	switch a.AgentCtrl {
	case 1:
		return nil
	case 2:
		
	}

	return nil
}
