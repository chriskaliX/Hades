package config

import (
	"errors"
	"sync"
)

var (
	WhiteList sync.Map
)

// 白名单, 每个主机支持64个白名单(性能问题), 支持对
// 任意collection的任意字段, 进行组和的 contains, regexp(length超过1000跳过) 判断
// 其他采集相对固定, 我们只需要对 execve 做过滤即可

type WhiteListConfig struct {
	Rules []Rule `json:"Rules"`
}

type Rule struct {
	Raw     string `json:"Raw"`		// Raw字段 field:string
	Type    uint8  `json:"Type"`
}

func (w *WhiteListConfig) Check() error {
	// 检验 config 是否存在
	if w == nil {
		return errors.New("config nil")
	}

	// 开始遍历 rules
	for _, rule := range w.Rules {
		if 
	}

	return nil
}
