package config

import (
	"errors"
	"regexp"
	"sync"
)

var (
	ExeList        sync.Map
	Sha256List     sync.Map
	CmdlineList    sync.Map
	PidtreeList    sync.Map
	WhiteListCount uint
)

const (
	WhiteListLimit = 64
)

// 白名单, 每个主机支持64个白名单(性能问题), 支持对
// 任意collection的任意字段, 进行组和的 contains, regexp(length超过1000跳过) 判断
// 其他采集相对固定, 我们只需要对 execve 做过滤即可
type WhiteListConfig struct {
	Rules []Rule `json:"Rules"`
}

type Rule struct {
	Raw   string `json:"Raw"`
	Field string `json:"Field"`
}

func (w *WhiteListConfig) Check() error {
	// 检验 config 是否存在
	if w == nil {
		return errors.New("whitelist config nil")
	}
	if w.Rules == nil {
		return errors.New("whitelist rules nil")
	}

	// 开始遍历 rules
	// 有一条 rule 失败就错误
	for _, rule := range w.Rules {
		switch rule.Field {
		// equals only
		case "sha256":
			matched, err := regexp.Match("([0-9]|[a-f]){64}", []byte(rule.Raw))
			if err != nil {
				return err
			}
			if !matched {
				return errors.New("sha256 regexp not match")
			}
		// equals only
		case "exe":
			if len(rule.Raw) > 100 {
				return errors.New("exe length over 100")
			}
		// matches
		case "cmdline":
			if len(rule.Raw) > 200 {
				return errors.New("exe length over 100")
			}
		// matches
		case "pidtree":
			if len(rule.Raw) > 200 {
				return errors.New("exe length over 100")
			}
		// else drop
		default:
			return errors.New("unrecognize field")
		}
	}
	return nil
}

func (w *WhiteListConfig) Load(confByte []byte) error {
	return nil
}
