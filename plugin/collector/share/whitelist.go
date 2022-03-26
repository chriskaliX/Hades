package share

import (
	"collector/cache"
	"errors"
	"reflect"
	"regexp"
	"strings"
	"sync"
)

var (
	ExeList     sync.Map
	Sha256List  sync.Map
	CmdlineList sync.Map
	PidtreeList sync.Map
)

const (
	WhiteListLimit = 64
)

// 白名单, 每个主机支持64个白名单(性能问题), 支持对
// 任意collection的任意字段, 进行组和的 contains, regexp(length超过1000跳过) 判断
// 其他采集相对固定, 我们只需要对 execve 做过滤即可
type WhiteList struct {
	Sha256  []string `json:"Sha256"`
	Exe     []string `json:"Exe"`
	Cmdline []string `json:"Cmdline"`
	Pidtree []string `json:"Pidtree"`
}

func (w *WhiteList) Check() error {
	v := reflect.ValueOf(w).Elem()
	t := v.Type()

	// 长度限制
	var count int
	for i := 0; i < t.NumField(); i++ {
		if v.Field(i).IsValid() {
			count = count + v.Field(i).Len()
		}
	}
	if count > WhiteListLimit {
		return errors.New("config length over 64")
	}

	// 开始check
	for i := 0; i < t.NumField(); i++ {
		if v.Field(i).IsValid() {
			for j := 0; j < v.Field(i).Len(); j++ {
				switch t.Field(i).Name {
				case "Sha256":
					matched, err := regexp.MatchString("^([0-9]|[a-f]){64}$", v.Field(i).Index(j).String())
					if err != nil {
						return err
					}
					if !matched {
						return errors.New("Sha256 regexp not match")
					}
				case "Exe":
					if v.Field(i).Index(j).Len() > 100 {
						return errors.New("exe Length over 100")
					}
				case "Cmdline":
					if v.Field(i).Index(j).Len() > 200 {
						return errors.New("exe Length over 100")
					}
				case "Pidtree":
					if v.Field(i).Index(j).Len() > 200 {
						return errors.New("exe Length over 100")
					}
				default:
					return errors.New("unrecognize field")
				}
			}
		}
	}
	return nil
}

func (w *WhiteList) Load() error {
	// 清空函数
	clear := func(sm sync.Map) {
		sm.Range(func(key interface{}, value interface{}) bool {
			sm.Delete(key)
			return true
		})
	}

	// 加载函数
	load := func(sm sync.Map, list []string) {
		clear(sm)
		for _, v := range list {
			sm.Store(v, nil)
		}
	}

	load(Sha256List, w.Sha256)
	load(ExeList, w.Exe)
	load(CmdlineList, w.Cmdline)
	load(PidtreeList, w.Pidtree)
	return nil
}

func WhiteListCheck(process cache.Process) bool {
	if _, ok := ExeList.Load(process.Exe); ok {
		return true
	}
	if _, ok := Sha256List.Load(process.Sha256); ok {
		return true
	}
	flag := false
	CmdlineList.Range(func(k, v interface{}) bool {
		if strings.Contains(process.Cmdline, k.(string)) {
			flag = true
			return false
		}
		return true
	})
	if flag {
		return true
	}

	PidtreeList.Range(func(k, v interface{}) bool {
		if strings.Contains(process.PidTree, k.(string)) {
			flag = true
			return false
		}
		return true
	})

	if flag {
		return true
	}
	return false
}
