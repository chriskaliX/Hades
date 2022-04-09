package cache

import (
	"fmt"
	"os/user"
	"strings"
	"sync"

	lru "github.com/hashicorp/golang-lru"
)

// 每个 id 需要获取到
// 当前 pid, pid_cmdline, ppid
var ProcessCache, _ = lru.New(10240)
var ProcessCmdlineCache, _ = lru.New(10240)

// TODO: 暂时用这个, 不会变更
var UsernameCache = &sync.Map{}

func GetUsername(uid string) string {
	username, ok := UsernameCache.Load(uid)
	if !ok {
		if user, err := user.LookupId(fmt.Sprint(uid)); err == nil {
			UsernameCache.Store(uid, user.Username)
			return user.Username
		} else {
			return ""
		}
	}
	return username.(string)
}

// if pid tree get from argv or exe. It will enlarge the field.
// https://github.com/EBWi11/AgentSmith-HIDS/blob/master/doc/How-to-use-AgentSmith-HIDS-to-detect-reverse-shell/%E5%A6%82%E4%BD%95%E5%88%A9%E7%94%A8AgentSmith-HIDS%E6%A3%80%E6%B5%8B%E5%8F%8D%E5%BC%B9shell.md
func GetPstree(pid uint32) (pidtree string) {
	// set limit for the pidtree
	for i := 0; i < 12; i++ {
		cmdline, ok := ProcessCmdlineCache.Get(pid)
		if ok {
			pidtree = pidtree + fmt.Sprint(pid) + "." + cmdline.(string) + "<"
		} else {
			break
		}

		ppid, ok := ProcessCache.Get(pid)
		if !ok {
			break
		}

		pid = ppid.(uint32)
	}
	return strings.TrimRight(pidtree, "<")
}
