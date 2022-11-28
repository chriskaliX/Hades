package cache

import (
	"fmt"
	"strings"

	"k8s.io/utils/lru"
)

const MaxProcess = 8
const MaxProcessCache = 2048

var PidCache = lru.New(MaxProcessCache)
var ArgvCache = lru.New(MaxProcessCache)
var CmdlineCache = lru.New(MaxProcessCache)

// if pid tree get from argv or exe, the field would be enlarged...
// https://github.com/EBWi11/AgentSmith-HIDS/blob/master/doc/How-to-use-AgentSmith-HIDS-to-detect-reverse-shell/%E5%A6%82%E4%BD%95%E5%88%A9%E7%94%A8AgentSmith-HIDS%E6%A3%80%E6%B5%8B%E5%8F%8D%E5%BC%B9shell.md
func GetPstree(pid uint32) (pidtree string) {
	for i := 0; i < MaxProcess; i++ {
		if cmdline, ok := CmdlineCache.Get(pid); ok {
			pidtree = pidtree + fmt.Sprint(pid) + "." + cmdline.(string) + "<"
		} else if i == 0 {
			// if the very first time, try to get the comm
			if ppid, ok := PidCache.Get(pid); ok {
				if comm, err := getComm(int(ppid.(uint32))); err == nil {
					pidtree = pidtree + fmt.Sprint(pid) + "." + comm + "<"
				}
			}
		} else {
			break
		}

		if pid == 1 {
			break
		}
		if ppid, ok := PidCache.Get(pid); !ok {
			break
		} else {
			pid = ppid.(uint32)
		}
	}
	return strings.TrimRight(pidtree, "<")
}
