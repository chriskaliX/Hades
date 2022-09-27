package cache

import (
	"fmt"
	"strings"

	lru "github.com/hashicorp/golang-lru"
)

const MaxProcess = 12
const MaxProcessCache = 1000

// for process cache
var ProcessCache, _ = lru.New(MaxProcessCache)
var ProcessCmdlineCache, _ = lru.New(MaxProcessCache)

// if pid tree get from argv or exe, the field would be enlarged...
// https://github.com/EBWi11/AgentSmith-HIDS/blob/master/doc/How-to-use-AgentSmith-HIDS-to-detect-reverse-shell/%E5%A6%82%E4%BD%95%E5%88%A9%E7%94%A8AgentSmith-HIDS%E6%A3%80%E6%B5%8B%E5%8F%8D%E5%BC%B9shell.md
func GetPstree(pid uint32) (pidtree string) {
	// set limit for the pidtree
	for i := 0; i < MaxProcess; i++ {
		cmdline, ok := ProcessCmdlineCache.Get(pid)
		if ok {
			pidtree = pidtree + fmt.Sprint(pid) + "." + cmdline.(string) + "<"
		} else {
			break
		}
		// break if we reach the pid 1
		if pid == 1 {
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
