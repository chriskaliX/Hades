package global

import (
	"fmt"
	"os/user"
	"strconv"
	"strings"
	"sync"

	lru "github.com/hashicorp/golang-lru"
)

// 每个 id 需要获取到
// 当前 pid, pid_cmdline, ppid
var ProcessCache *lru.Cache
var ProcessCmdlineCache *lru.Cache
var FileHashCache *lru.ARCCache

// 暂时用这个, 不会变更
var UsernameCache *sync.Map

func init() {
	ProcessCache, _ = lru.New(10240)
	ProcessCmdlineCache, _ = lru.New(10240)
	FileHashCache, _ = lru.NewARC(2048)
	UsernameCache = &sync.Map{}
}

func GetUsername(uid int) string {
	var strUid string
	strUid = strconv.Itoa(uid)
	username, ok := UsernameCache.Load(strUid)
	if !ok {
		if user, err := user.LookupId(fmt.Sprint(uid)); err == nil {
			UsernameCache.Store(strUid, user.Username)
			return user.Username
		} else {
			return ""
		}
	}
	return username.(string)
}

func GetPstree(pid uint32) string {
	var pstree string
	for {
		cmdline, ok := ProcessCmdlineCache.Get(pid)
		if ok {
			pstree = pstree + fmt.Sprint(pid) + "." + cmdline.(string) + "<"
		} else {
			break
		}

		ppid, ok := ProcessCache.Get(pid)
		if !ok {
			break
		}

		pid = ppid.(uint32)
	}
	return strings.TrimRight(pstree, "<")
}
