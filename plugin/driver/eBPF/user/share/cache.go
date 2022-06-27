package share

import (
	"fmt"
	"os/user"
	"sync"

	lru "github.com/hashicorp/golang-lru"
)

// 每个 id 需要获取到
// 当前 pid, pid_cmdline, ppid
var ProcessCache *lru.Cache
var ProcessCmdlineCache *lru.Cache

// TODO: 暂时用这个, 不会变更
var UsernameCache *sync.Map

func init() {
	ProcessCache, _ = lru.New(10240)
	ProcessCmdlineCache, _ = lru.New(10240)
	UsernameCache = &sync.Map{}
}

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
