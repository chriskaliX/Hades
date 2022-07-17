package cache

import (
	"bytes"
	"fmt"
	"hades-ebpf/user/share"
	"os"
	"strings"
	"time"

	lru "github.com/hashicorp/golang-lru"
	"golang.org/x/time/rate"
)

var DefaultArgvCache = NewArgvCache()

type ArgvCache struct {
	rlimiter *rate.Limiter
	cache    *lru.Cache
}

func NewArgvCache() *ArgvCache {
	// the default value is from Elkeid, which is reasonable
	acache := &ArgvCache{
		rlimiter: rate.NewLimiter(rate.Every(40*time.Millisecond), 25),
	}
	acache.cache, _ = lru.New(8192)
	return acache
}

func (a *ArgvCache) Get(pid uint32) string {
	// pre check for pid
	if pid == 0 || pid == 1 {
		return share.INVALID_STRING
	}
	// get argv from cache
	if value, ok := a.cache.Get(pid); ok {
		return value.(string)
	}
	// get from /proc/{pid}/cmdline
	if a.rlimiter.Allow() {
		_byte, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
		if err != nil {
			return share.INVALID_STRING
		}
		if len(_byte) > 512 {
			_byte = _byte[:512]
		}
		argv := strings.TrimSpace(string(bytes.ReplaceAll(_byte, []byte{0}, []byte{' '})))
		a.cache.Add(pid, argv)
		return argv
	}
	return share.INVALID_STRING
}

func (a *ArgvCache) Put(pid uint32, argv string) {
	a.cache.Add(pid, argv)
}
