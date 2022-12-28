package cache

import (
	"bytes"
	"fmt"
	"hades-ebpf/utils"
	"os"
	"strings"
	"time"

	"github.com/chriskaliX/SDK/config"
	"golang.org/x/time/rate"
	"k8s.io/utils/lru"
)

const (
	argvCacheSize       = 8192
	argvLimiterBurst    = 100
	argvLimiterInterval = 2 * time.Millisecond
	argvMaxLength       = 1024
)

var DefaultArgvCache = NewArgvCache()

type ArgvCache struct {
	rlimiter *rate.Limiter
	cache    *lru.Cache
}

func NewArgvCache() *ArgvCache {
	// the default value is from Elkeid, which is reasonable
	acache := &ArgvCache{
		rlimiter: rate.NewLimiter(
			rate.Every(argvLimiterInterval), argvLimiterBurst,
		),
		cache: lru.New(argvCacheSize),
	}
	return acache
}

// Get the argv by pid
func (a *ArgvCache) Get(pid uint32) string {
	// pre check for pid
	if pid == 0 {
		return config.FieldInvalid
	}
	// get argv from cache
	if value, ok := a.cache.Get(pid); ok {
		return value.(string)
	}
	// get from /proc/{pid}/cmdline
	if a.rlimiter.AllowN(utils.Clock.Now(), 1) {
		_byte, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
		if err != nil {
			return config.FieldInvalid
		}
		if len(_byte) > argvMaxLength {
			_byte = _byte[:argvMaxLength]
		}
		argv := convertCmdline(_byte)
		a.Set(pid, argv)
		return argv
	}
	return config.FieldOverrate
}

// Set pid, argv to cache
func (a *ArgvCache) Set(pid uint32, argv string) {
	a.cache.Add(pid, argv)
}

// convert /proc/<pid>/cmdline to readable string
func convertCmdline(_cmdline []byte) string {
	return strings.TrimRight(string(bytes.ReplaceAll(_cmdline, []byte("\x00"), []byte(" "))), " ")
}
