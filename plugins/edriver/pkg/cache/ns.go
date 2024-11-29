package cache

import (
	"bytes"
	"edriver/utils"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"time"

	"github.com/chriskaliX/SDK/config"
	"golang.org/x/time/rate"
	utilcache "k8s.io/apimachinery/pkg/util/cache"
)

const (
	// the ccache max cache size is 5000
	nsCacheSize       = 4096
	nsLimiterBurst    = 100
	nsLimiterInterval = 2 * time.Millisecond
)

// environment variables for k8s
const (
	K8sMyPodName = "MY_POD_NAME"
	k8sPodName   = "POD_NAME"
)

var DefaultNsCache = NewNsCache()

type NsCache struct {
	cache    *utilcache.LRUExpireCache
	rlimiter *rate.Limiter
}

func NewNsCache() *NsCache {
	cache := &NsCache{
		rlimiter: rate.NewLimiter(rate.Every(nsLimiterInterval), nsLimiterBurst),
		cache:    utilcache.NewLRUExpireCacheWithClock(nsCacheSize, utils.Clock),
	}
	return cache
}

// Get the pod name of the pns. It's also from the Elkeid, but I changed
// the cache to lruexpirecache
func (n *NsCache) Get(pid uint32, pns uint32) string {
	// get the pns from the cache
	item, status := n.cache.Get(pns)
	if status {
		return item.(string)
	}
	// missed, get it from environ
	if n.rlimiter.AllowN(utils.Clock.Now(), 1) {
		// extract pod name from /proc/<pid>/environ
		_byte, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
		if err != nil {
			return config.FieldInvalid
		}
		envList := bytes.Split(_byte, []byte{0})
		for _, env := range envList {
			_env := strings.Split(string(env), "=")
			if len(_env) != 2 {
				continue
			}
			if _env[0] == K8sMyPodName || _env[0] == k8sPodName {
				// get it right, save to cache and return
				duration := time.Hour + time.Duration(rand.Intn(600))*time.Second
				n.cache.Add(pns, _env[1], duration)
				return _env[1]
			}
		}
		// missed, no pod_name is got. save invalid for a minite
		// just for better performance
		n.cache.Add(pns, config.FieldInvalid, time.Minute)
		return config.FieldInvalid
	}
	return config.FieldOverrate
}
