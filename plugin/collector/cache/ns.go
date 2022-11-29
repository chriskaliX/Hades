package cache

import (
	"bytes"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"time"

	"golang.org/x/time/rate"
	utilcache "k8s.io/apimachinery/pkg/util/cache"
)

const (
	// the ccache max cache size is 5000
	nsCacheSize       = 4096
	nsLimiterBurst    = 25
	nsLimiterInterval = 40 * time.Millisecond
)

const InValid = "-1"

var DefaultNsCache = NewNsCache()
var hostname string

type NsCache struct {
	cache     *utilcache.LRUExpireCache
	namecache *utilcache.LRUExpireCache
	rlimiter  *rate.Limiter
}

func NewNsCache() *NsCache {
	cache := &NsCache{
		rlimiter:  rate.NewLimiter(rate.Every(nsLimiterInterval), nsLimiterBurst),
		cache:     utilcache.NewLRUExpireCacheWithClock(nsCacheSize, GTicker),
		namecache: utilcache.NewLRUExpireCacheWithClock(nsCacheSize, GTicker),
	}
	return cache
}

// Get the pod name of the pns. It's also from the Elkeid, but I changed
// the cache to lruexpirecache
func (n *NsCache) Get(pid uint32, pns uint32) (podname string, nodename string) {
	pname, ok := n.cache.Get(pns)
	if ok {
		podname = pname.(string)
	} else {
		podname = InValid
	}

	name, ok := n.namecache.Get(pns)
	if ok {
		nodename = name.(string)
	} else if pns == uint32(root_pns) {
		n.namecache.Add(uint32(root_pns), hostname, 5 * time.Minute)
		nodename = hostname
	} else {
		nodename = InValid
	}
	// if pname and nodename is valid, not need to get from environ
	if pname != InValid && name != InValid {
		return
	}

	// missed, get it from environ
	if n.rlimiter.Allow() {
		// extract pod name from /proc/<pid>/environ
		_byte, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
		if err != nil {
			return
		}
		envList := bytes.Split(_byte, []byte{0})
		for _, env := range envList {
			_env := strings.Split(string(env), "=")
			if len(_env) != 2 {
				continue
			}
			// TODO: check this out, just try to get from env which is not reliable
			if _env[0] == "HOSTNAME" {
				duration := time.Hour + time.Duration(rand.Intn(600))*time.Second
				n.namecache.Add(pns, _env[1], duration)
				nodename = _env[1]
			}
			if _env[0] == "MY_POD_NAME" || _env[0] == "POD_NAME" {
				// get it right, save to cache and return
				duration := time.Hour + time.Duration(rand.Intn(600))*time.Second
				n.cache.Add(pns, _env[1], duration)
				podname = _env[1]
			}
		}
		// missed, no pod_name is got. save invalid for a minite
		// just for better performance
		if nodename == InValid {
			n.namecache.Add(pns, InValid, 5 * time.Minute)
		}
		if podname == InValid {
			n.cache.Add(pns, InValid, 5 * time.Minute)
		}
		return
	}
	return
}

func init() {
	hostname, _ = os.Hostname()
}