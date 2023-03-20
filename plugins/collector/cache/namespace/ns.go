package namepsace

import (
	"bytes"
	"collector/cache"
	"collector/utils"
	"fmt"
	"math/rand"
	"os"
	"time"

	"golang.org/x/time/rate"
	utilcache "k8s.io/apimachinery/pkg/util/cache"
)

const (
	nsCacheSize       = 4096
	nsLimiterBurst    = 100
	nsLimiterInterval = 50 * time.Millisecond
)

const invalid = "-1"

var Cache = NewNsCache()
var hostname string

type NsCache struct {
	cache     *utilcache.LRUExpireCache
	namecache *utilcache.LRUExpireCache
	rlimiter  *rate.Limiter
}

func NewNsCache() *NsCache {
	cache := &NsCache{
		rlimiter:  rate.NewLimiter(rate.Every(nsLimiterInterval), nsLimiterBurst),
		cache:     utilcache.NewLRUExpireCacheWithClock(nsCacheSize, utils.Clock),
		namecache: utilcache.NewLRUExpireCacheWithClock(nsCacheSize, utils.Clock),
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
		podname = invalid
	}

	name, ok := n.namecache.Get(pns)
	if ok {
		nodename = name.(string)
	} else if pns == uint32(cache.RootPns) {
		n.namecache.Add(uint32(cache.RootPns), hostname, 5*time.Minute)
		nodename = hostname
	} else {
		nodename = invalid
	}
	// if pname and nodename is valid, not need to get from environ
	if podname != invalid && nodename != invalid {
		return
	}
	// missed, get it from environ
	// if !n.rlimiter.Allow() {
	// 	return
	// }
	_byte, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
	if err != nil {
		return
	}
	envList := bytes.Split(_byte, []byte{0})
	for _, env := range envList {
		_env := bytes.Split(env, []byte{'='})
		if len(_env) != 2 {
			continue
		}
		key := string(_env[0])
		value := string(_env[1])
		// TODO: check this out, just try to get from env which is not reliable
		if key == "HOSTNAME" {
			duration := time.Hour + time.Duration(rand.Intn(600))*time.Second
			n.namecache.Add(pns, value, duration)
			nodename = value
		}
		if key == "MY_POD_NAME" || key == "POD_NAME" {
			// get it right, save to cache and return
			duration := time.Hour + time.Duration(rand.Intn(600))*time.Second
			n.cache.Add(pns, value, duration)
			podname = value
		}
	}
	// missed, no pod_name is got. save invalid for a minite
	// just for better performance
	if nodename == invalid {
		n.namecache.Add(pns, invalid, 5*time.Minute)
	}
	if podname == invalid {
		n.cache.Add(pns, invalid, 5*time.Minute)
	}
	return
}

func init() {
	hostname, _ = os.Hostname()
}
