package cache

import (
	"bytes"
	"fmt"
	"hades-ebpf/user/share"
	"math/rand"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/karlseguin/ccache/v2"
	"golang.org/x/time/rate"
)

var DefaultNsCache = NewNsCache()

type NsCache struct {
	cache    *ccache.Cache
	rlimiter *rate.Limiter
}

func NewNsCache() *NsCache {
	cache := &NsCache{
		rlimiter: rate.NewLimiter(rate.Every(40*time.Millisecond), 25),
		cache:    ccache.New(ccache.Configure().MaxSize(1024)),
	}
	return cache
}

// Get the pod_name of the pns. Also from the Elkeid, but I do some modificaiton
// For now, it's only for k8s situation.
func (n *NsCache) Get(_pid uint32, _pns uint32) string {
	// convert the inputs
	pid := strconv.FormatUint(uint64(_pid), 10)
	pns := strconv.FormatUint(uint64(_pns), 10)
	// get the pns from the cache
	item := n.cache.Get(pns)
	if item != nil {
		if item.Expired() {
			n.cache.Delete(pns)
		}
		return item.Value().(string)
	}
	// missed, get it from environ
	if n.rlimiter.Allow() {
		_byte, err := os.ReadFile(fmt.Sprintf("/proc/%s/environ", pid))
		if err != nil {
			return share.INVALID_STRING
		}
		envList := bytes.Split(_byte, []byte{0})
		for _, env := range envList {
			_env := strings.Split(string(env), "=")
			if len(_env) != 2 {
				continue
			}
			if _env[0] == "MY_POD_NAME" || _env[0] == "POD_NAME" {
				// get it right, save to cache and return
				n.cache.Set(pns, _env[1], 1*time.Hour+time.Duration(rand.Intn(600))*time.Second)
				return _env[1]
			}
		}
		// missed, no pod_name is got. save invalid for a minite
		// speed up
		n.cache.Set(pns, share.INVALID_STRING, 1*time.Minute)
		return share.INVALID_STRING
	}
	return share.INVALID_STRING
}
