// hash is linux only
package hash

import (
	"crypto/md5"
	"sync"
	"time"

	"github.com/chriskaliX/SDK/clock"
	"golang.org/x/time/rate"
	"k8s.io/utils/lru"
)

const (
	freq          = 60
	maxFileSize   = 10485760
	hashCacheSize = 4096
	burst         = 32
)

type IHashCache interface {
	GetHash(path string) string
}

type HashCache struct {
	cache *lru.Cache
	pool  *sync.Pool
	clock clock.IClock
	rl    *rate.Limiter
}

func NewWithClock(c clock.IClock) *HashCache {
	return &HashCache{
		cache: lru.New(hashCacheSize),
		pool: &sync.Pool{
			New: func() interface{} {
				return md5.New()
			},
		},
		clock: c,
		rl:    rate.NewLimiter(rate.Every(5*time.Microsecond), burst),
	}
}
