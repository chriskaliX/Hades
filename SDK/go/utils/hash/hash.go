// hash is linux only
package hash

import (
	"time"

	"github.com/cespare/xxhash/v2"
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
	buf   []byte
	clock clock.IClock
	hash  *xxhash.Digest
	rl    *rate.Limiter
}

func NewWithClock(c clock.IClock) *HashCache {
	return &HashCache{
		cache: lru.New(hashCacheSize),
		buf:   make([]byte, 32*1024),
		clock: c,
		hash:  xxhash.New(),
		rl:    rate.NewLimiter(rate.Every(5*time.Microsecond), burst),
	}
}
