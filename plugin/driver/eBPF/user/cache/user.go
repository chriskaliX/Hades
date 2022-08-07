package cache

import (
	"math/rand"
	"os/user"
	"strconv"
	"time"

	utilcache "k8s.io/apimachinery/pkg/util/cache"
)

const (
	userCacheSize = 1024
)

var DefaultUserCache = NewUserCache()

type UserCache struct {
	cache *utilcache.LRUExpireCache
}

func NewUserCache() *UserCache {
	return &UserCache{
		cache: utilcache.NewLRUExpireCacheWithClock(userCacheSize, GTicker),
	}
}

// username may changed, cache with timeout is needed
func (u *UserCache) Get(_uid uint32) string {
	uid := strconv.FormatUint(uint64(_uid), 10)
	item, status := u.cache.Get(uid)
	if status {
		return item.(string)
	}
	user, err := user.LookupId(uid)
	if err != nil {
		return InVaild
	}
	duration := time.Hour + time.Duration(rand.Intn(600))*time.Second
	u.cache.Add(uid, user.Username, duration)
	return user.Username
}
