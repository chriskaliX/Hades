package cache

import (
	"edriver/utils"
	"math/rand"
	"os/user"
	"strconv"
	"time"

	"github.com/chriskaliX/SDK/config"
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
		cache: utilcache.NewLRUExpireCacheWithClock(userCacheSize, utils.Clock),
	}
}

func (u *UserCache) Get(_uid uint32) string {
	uid := strconv.FormatUint(uint64(_uid), 10)
	item, status := u.cache.Get(uid)
	if status {
		return item.(string)
	}
	user, err := user.LookupId(uid)
	if err != nil {
		return config.FieldInvalid
	}
	duration := time.Hour + time.Duration(rand.Intn(600))*time.Second
	u.cache.Add(uid, user.Username, duration)
	return user.Username
}
