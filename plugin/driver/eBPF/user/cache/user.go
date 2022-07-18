package cache

import (
	"hades-ebpf/user/share"
	"math/rand"
	"os/user"
	"strconv"
	"time"

	"github.com/karlseguin/ccache/v2"
)

var DefaultUserCache = NewUserCache()

type UserCache struct {
	cache *ccache.Cache
}

func NewUserCache() *UserCache {
	cache := &UserCache{
		cache: ccache.New(ccache.Configure().MaxSize(1024)),
	}

	return cache
}

// username may changed, cache with timeout is needed
func (u *UserCache) Get(_uid uint32) string {
	uid := strconv.FormatUint(uint64(_uid), 10)
	item := u.cache.Get(uid)
	if item != nil {
		if item.Expired() {
			u.cache.Delete(uid)
		}
		return item.Value().(string)
	}
	user, err := user.LookupId(uid)
	if err != nil {
		return share.INVALID_STRING
	}
	u.cache.Set(uid, user.Username, 1*time.Hour+time.Duration(rand.Intn(600))*time.Second)
	return user.Username
}
