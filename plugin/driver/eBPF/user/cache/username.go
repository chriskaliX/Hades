package cache

import (
	"hades-ebpf/user/share"
	"os/user"
	"strconv"

	lru "github.com/hashicorp/golang-lru"
)

var DefaultUserCache = NewUserCache()

type UserCache struct {
	cache *lru.Cache
}

func NewUserCache() *UserCache {
	cache := &UserCache{}
	cache.cache, _ = lru.New(1024)
	return cache
}

func (u *UserCache) Get(uid uint32) string {
	username, ok := u.cache.Get(uid)
	if ok {
		return username.(string)
	}
	user, err := user.LookupId(strconv.Itoa(int(uid)))
	if err != nil {
		return share.INVALID_STRING
	}
	u.cache.Add(uid, user.Username)
	return user.Username
}
