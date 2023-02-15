package user

import (
	"collector/utils"
	"math/rand"
	"net"
	"os/user"
	"strconv"
	"time"

	utilcache "k8s.io/apimachinery/pkg/util/cache"
)

const userCacheSize = 2048

// TODO: better format maybe?
type User struct {
	Username                 string `json:"username"`
	Password                 string `json:"password"`
	PasswordUpdateTime       string `json:"password_update_time"`
	PasswordChangeInterval   string `json:"password_change_interval"`
	PasswordValidity         string `json:"password_validity"`
	PasswordWarnBeforeExpire string `json:"password_warn_before_expire"`
	PasswordGracePeriod      string `json:"password_grace_period"`
	UID                      uint32 `json:"uid"`
	GID                      uint32 `json:"gid"`
	GroupName                string `json:"group_name"`
	Info                     string `json:"info"`
	HomeDir                  string `json:"home_dir"`
	Shell                    string `json:"shell"`
	LastLoginTime            int64  `json:"last_login_time"`
	LastLoginIP              net.IP `json:"last_login_ip"`
}

var Cache = &UserCache{
	cache:     utilcache.NewLRUExpireCacheWithClock(userCacheSize, utils.Clock),
	namecache: utilcache.NewLRUExpireCacheWithClock(userCacheSize, utils.Clock),
}

type UserCache struct {
	cache     *utilcache.LRUExpireCache
	namecache *utilcache.LRUExpireCache
}

func (u *UserCache) GetUser(userid uint32) User {
	ustr := strconv.FormatUint(uint64(userid), 10)
	if _user, ok := u.cache.Get(ustr); ok {
		return _user.(User)
	}
	// Filled by LookupId, not complete User we get
	if tmp, err := user.LookupId(ustr); err == nil {
		gid, _ := strconv.ParseInt(tmp.Gid, 10, 32)
		uid, _ := strconv.ParseInt(tmp.Uid, 10, 32)
		user := User{
			Username: tmp.Username,
			HomeDir:  tmp.HomeDir,
			GID:      uint32(gid),
			UID:      uint32(uid),
		}
		u.Update(user)
		return user
	}
	return User{}
}

func (u *UserCache) GetUserFromName(name string) User {
	if _user, ok := u.namecache.Get(name); ok {
		return _user.(User)
	}
	if tmp, err := user.Lookup(name); err == nil {
		gid, _ := strconv.ParseInt(tmp.Gid, 10, 32)
		uid, _ := strconv.ParseInt(tmp.Uid, 10, 32)
		user := User{
			Username: tmp.Username,
			HomeDir:  tmp.HomeDir,
			GID:      uint32(gid),
			UID:      uint32(uid),
		}
		u.Update(user)
		return user
	}
	return User{}
}

func (u *UserCache) GetUsername(userid uint32) (username string) {
	user := u.GetUser(userid)
	username = user.Username
	return
}

func (u *UserCache) GetUsers() (users []User) {
	for _, username := range u.cache.Keys() {
		if value, ok := u.cache.Get(username.(string)); ok {
			users = append(users, value.(User))
		}
	}
	return
}

func (u *UserCache) Update(usr User) {
	ustr := strconv.FormatUint(uint64(usr.UID), 10)
	u.cache.Add(ustr, usr, time.Minute*time.Duration(rand.Intn(60)+60))
	u.cache.Add(usr.Username, usr, time.Minute*time.Duration(rand.Intn(60)+60))
}

func init() {
	rand.Seed(time.Now().UnixNano())
}
