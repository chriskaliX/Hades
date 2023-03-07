package user

import (
	"collector/utils"
	"math/rand"
	"os/user"
	"strconv"
	"time"

	utilcache "k8s.io/apimachinery/pkg/util/cache"
)

const userCacheSize = 2048

type User struct {
	Username                 string `mapstructure:"username"`
	Password                 string `mapstructure:"password"`
	PasswordUpdateTime       string `mapstructure:"password_update_time"`
	PasswordChangeInterval   string `mapstructure:"password_change_interval"`
	PasswordValidity         string `mapstructure:"password_validity"`
	PasswordWarnBeforeExpire string `mapstructure:"password_warn_before_expire"`
	PasswordGracePeriod      string `mapstructure:"password_grace_period"`
	UID                      string `mapstructure:"uid"`
	GID                      string `mapstructure:"gid"`
	GroupName                string `mapstructure:"group_name"`
	Info                     string `mapstructure:"info"`
	HomeDir                  string `mapstructure:"home_dir"`
	Shell                    string `mapstructure:"shell"`
	LastLoginTime            string `mapstructure:"last_login_time"`
	LastLoginIP              string `mapstructure:"last_login_ip"`
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
			GID:      strconv.FormatInt(gid, 10),
			UID:      strconv.FormatInt(uid, 10),
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
			GID:      strconv.FormatInt(gid, 10),
			UID:      strconv.FormatInt(uid, 10),
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
	u.cache.Add(usr.UID, usr, time.Minute*time.Duration(rand.Intn(60)+60))
	u.cache.Add(usr.Username, usr, time.Minute*time.Duration(rand.Intn(60)+60))
}

func init() {
	rand.Seed(time.Now().UnixNano())
}
