package cache

import (
	"math/rand"
	"net"
	"os/user"
	"strconv"
	"time"

	"github.com/patrickmn/go-cache"
)

type User struct {
	Username      string `json:"username"`
	Password      string `json:"password"`
	UID           uint32 `json:"uid"`
	GID           uint32 `json:"gid"`
	GroupName     string `json:"group_name"`
	Info          string `json:"info"`
	HomeDir       string `json:"home_dir"`
	Shell         string `json:"shell"`
	LastLoginTime uint64 `json:"last_login_time"`
	LastLoginIP   net.IP `json:"last_login_ip"`
}

type UserCache struct {
	_cache *cache.Cache
}

func (u *UserCache) GetUser(userid uint32) *User {
	useridstr := strconv.FormatUint(uint64(userid), 10)
	if _user, ok := u._cache.Get(useridstr); ok {
		return _user.(*User)
	}
	// Filled by LookupId, not complete User we get
	if tmp, err := user.LookupId(useridstr); err == nil {
		gid, _ := strconv.ParseInt(tmp.Gid, 10, 32)
		uid, _ := strconv.ParseInt(tmp.Uid, 10, 32)
		u._cache.Add(useridstr, &User{
			Username: tmp.Username,
			HomeDir:  tmp.HomeDir,
			GID:      uint32(gid),
			UID:      uint32(uid),
		}, time.Minute*time.Duration(rand.Intn(60)+60))
	}
	return nil
}

func (u *UserCache) GetUsers() (users []*User) {
	for _, user := range u._cache.Items() {
		users = append(users, user.Object.(*User))
	}
	return
}

func (u *UserCache) Update(usr *User) {
	useridstr := strconv.FormatUint(uint64(usr.UID), 10)
	u._cache.Add(useridstr, usr, time.Minute*time.Duration(rand.Intn(60)+60))
}

var DefaultUserCache = &UserCache{
	_cache: cache.New(time.Hour*time.Duration(2), time.Minute*time.Duration(30)),
}

func init() {
	rand.Seed(time.Now().UnixNano())
}
