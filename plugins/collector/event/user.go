package event

import (
	"bufio"
	cache "collector/cache/user"
	"collector/eventmanager"
	"collector/utils/login"
	"os"
	"os/user"
	"strconv"
	"strings"

	"github.com/bytedance/sonic"
	"github.com/chriskaliX/SDK"
	"github.com/chriskaliX/SDK/transport/protocol"
)

const USER_DATATYPE = 3004

var _ eventmanager.IEvent = (*User)(nil)

// Contains the UtmpFile state, based on
// https://github.com/elastic/beats/blob/237937085a5a7337ba06f1268cfc55cd4b869e31/x-pack/auditbeat/module/system/login/utmp.go
type User struct {
	f *login.UtmpFile
}

func (User) DataType() int { return USER_DATATYPE }

func (User) Name() string { return "user" }

func (User) Flag() int { return eventmanager.Periodic }

func (User) Immediately() bool { return true }

// get user and update the usercache
func (u *User) Run(s SDK.ISandbox, sig chan struct{}) error {
	result := make([]cache.User, 0, 20)
	var userMap = make(map[string]cache.User, 20)
	passwd, err := os.Open("/etc/passwd")
	if err != nil {
		return err
	}
	defer passwd.Close()
	// basic information
	passwdScanner := bufio.NewScanner(passwd)
	for passwdScanner.Scan() {
		line := passwdScanner.Text()
		fields := strings.Split(line, ":")
		u := cache.User{
			Username: fields[0],
			Password: fields[1],
			Info:     fields[4],
			HomeDir:  fields[5],
			Shell:    fields[6],
		}
		uid, _ := strconv.ParseUint(fields[2], 10, 32)
		gid, _ := strconv.ParseUint(fields[3], 10, 32)
		u.UID = uint32(uid)
		u.GID = uint32(gid)
		if group, err := user.LookupGroupId(fields[3]); err == nil {
			u.GroupName = group.Name
		}
		userMap[fields[0]] = u
	}
	// login status
	if u.f == nil {
		u.f = &login.UtmpFile{}
	}
	if records, err := u.f.GetRecord(); err == nil {
		for _, record := range records {
			user, ok := userMap[record.Username]
			if ok {
				user.LastLoginIP = record.IP
				user.LastLoginTime = record.Time.Unix()
				userMap[record.Username] = user
			}
		}
	}
	// append all
	for _, user := range userMap {
		result = append(result, user)
		cache.Cache.Update(user)
	}
	data, err := sonic.MarshalString(result)
	if err != nil {
		return err
	}
	rec := &protocol.Record{
		DataType: SSHCONFIG_DATATYPE,
		Data: &protocol.Payload{
			Fields: map[string]string{
				"data": data,
			},
		},
	}
	s.SendRecord(rec)
	return nil
}
