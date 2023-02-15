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
	"time"

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
	result := make([]cache.User, 0)
	var userMap = make(map[string]cache.User, 0)
	if err := u.etcPasswd(userMap); err != nil {
		return err
	}
	if err := u.loginStatus(userMap); err != nil {
		return err
	}
	if err := u.etcShadow(userMap); err != nil {
		return err
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

func (u *User) etcPasswd(userMap map[string]cache.User) error {
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
	return nil
}

const TIME_LAYOUT = "2006-01-02 15:04:05"

func (u *User) etcShadow(userMap map[string]cache.User) error {
	t, _ := time.Parse(TIME_LAYOUT, "1970-01-01 00:00:00")
	// /etc/shadow fields
	shadow, err := os.Open("/etc/shadow")
	if err != nil {
		return err
	}
	defer shadow.Close()
	shadowScanner := bufio.NewScanner(shadow)
	for shadowScanner.Scan() {
		line := shadowScanner.Text()
		fields := strings.Split(line, ":")
		if len(fields) < 7 {
			continue
		}
		user, ok := userMap[fields[0]]
		if !ok {
			continue
		}
		user.Password = fields[1]
		if updateTime, err := strconv.Atoi(fields[2]); err == nil {
			user.PasswordUpdateTime = t.AddDate(0, 0, updateTime).Format(TIME_LAYOUT)
		}
		user.PasswordChangeInterval = fields[3]
		if validDays, err := strconv.Atoi(fields[4]); err == nil {
			user.PasswordValidity = t.AddDate(0, 0, validDays).Format(TIME_LAYOUT)
		}
		user.PasswordWarnBeforeExpire = fields[5]
		user.PasswordGracePeriod = fields[6]
		userMap[user.Username] = user
	}
	return nil
}

func (u *User) loginStatus(userMap map[string]cache.User) error {
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
	return nil
}
