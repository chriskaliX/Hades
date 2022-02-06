package main

import (
	"bufio"
	"encoding/binary"
	"net"
	"os"
	"os/user"
	"strconv"
	"strings"
)

type Utmp struct {
	Type int16
	// alignment
	_      [2]byte
	Pid    int32
	Device [32]byte
	Id     [4]byte
	User   [32]byte
	Host   [256]byte
	Exit   struct {
		Termination int16
		Exit        int16
	}
	Session int32
	Time    struct {
		Sec  int32
		Usec int32
	}
	AddrV6 [16]byte
	// Reserved member
	Reserved [20]byte
}

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
	WeakPassword  bool   `json:"weak_password"`
}

func GetUser() (users []User, err error) {
	userMap := make(map[string]*User, 30)
	var passwd *os.File
	passwd, err = os.Open("/etc/passwd")
	if err != nil {
		return
	}
	defer passwd.Close()
	passwdScanner := bufio.NewScanner(passwd)
	for passwdScanner.Scan() {
		line := passwdScanner.Text()
		fields := strings.Split(line, ":")
		u := User{Username: fields[0], Password: fields[1], Info: fields[4], HomeDir: fields[5], Shell: fields[6]}
		uid, _ := strconv.ParseUint(fields[2], 10, 32)
		gid, _ := strconv.ParseUint(fields[3], 10, 32)
		u.UID = uint32(uid)
		u.GID = uint32(gid)
		group, err := user.LookupGroupId(fields[3])
		if err == nil {
			u.GroupName = group.Name
		}
		userMap[fields[0]] = &u
	}
	if wtmp, err := os.Open("/var/log/wtmp"); err == nil {
		defer wtmp.Close()
		for {
			u := Utmp{}
			if e := binary.Read(wtmp, binary.LittleEndian, &u); e != nil {
				break
			}
			username := strings.TrimRight(string(u.User[:]), "\x00")
			ip := strings.TrimRight(string(u.Host[:]), "\x00")
			user, ok := userMap[username]
			if ok {
				user.LastLoginIP = net.ParseIP(ip)
				user.LastLoginTime = uint64(u.Time.Sec)
			}
		}
	}
	for _, user := range userMap {
		users = append(users, *user)
	}
	return
}
