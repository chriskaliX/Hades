package event

import (
	"bufio"
	cache "collector/cache/user"
	"collector/eventmanager"
	"encoding/binary"
	"net"
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

type User struct{}

type utmp struct {
	Type   int16
	_      [2]byte // alignment
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
	AddrV6   [16]byte
	Reserved [20]byte // Reserved member
}

func (User) DataType() int {
	return USER_DATATYPE
}

func (User) Name() string {
	return "user"
}

func (n *User) Flag() int {
	return eventmanager.Periodic
}

// get user and update the usercache
func (User) Run(s SDK.ISandbox, sig chan struct{}) error {
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
	// login thing
	if wtmp, err := os.Open("/var/log/wtmp"); err == nil {
		defer wtmp.Close()
		for {
			u := utmp{}
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
