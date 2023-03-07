package handler

import (
	"hboat/grpc/transfer/pool"
	pb "hboat/grpc/transfer/proto"
	"strconv"
)

type User struct{}

var _ Event = (*User)(nil)

func (u *User) ID() int32 { return 3004 }

func (u *User) Name() string { return "users" }

func (c *User) Handle(m map[string]string, req *pb.RawData, conn *pool.Connection) error {
	mapper := make(map[string]interface{})
	// handle the data
	for k, v := range m {
		switch k {
		case "uid", "gid":
			id, _ := strconv.ParseUint(v, 10, 32)
			mapper[k] = id
		case "last_login_time":
			t, _ := strconv.ParseUint(v, 10, 64)
			mapper[k] = t
		default:
			mapper[k] = v
		}
	}
	DefaultWorker.Add(c.ID(), req.AgentID, mapper)
	return nil
}

func init() { RegistEvent(&User{}) }
