package windows

import (
	"encoding/json"
	"hboat/grpc/handler"
	"hboat/grpc/transfer/pool"
	pb "hboat/grpc/transfer/proto"
)

type UAccount struct {
	Win_User_sysuser_user string `json:"win_user_sysuser_user"`
	Win_User_sysuser_name string `json:"win_user_sysuser_name"`
	Win_User_sysuser_sid  string `json:"win_user_sysuser_sid"`
	Win_User_sysuser_flag string `json:"win_user_sysuser_flag"`
}

func (k *UAccount) ID() int32 { return 207 }

func (k *UAccount) Name() string { return "user_account" }

func (c *UAccount) Handle(m map[string]string, req *pb.RawData, conn *pool.Connection) error {
	data := m["udata"]
	return json.Unmarshal([]byte(data), c)
}

func init() {
	handler.RegistEvent(&UAccount{})
}
