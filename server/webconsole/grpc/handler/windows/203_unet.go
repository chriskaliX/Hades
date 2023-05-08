package windows

import (
	"encoding/json"
	"hboat/grpc/handler"
	"hboat/grpc/transfer/pool"
	pb "hboat/grpc/transfer/proto"
)

type UNet struct {
	Win_User_net_flag   string `json:"win_user_net_flag"`
	Win_User_net_src    string `json:"win_user_net_src"`
	Win_User_net_dst    string `json:"win_user_net_dst"`
	Win_User_net_status string `json:"win_user_net_status"`
	Win_User_net_pid    string `json:"win_user_net_pid"`
}

func (k *UNet) ID() int32 { return 203 }

func (k *UNet) Name() string { return "user_net" }

func (c *UNet) Handle(m map[string]string, req *pb.RawData, conn *pool.Connection) error {
	data := m["udata"]
	return json.Unmarshal([]byte(data), c)
}

func init() {
	handler.RegistEvent(&UNet{})
}
