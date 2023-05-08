package windows

import (
	"encoding/json"
	"hboat/grpc/handler"
	"hboat/grpc/transfer/pool"
	pb "hboat/grpc/transfer/proto"
)

type UAutoRun struct {
	Win_User_autorun_flag        string `json:"win_user_autorun_flag"`
	Win_User_autorun_regName     string `json:"win_user_autorun_regName"`
	Win_User_autorun_regKey      string `json:"win_user_autorun_regKey"`
	Win_User_autorun_tschname    string `json:"win_user_autorun_tschname"`
	Win_User_autorun_tscState    string `json:"win_user_autorun_tscState"`
	Win_User_autorun_tscLastTime string `json:"win_user_autorun_tscLastTime"`
	Win_User_autorun_tscNextTime string `json:"win_user_autorun_tscNextTime"`
	Win_User_autorun_tscCommand  string `json:"win_user_autorun_tscCommand"`
}

func (k *UAutoRun) ID() int32 { return 202 }

func (k *UAutoRun) Name() string { return "user_autorun" }

func (c *UAutoRun) Handle(m map[string]string, req *pb.RawData, conn *pool.Connection) error {
	data := m["udata"]
	return json.Unmarshal([]byte(data), c)
}

func init() {
	handler.RegistEvent(&UAutoRun{})
}
