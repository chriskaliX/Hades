package windows

import (
	"encoding/json"
	"hboat/grpc/handler"
	"hboat/grpc/transfer/pool"
	pb "hboat/grpc/transfer/proto"
)

type UProcessInfo struct {
	Win_User_Process_Pid       string `json:"win_ser_process_pid"`
	Win_User_Process_Pribase   string `json:"win_user_process_pribase"`
	Win_User_Process_Thrcout   string `json:"win_user_process_thrcout"`
	Win_User_Process_Parenid   string `json:"win_user_process_parenid"`
	Win_User_Process_Path      string `json:"win_user_process_Path"`
	Win_User_Process_szExeFile string `json:"win_user_process_szExeFile"`
}

func (k *UProcessInfo) ID() int32 { return 200 }

func (k *UProcessInfo) Name() string { return "user_processinfo" }

func (c *UProcessInfo) Handle(m map[string]string, req *pb.RawData, conn *pool.Connection) error {
	data := m["udata"]
	return json.Unmarshal([]byte(data), c)
}

func init() {
	handler.RegistEvent(&UProcessInfo{})
}
