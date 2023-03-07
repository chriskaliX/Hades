package windows

import (
	"encoding/json"
	"hboat/grpc/handler"
	"hboat/grpc/transfer/pool"
	pb "hboat/grpc/transfer/proto"
)

type UEtwProcessinfo struct {
	Win_Etw_processinfo_EventName string `json:"win_etw_processinfo_eventname"`
	Win_Etw_processinfo_ParentId  string `json:"win_etw_processinfo_parentid"`
	Win_Etw_processinfo_Status    string `json:"win_etw_processinfo_status"`
	Win_Etw_processinfo_pid       string `json:"win_etw_processinfo_pid"`
	Win_Etw_processinfo_Path      string `json:"win_etw_processinfo_path"`
}

func (k *UEtwProcessinfo) ID() int32 { return 300 }

func (k *UEtwProcessinfo) Name() string { return "user_etw_processinfo" }

func (c *UEtwProcessinfo) Handle(m map[string]string, req *pb.RawData, conn *pool.Connection) error {
	data := m["udata"]
	return json.Unmarshal([]byte(data), c)
}

func init() {
	handler.RegistEvent(&UEtwProcessinfo{})
}
